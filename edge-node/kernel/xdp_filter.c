// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_filter.c — XDP/eBPF Packet Filter cho hệ thống Tường lửa Phân tán
 *
 * Phiên bản này bổ sung Stats Map (nice-to-have) so với bản đơn giản ban đầu.
 *
 * Vị trí trong kiến trúc (multistate firewall):
 *   [NIC Driver]
 *       └── XDP hook (file này) ← TẦNG NGOÀI CÙNG: stateless, tốc độ cao
 *               │   DROP nếu IP nguồn có trong blacklist
 *               │   PASS nếu không có trong blacklist
 *               ▼
 *       [Kernel Network Stack]
 *               └── iptables/netfilter ← TẦNG TRONG: stateful, kết nối thông thường
 *                       └── SYN Cookie (kernel tự xử lý SYN Flood)
 *
 * Hai Maps trong file này:
 *   1. xdp_blacklist — LRU Hash Map: Python ghi IP vào, XDP đọc để DROP
 *   2. xdp_stats     — PerCPU Array: XDP ghi counter, Python đọc để monitor
 *
 * Cách compile:
 *   make
 *   # Hoặc thủ công:
 *   clang -O2 -g -target bpf -c xdp_filter.c -o build/xdp_filter.o
 *
 * Cách load và attach:
 *   sudo ip link set eth1 xdp obj build/xdp_filter.o sec xdp
 *   ip link show eth1              # kiểm tra đã attach
 *   sudo ip link set eth1 xdp off  # gỡ XDP
 *
 * Về libbpf:
 *   File này chỉ cần package libbpf-dev (đã có trong env/setup.sh).
 *   KHÔNG cần clone repo libbpf từ GitHub — đó là C loader userspace,
 *   không phải thứ cần thiết ở kernel-side code này.
 *
 * ⚠️  LƯU Ý QUAN TRỌNG CHO NGƯỜI MỚI:
 *   1. Đây là "restricted C" — không phải C thông thường. Nhiều thứ bị cấm.
 *   2. Mọi truy cập packet data phải có bounds check — verifier sẽ từ chối
 *      load nếu thiếu, không phải runtime crash.
 *   3. Không dùng hàm kernel thông thường, chỉ dùng bpf_* helpers.
 *   4. Sau bpf_map_lookup_elem(), PHẢI check NULL kể cả khi biết chắc
 *      không NULL — đây là yêu cầu của verifier, không phải logic thật.
 *   5. Debug bằng bpf_trace_printk() → /sys/kernel/debug/tracing/trace_pipe
 */

/* ── Includes ─────────────────────────────────────────────────────────────────
 * Thứ tự: linux/* trước, bpf/* sau.
 * Tuyệt đối KHÔNG include <stdio.h>, <stdlib.h> hay bất kỳ userspace header.
 */
#include <linux/bpf.h>          /* XDP_DROP, XDP_PASS, XDP_ABORTED, ...         */
#include <linux/if_ether.h>     /* struct ethhdr, ETH_P_IP (0x0800)             */
#include <linux/ip.h>           /* struct iphdr, ip->saddr                      */
#include <bpf/bpf_helpers.h>    /* SEC(), __uint(), __type(),
                                   bpf_map_lookup_elem(), bpf_map_update_elem() */
#include <bpf/bpf_endian.h>     /* bpf_htons() — host ↔ network byte order      */


/* ══════════════════════════════════════════════════════════════════════════════
 * PHẦN 1: Stats counter indices
 *
 * Dùng enum đặt tên cho từng slot trong Stats Array Map.
 * Phải khớp chính xác với phía Python trong map_manager.py:
 *   STATS_IDX_DROPPED = 0  →  Python: read_stats()[0]
 *   STATS_IDX_PASSED  = 1  →  Python: read_stats()[1]
 *
 * ⚠️  Nếu thêm counter mới ở đây, cập nhật map_manager.py tương ứng.
 * ══════════════════════════════════════════════════════════════════════════════
 */
enum xdp_stats_idx {
    STATS_IDX_DROPPED = 0,
    STATS_IDX_PASSED  = 1,
    STATS_IDX_MAX     = 2,   /* Kích thước mảng — phải là phần tử cuối */
};


/* ══════════════════════════════════════════════════════════════════════════════
 * PHẦN 2: Map 1 — xdp_blacklist
 *
 * Đây là Map trung tâm của toàn hệ thống — "cầu nối" duy nhất giữa
 * Python (userspace) và XDP (kernel). Python ghi IP vào, XDP đọc để DROP.
 *
 * BPF_MAP_TYPE_LRU_HASH:
 *   Khi Map đầy (65536 entries), kernel tự xóa entry ít lookup nhất.
 *   Giải quyết "số IP xấu tăng đột biến" mà không cần quản lý thủ công.
 *   Đây chính xác là lý do proposal chọn LRU thay vì HASH thông thường.
 *
 * Key = __u32 (network byte order):
 *   ⚠️  Phải khớp với cách Python ghi key:
 *     struct.unpack("!I", socket.inet_aton(ip))[0]
 *   "!" = network/big-endian. Sai byte order → lookup luôn miss trên x86.
 *
 * pinning = LIBBPF_PIN_BY_NAME:
 *   Pin Map tại /sys/fs/bpf/xdp_blacklist sau khi load.
 *   Không pin → Map mất khi process loader thoát.
 *   Có pin → node_agent.py truy cập được bất cứ lúc nào.
 * ══════════════════════════════════════════════════════════════════════════════
 */
struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key,         __u32);  /* IPv4 source address — network byte order   */
    __type(value,       __u8);   /* dummy: 1 = blocked. Chỉ cần key tồn tại.  */
    __uint(pinning,     LIBBPF_PIN_BY_NAME);
} xdp_blacklist SEC(".maps");


/* ══════════════════════════════════════════════════════════════════════════════
 * PHẦN 3: Map 2 — xdp_stats (nice-to-have: Statistics Counter)
 *
 * Lưu số liệu DROP/PASS để Python đọc và report.
 * Biến kết quả benchmark từ "CPU giảm Z%" thành số liệu chính xác hơn:
 * "XDP DROP X triệu packet/giây với Y% CPU".
 *
 * Tại sao dùng BPF_MAP_TYPE_PERCPU_ARRAY thay vì ARRAY thông thường?
 *
 *   Vấn đề với ARRAY thông thường trong môi trường đa nhân:
 *     Nhiều CPU core cùng tăng counter → race condition → mất count.
 *     Dùng atomic operations để fix thì tốn thêm CPU cycles.
 *
 *   PERCPU_ARRAY giải quyết thanh lịch hơn:
 *     Kernel tạo một bản sao riêng cho MỖI CPU core.
 *     Mỗi core chỉ đọc/ghi bản sao của mình → zero contention, zero lock.
 *     Python đọc tổng bằng cách cộng tất cả bản sao lại.
 *     Đây là pattern chuẩn cho high-performance counter trong eBPF.
 *
 *   max_entries = STATS_IDX_MAX = 2 (dropped + passed).
 *   Pin tại /sys/fs/bpf/xdp_stats để map_manager.py đọc được.
 * ══════════════════════════════════════════════════════════════════════════════
 */
struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STATS_IDX_MAX);
    __type(key,         __u32);   /* STATS_IDX_DROPPED hoặc STATS_IDX_PASSED   */
    __type(value,       __u64);   /* __u64 để không bị overflow khi flood       */
    __uint(pinning,     LIBBPF_PIN_BY_NAME);
} xdp_stats SEC(".maps");


/* ══════════════════════════════════════════════════════════════════════════════
 * PHẦN 4: Helper — update_stats()
 *
 * Tách thành helper riêng để giữ hàm chính sạch và dễ đọc.
 *
 * __always_inline: yêu cầu compiler inline hàm này vào caller.
 *   Trong eBPF, function call có overhead nhất định. Với helper nhỏ
 *   được gọi trong hot path (mỗi packet), inline là lựa chọn đúng.
 *
 * ⚠️  NULL check sau bpf_map_lookup_elem() là BẮT BUỘC cho verifier:
 *   Dù ARRAY map với index hợp lệ KHÔNG BAO GIỜ trả về NULL trong thực tế,
 *   verifier không đủ thông minh để biết điều này. Nếu bỏ NULL check,
 *   verifier in "invalid mem access 'map_value_or_null'" và từ chối load.
 *   Đây là một trong những "gotcha" đặc trưng nhất của eBPF programming.
 * ══════════════════════════════════════════════════════════════════════════════
 */
static __always_inline void update_stats(__u32 idx)
{
    __u64 *counter = bpf_map_lookup_elem(&xdp_stats, &idx);

    if (!counter)   /* NULL check bắt buộc cho verifier — xem giải thích trên */
        return;

    (*counter)++;   /* Atomic-free vì PERCPU: mỗi CPU chỉ ghi bản sao của mình */
}


/* ══════════════════════════════════════════════════════════════════════════════
 * PHẦN 5: Hàm XDP chính — xdp_filter_func
 *
 * Kernel gọi hàm này với MỖI packet đến. Phải xử lý trong vài nanoseconds.
 *
 * SEC("xdp"): section name trong ELF, phải khớp với lệnh attach:
 *   sudo ip link set eth1 xdp obj xdp_filter.o sec xdp
 *
 * Luồng xử lý:
 *   Parse Ethernet → kiểm tra IPv4 → parse IP → lookup blacklist
 *     → DROP + update dropped_counter  (nếu IP trong blacklist)
 *     → PASS + update passed_counter   (nếu IP bình thường)
 * ══════════════════════════════════════════════════════════════════════════════
 */
SEC("xdp")
int xdp_filter_func(struct xdp_md *ctx)
{
    /* ── Bước 1: Con trỏ đầu/cuối packet ─────────────────────────────────────
     *
     * ctx->data và ctx->data_end là __u32 offsets tương đối.
     * Cast sang (void *)(long) là cách chuẩn trong eBPF C.
     *
     * data     = byte đầu tiên Ethernet frame
     * data_end = byte ngay SAU byte cuối (exclusive, như STL iterator)
     *
     * Quy tắc bounds check: if ((ptr + 1) > data_end) → packet không đủ dài
     */
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* ── Bước 2: Parse Ethernet header ────────────────────────────────────────
     *
     * struct ethhdr = 14 bytes: [6B dst MAC][6B src MAC][2B EtherType]
     * (eth + 1) = địa chỉ ngay sau struct ethhdr = byte đầu payload.
     *
     * ⚠️  Bounds check bắt buộc. Thiếu → verifier từ chối load với:
     *   "R1 offset is outside of the packet"
     */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;   /* Packet quá nhỏ, corrupt → bỏ qua */

    /* ── Bước 3: Chỉ xử lý IPv4 ──────────────────────────────────────────────
     *
     * eth->h_proto là network byte order (big-endian, từ frame).
     * ETH_P_IP = 0x0800 trong if_ether.h là host byte order.
     *
     * ⚠️  PHẢI dùng bpf_htons(ETH_P_IP) để so sánh đúng.
     *   Thiếu bpf_htons() trên x86: 0x0800 ≠ 0x0008 → mọi packet PASS.
     *   Đây là lỗi byte order phổ biến nhất, không có warning nào cả.
     *
     * Non-IPv4 (ARP, IPv6, VLAN...) → PASS, để kernel xử lý bình thường.
     */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* ── Bước 4: Parse IP header ──────────────────────────────────────────────
     *
     * IP header ngay sau Ethernet header.
     * Minimum = 20 bytes = sizeof(struct iphdr).
     * ip->saddr luôn nằm trong 20 bytes đầu (fixed header), nên chỉ cần
     * kiểm tra minimum size dù IP có Options làm header dài hơn.
     */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;   /* IP header bị cắt ngắn, corrupt → bỏ qua */

    /* ── Bước 5: Lookup source IP trong blacklist ─────────────────────────────
     *
     * ip->saddr đã là network byte order (từ IP header trong packet).
     * map_manager.py lưu key bằng struct.unpack("!I", ...) — cũng network order.
     * Hai bên khớp nhau tự nhiên, không cần chuyển đổi thêm.
     *
     * bpf_map_lookup_elem():
     *   Trả về pointer đến value nếu key tồn tại, NULL nếu không.
     *   Ta chỉ cần biết NULL hay không — không cần đọc value (__u8 = 1).
     */
    __u32 src_ip = ip->saddr;
    __u8 *blocked = bpf_map_lookup_elem(&xdp_blacklist, &src_ip);

    if (blocked) {
        /* ── IP trong blacklist → DROP ────────────────────────────────────────
         *
         * Xảy ra tại driver level. Không có sk_buff allocation, không có
         * netfilter traversal, không có routing lookup.
         *
         * Từ góc nhìn kẻ tấn công: packet biến mất im lặng → timeout.
         * Không có RST hay ICMP unreachable — đây là dấu hiệu phân biệt
         * "bị XDP DROP" với "bị iptables REJECT" trong attack_sim.sh.
         */
        update_stats(STATS_IDX_DROPPED);
        return XDP_DROP;
    }

    /* ── IP không trong blacklist → PASS ─────────────────────────────────────
     *
     * Đi lên kernel network stack → iptables/netfilter xử lý tiếp.
     * SYN Cookie hoạt động ở tầng này để chống SYN Flood.
     * Đây là happy path — đại đa số packet đi qua đây.
     */
    update_stats(STATS_IDX_PASSED);
    return XDP_PASS;
}


/* ══════════════════════════════════════════════════════════════════════════════
 * PHẦN 6: License — BẮT BUỘC
 *
 * Thiếu dòng này → kernel từ chối load với:
 *   "cannot call GPL-restricted function from non-GPL compatible program"
 *
 * bpf_map_lookup_elem() và hầu hết BPF helpers đều là GPL-only trong kernel.
 * ══════════════════════════════════════════════════════════════════════════════
 */
char LICENSE[] SEC("license") = "GPL";