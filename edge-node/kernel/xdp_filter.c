/*
 * xdp_filter.c — Chương trình XDP chạy trong Linux Kernel space
 *
 * Chức năng: Kiểm tra IP nguồn của mỗi gói tin đến.
 * Nếu IP nằm trong eBPF LRU Hash Map (blacklist), lập tức DROP gói tin.
 * Nếu không có trong blacklist, trả về XDP_PASS để xử lý bình thường.
 *
 * Compile bằng: make (xem Makefile cùng thư mục)
 * Output: ../build/xdp_filter.o
 */
/*---------------------------------------------------------------*/
// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_filter.c — XDP/eBPF Packet Filter cho hệ thống Tường lửa Phân tán
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
 * Luồng dữ liệu với userspace:
 *   node_agent.py (Python)
 *       └── map_manager.py
 *               └── bpf_map_update_elem() / bpf_map_delete_elem()
 *                       └── xdp_blacklist Map (file này)
 *                               └── XDP lookup → DROP/PASS
 *
 * Cách compile:
 *   make    (xem Makefile trong cùng thư mục)
 *   # Hoặc thủ công:
 *   clang -O2 -g -target bpf -c xdp_filter.c -o build/xdp_filter.o
 *
 * Cách load và attach:
 *   # Attach vào interface eth1 (host-only NIC trong lab)
 *   sudo ip link set eth1 xdp obj build/xdp_filter.o sec xdp
 *   # Kiểm tra đã attach chưa
 *   ip link show eth1
 *   # Gỡ XDP
 *   sudo ip link set eth1 xdp off
 *
 * ⚠️  LƯU Ý QUAN TRỌNG CHO NGƯỜI MỚI:
 *   1. Đây là "restricted C" — không phải C thông thường. Nhiều thứ bị cấm.
 *   2. Mọi truy cập packet data phải có bounds check — không thể bỏ qua.
 *   3. Không được dùng hàm kernel thông thường, chỉ dùng bpf_* helpers.
 *   4. Khi bị lỗi khi load, đọc output của: sudo ip link set eth1 xdp ...
 *      hoặc dùng: sudo bpftool prog load build/xdp_filter.o /sys/fs/bpf/prog
 *   5. Debug bằng bpf_trace_printk() → xem tại /sys/kernel/debug/tracing/trace_pipe
 */

/* ── Includes ────────────────────────────────────────────────────────────────
 * Thứ tự include quan trọng: linux/* trước, bpf/* sau.
 * Không include <stdio.h>, <stdlib.h>, hay bất kỳ userspace header nào —
 * chúng không tồn tại trong kernel context.
 */
#include <linux/bpf.h>          /* XDP action codes: XDP_DROP, XDP_PASS, ...    */
#include <linux/if_ether.h>     /* struct ethhdr, ETH_P_IP (0x0800)             */
#include <linux/ip.h>           /* struct iphdr, ip->saddr                      */
#include <bpf/bpf_helpers.h>    /* SEC(), bpf_map_lookup_elem(), bpf_htons()    */
#include <bpf/bpf_endian.h>     /* bpf_htons() — chuyển host↔network byte order */


/* ══════════════════════════════════════════════════════════════════════════════
 * PHẦN 1: Khai báo eBPF LRU Hash Map — "Blacklist" dùng chung với userspace
 *
 * Đây là "cầu nối" duy nhất giữa XDP program (kernel) và Python (userspace).
 * node_agent.py ghi IP vào đây → XDP đọc và DROP packet từ IP đó.
 *
 * Giải thích từng field:
 *   BPF_MAP_TYPE_LRU_HASH:
 *     LRU = Least Recently Used. Khi Map đầy (65536 entries), kernel tự động
 *     xóa entry ít được lookup nhất để nhường chỗ cho entry mới.
 *     Đây là giải pháp cho vấn đề "số lượng IP xấu tăng đột biến" như
 *     đề cập trong proposal — hệ thống không bao giờ bị OOM vì Map này.
 *
 *   max_entries = 65536:
 *     64K entries × (4 bytes key + 1 byte value + overhead) ≈ vài MB RAM.
 *     Con số đủ lớn cho lab, điều chỉnh tùy scale thực tế.
 *
 *   key = __u32 (IPv4 address):
 *     ⚠️  QUAN TRỌNG: Key phải là NETWORK BYTE ORDER (big-endian).
 *     ip->saddr trong kernel luôn là network byte order.
 *     map_manager.py dùng struct.unpack("!I", ...) để đảm bảo khớp.
 *     Nếu không khớp: lookup luôn miss trên máy x86 (little-endian).
 *
 *   value = __u8:
 *     Không quan tâm đến value, chỉ cần biết key có TỒN TẠI không.
 *     Dùng 1 byte để tiết kiệm bộ nhớ tối đa.
 *
 *   pinning = LIBBPF_PIN_BY_NAME:
 *     Tự động pin Map tại /sys/fs/bpf/xdp_blacklist khi program load.
 *     "xdp_blacklist" = tên biến bên dưới.
 *     Nếu không pin: Map chỉ sống khi process đang load program còn sống.
 *     Với pin: Map tồn tại độc lập, node_agent.py có thể truy cập bất cứ lúc.
 * ══════════════════════════════════════════════════════════════════════════════
 */
struct {
    __uint(type,        BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key,         __u32);   /* IPv4 source address — network byte order  */
    __type(value,       __u8);    /* dummy: 1 = blocked, chỉ cần key tồn tại   */
    __uint(pinning,     LIBBPF_PIN_BY_NAME); /* pin tại /sys/fs/bpf/xdp_blacklist */
} xdp_blacklist SEC(".maps");


/* ══════════════════════════════════════════════════════════════════════════════
 * PHẦN 2: Hàm XDP chính
 *
 * Kernel gọi hàm này với MỖI packet đến trên interface đã attach.
 * Hàm phải trả về một trong các XDP action codes:
 *   XDP_DROP    — Hủy packet ngay lập tức, không vào network stack.
 *                 Đây là action nhanh nhất và tốn ít CPU nhất.
 *   XDP_PASS    — Cho packet đi lên kernel network stack bình thường.
 *                 Iptables/netfilter sẽ xử lý tiếp (tầng thứ hai).
 *   XDP_TX      — Gửi packet ngược lại ra NIC (không dùng ở đây).
 *   XDP_REDIRECT — Chuyển packet sang interface/CPU khác (không dùng).
 *   XDP_ABORTED — Báo lỗi, drop packet và tăng error counter.
 *                 Dùng khi có lỗi không mong đợi (không bao giờ nên xảy ra).
 *
 * SEC("xdp"): Khai báo section name trong ELF object file.
 *   Tên này phải khớp với tham số "sec" trong lệnh ip link set:
 *   sudo ip link set eth1 xdp obj xdp_filter.o sec xdp
 * ══════════════════════════════════════════════════════════════════════════════
 */
SEC("xdp")
int xdp_filter_func(struct xdp_md *ctx)
{
    /*
     * Bước 1: Lấy con trỏ đầu và cuối của packet trong bộ nhớ.
     *
     * ctx->data và ctx->data_end là __u32 offsets tương đối, không phải
     * pointer thật. Phải cast sang (void *)(long) để dùng như pointer.
     *
     * data     → byte đầu tiên của Ethernet frame
     * data_end → byte SAU byte cuối cùng (exclusive end, giống STL iterator)
     *
     * Mọi bounds check đều có dạng: if ((ptr + size) > data_end) return XDP_PASS
     * Nghĩa là: "nếu accessing đến đây sẽ vượt quá boundary, bỏ qua packet này"
     */
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /*
     * Bước 2: Parse Ethernet header.
     *
     * Ethernet frame layout:
     *   [6 bytes dst MAC][6 bytes src MAC][2 bytes EtherType][payload...]
     *   Total header = 14 bytes = sizeof(struct ethhdr)
     *
     * Bounds check bắt buộc:
     *   (eth + 1) là địa chỉ NGAY SAU struct ethhdr — tức là byte đầu tiên
     *   của payload. Nếu (eth + 1) > data_end, packet không đủ 14 bytes
     *   để chứa Ethernet header — packet bị corrupt hoặc quá nhỏ → PASS.
     *
     * ⚠️  Nếu bỏ bounds check này, kernel verifier sẽ in:
     *   "R1 offset is outside of the packet" và từ chối load.
     */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;  /* Packet quá nhỏ, không phải Ethernet hợp lệ */

    /*
     * Bước 3: Kiểm tra EtherType — chỉ xử lý IPv4.
     *
     * eth->h_proto là big-endian (network byte order) vì nó nằm trong frame.
     * ETH_P_IP (0x0800) được định nghĩa trong linux/if_ether.h là host order.
     * Trên x86 (little-endian): 0x0800 host = 0x0008 network → không khớp!
     *
     * ⚠️  PHẢI dùng bpf_htons() để chuyển ETH_P_IP sang network byte order
     *   trước khi so sánh. Đây là lỗi byte order phổ biến nhất trong XDP code.
     *
     * Các EtherType khác (IPv6=0x86DD, ARP=0x0806...) ta để PASS qua — không
     * phải nhiệm vụ của filter này.
     */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;  /* Không phải IPv4: ARP, IPv6, VLAN... → bỏ qua */

    /*
     * Bước 4: Parse IP header.
     *
     * IP header nằm ngay sau Ethernet header.
     * (eth + 1) trỏ đến byte đầu tiên của IP header — cast sang struct iphdr*.
     *
     * Bounds check tương tự: kiểm tra struct iphdr (20 bytes minimum) nằm
     * hoàn toàn trong packet.
     *
     * Lưu ý: IP header có thể có options (IHL > 5) làm header dài hơn 20 bytes.
     * Với mục đích lọc theo source IP, ta chỉ cần fixed header (20 bytes đầu)
     * vì saddr luôn nằm trong fixed header, không bị ảnh hưởng bởi options.
     */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;  /* IP header bị cắt ngắn → packet corrupt → PASS */

    /*
     * Bước 5: Lấy source IP và lookup trong blacklist Map.
     *
     * ip->saddr là source IP address — ĐÃ ở network byte order vì nó đến
     * thẳng từ IP header trong packet. Không cần chuyển đổi thêm.
     *
     * map_manager.py (Python) lưu IP vào Map bằng cách dùng:
     *   struct.unpack("!I", socket.inet_aton(ip_str))[0]
     * Đây cũng là network byte order → hai bên khớp nhau → lookup chính xác.
     *
     * bpf_map_lookup_elem():
     *   Tham số 1: pointer đến Map (không phải Map fd!)
     *   Tham số 2: pointer đến key (phải là __u32* cho Map này)
     *   Trả về:    pointer đến value nếu key tồn tại, NULL nếu không có
     *
     * ⚠️  Không dùng giá trị trả về của bpf_map_lookup_elem() nếu nó không
     *   NULL — trong trường hợp này ta chỉ cần biết NULL hay không.
     *   Nếu muốn đọc value, PHẢI kiểm tra non-NULL trước khi deref.
     */
    __u32 src_ip = ip->saddr;
    __u8 *blocked = bpf_map_lookup_elem(&xdp_blacklist, &src_ip);

    if (blocked) {
        /*
         * IP nguồn có trong blacklist → DROP packet ngay lập tức.
         *
         * Điều gì xảy ra khi XDP_DROP:
         *   - Packet bị hủy ngay tại driver level
         *   - Không có sk_buff allocation
         *   - Không có netfilter traversal
         *   - Không có routing lookup
         *   - Kẻ tấn công nhận được... im lặng (timeout)
         *   - CPU usage: gần như 0 so với iptables DROP
         */
        return XDP_DROP;
    }

    /*
     * Bước 6: IP không có trong blacklist → cho packet đi qua.
     *
     * Packet sẽ tiếp tục đi lên kernel network stack:
     *   XDP_PASS → sk_buff allocation → routing → netfilter/iptables → socket
     *
     * iptables/netfilter sẽ đảm nhiệm stateful filtering ở đây — đây là
     * tầng thứ hai trong kiến trúc "multistate firewall" của đề tài.
     * SYN Cookie cũng hoạt động ở tầng này để chống SYN Flood.
     */
    return XDP_PASS;
}


/* ══════════════════════════════════════════════════════════════════════════════
 * PHẦN 3: License declaration — BẮT BUỘC
 *
 * Nhiều BPF helper functions (bao gồm bpf_map_lookup_elem) được đánh dấu
 * "GPL only" trong kernel. Nếu không khai báo GPL license, kernel sẽ
 * từ chối load chương trình với lỗi:
 *   "cannot call GPL-restricted function from non-GPL compatible program"
 *
 * SEC("license") là một ELF section đặc biệt mà libbpf đọc khi load.
 * ══════════════════════════════════════════════════════════════════════════════
 */
char LICENSE[] SEC("license") = "GPL";