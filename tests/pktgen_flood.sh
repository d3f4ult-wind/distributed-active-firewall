#!/bin/bash
# pktgen_flood.sh — Benchmark hiệu năng XDP so với iptables dưới tải cao
#
# Sử dụng pktgen (Linux kernel packet generator) để 'bắn' gói tin tốc độ cao.
# Đo và ghi lại: CPU usage, packet throughput (pps), drop rate.
# Chạy 2 lần: một lần với XDP, một lần với iptables -> xuất kết quả vào results/raw/
# ---------------------------------------------------------------------------------
#!/usr/bin/env bash
# =============================================================================
# pktgen_flood.sh — Benchmark XDP vs iptables dưới tải gói tin cao
#
# Mục đích học thuật:
#   Chứng minh luận điểm cốt lõi của đề tài: XDP can thiệp gói tin ở
#   tầng driver (trước khi vào kernel network stack) nên tiêu thụ ít CPU
#   hơn và xử lý được nhiều packet/giây hơn so với iptables.
#
#   Thí nghiệm đối chứng (controlled experiment):
#     Biến độc lập:  Cơ chế chặn  → XDP DROP  hoặc  iptables DROP
#     Biến phụ thuộc: CPU usage (%)  và  throughput (Mpps)
#     Biến kiểm soát: Cùng VM, cùng lượng traffic, cùng IP bị chặn
#
# Luồng hoạt động:
#   1. Dọn dẹp trạng thái cũ (gỡ XDP, xóa iptables rules)
#   2. [Phase A] Chạy với iptables: flood → đo CPU + PPS → ghi kết quả
#   3. Dọn dẹp iptables rules
#   4. [Phase B] Load XDP + cùng blacklist: flood → đo CPU + PPS → ghi kết quả
#   5. So sánh và in bảng kết quả
#
# Cách dùng:
#   # Trên VM1 (Edge Node), với quyền root:
#   sudo bash tests/pktgen_flood.sh
#
#   # Chỉ chạy một phase:
#   sudo bash tests/pktgen_flood.sh --iptables-only
#   sudo bash tests/pktgen_flood.sh --xdp-only
#
#   # Tùy chỉnh cường độ:
#   sudo FLOOD_DURATION=30 FLOOD_PPS=500000 bash tests/pktgen_flood.sh
#
# Yêu cầu:
#   - Chạy với quyền root (pktgen cần root, XDP cần root)
#   - pktgen kernel module: modprobe pktgen
#   - iptables: có sẵn trên Ubuntu
#   - xdp_filter.o đã được compile (edge-node/kernel/build/xdp_filter.o)
#   - ip link: iproute2 (có sẵn)
#   - bc: để tính toán số thực trong bash
#
# Ghi chú về pktgen:
#   pktgen là kernel module tạo packet ở tốc độ cao. Nó được điều khiển
#   qua /proc/net/pktgen/ — một virtual filesystem đặc biệt.
#   Mỗi "thread" pktgen gắn với một CPU core và một network interface.
#   Packet được tạo ra trong kernel space, bypass hoàn toàn userspace,
#   cho phép đạt tốc độ hàng triệu pps (packets per second).
# =============================================================================

set -euo pipefail

# ── Màu sắc ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
log()     { echo -e "${CYAN}[$(date +%H:%M:%S)]${RESET} $*"; }
ok()      { echo -e "${GREEN}[  OK ]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[WARN ]${RESET} $*"; }
err()     { echo -e "${RED}[ERR  ]${RESET} $*" >&2; }
section() { echo -e "\n${BOLD}${CYAN}▶ $*${RESET}"; }
header()  {
    echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}  $*${RESET}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════${RESET}"
}

# ── Kiểm tra quyền root ───────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    err "Script này cần chạy với quyền root."
    err "Dùng: sudo bash tests/pktgen_flood.sh"
    exit 1
fi

# ══════════════════════════════════════════════════════════════════════════════
# Cấu hình — override bằng environment variables
# ══════════════════════════════════════════════════════════════════════════════

# Interface nhận traffic flood (eth1 = host-only NIC theo network-topology.md)
IFACE="${IFACE:-eth1}"

# IP nguồn giả cho packet flood — phải nằm trong blacklist để test DROP
# Dùng IP không có thật trong mạng lab để không gây side effects
FLOOD_SRC_IP="${FLOOD_SRC_IP:-10.255.99.1}"
FLOOD_DST_IP="${FLOOD_DST_IP:-192.168.56.10}"  # IP của VM1

# Thời gian flood mỗi phase (giây) — 20s đủ để CPU usage ổn định
FLOOD_DURATION="${FLOOD_DURATION:-20}"

# Tốc độ packet mong muốn (packets/sec) — 0 = tối đa có thể
# Trong VirtualBox, NIC ảo thường đạt ~200k-500k pps
FLOOD_PPS="${FLOOD_PPS:-0}"

# Số CPU core dùng cho pktgen (dùng 1 để kết quả nhất quán hơn)
PKTGEN_THREADS="${PKTGEN_THREADS:-1}"

# Path đến XDP object file đã compile
XDP_OBJ="${XDP_OBJ:-edge-node/kernel/build/xdp_filter.o}"
XDP_MAP_PIN="${XDP_MAP_PIN:-/sys/fs/bpf/xdp_blacklist}"

# Thư mục lưu kết quả
RESULTS_DIR="results/raw"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_FILE="$RESULTS_DIR/pktgen_benchmark_$TIMESTAMP.csv"

# ── Parse arguments ───────────────────────────────────────────────────────────
RUN_IPTABLES=true
RUN_XDP=true
case "${1:-}" in
    --iptables-only) RUN_XDP=false ;;
    --xdp-only)      RUN_IPTABLES=false ;;
    --help)
        grep "^#" "$0" | head -40 | sed 's/^# \{0,2\}//'
        exit 0
        ;;
esac

# ── Biến lưu kết quả ─────────────────────────────────────────────────────────
IPTABLES_CPU=""
IPTABLES_PPS=""
IPTABLES_RXDROP=""
XDP_CPU=""
XDP_PPS=""
XDP_RXDROP=""

# ══════════════════════════════════════════════════════════════════════════════
# PHẦN 1: Utilities
# ══════════════════════════════════════════════════════════════════════════════

check_deps() {
    section "Kiểm tra dependencies"
    local missing=()
    for cmd in iptables ip bc mpstat; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    # bc dùng để tính số thực trong bash (CPU%, PPS trung bình)
    # mpstat từ package sysstat — đo CPU usage per-core
    if [[ ${#missing[@]} -gt 0 ]]; then
        err "Thiếu: ${missing[*]}"
        err "Cài: apt install iproute2 bc sysstat iptables"
        exit 1
    fi

    # Kiểm tra pktgen module
    if ! lsmod | grep -q pktgen; then
        log "Đang load pktgen kernel module..."
        modprobe pktgen || { err "Không load được pktgen. Kiểm tra kernel version."; exit 1; }
    fi
    ok "Tất cả dependencies OK"
}

cleanup_all() {
    section "Dọn dẹp trạng thái cũ"

    # Xóa tất cả iptables rules liên quan đến test IP
    iptables -D INPUT -s "$FLOOD_SRC_IP" -j DROP 2>/dev/null || true
    iptables -D FORWARD -s "$FLOOD_SRC_IP" -j DROP 2>/dev/null || true

    # Gỡ XDP khỏi interface nếu đang attach
    ip link set "$IFACE" xdp off 2>/dev/null || true

    # Dừng tất cả pktgen threads cũ
    for pgfile in /proc/net/pktgen/kpktgend_*; do
        [[ -f "$pgfile" ]] && echo "stop" > "$pgfile" 2>/dev/null || true
    done

    ok "Đã dọn dẹp xong"
}

# ══════════════════════════════════════════════════════════════════════════════
# PHẦN 2: pktgen control
# pktgen được điều khiển bằng cách ghi lệnh vào /proc/net/pktgen/
# Đây là giao diện kernel-userspace đặc trưng của pktgen.
# ══════════════════════════════════════════════════════════════════════════════

pktgen_cmd() {
    # Ghi lệnh vào pktgen control file
    # $1: file path (/proc/net/pktgen/pgctrl hoặc /proc/net/pktgen/kpktgend_N)
    # $2: lệnh cần ghi
    echo "$2" > "$1"
}

setup_pktgen() {
    local thread_file="/proc/net/pktgen/kpktgend_0"
    local dev_file="/proc/net/pktgen/${IFACE}"

    section "Cấu hình pktgen"

    # Thêm interface vào thread 0
    pktgen_cmd "$thread_file" "add_device $IFACE"

    # Chờ file device xuất hiện
    sleep 0.5

    if [[ ! -f "$dev_file" ]]; then
        err "pktgen device file không tồn tại: $dev_file"
        err "Kiểm tra: interface '$IFACE' có tồn tại không? (ip link show)"
        exit 1
    fi

    # Cấu hình packet flood:
    #   count 0      = flood vô hạn cho đến khi bị stop
    #   pkt_size 64  = packet size nhỏ nhất (64 bytes) để maximize pps
    #                  Packet nhỏ = nhiều packet/giây hơn = áp lực CPU cao hơn
    #                  Đây là worst-case scenario cho việc xử lý packet
    #   src_min/max  = IP nguồn cố định = FLOOD_SRC_IP (IP trong blacklist)
    #   dst_min/max  = IP đích = FLOOD_DST_IP
    pktgen_cmd "$dev_file" "count 0"
    pktgen_cmd "$dev_file" "pkt_size 64"
    pktgen_cmd "$dev_file" "src_min $FLOOD_SRC_IP"
    pktgen_cmd "$dev_file" "src_max $FLOOD_SRC_IP"
    pktgen_cmd "$dev_file" "dst_min $FLOOD_DST_IP"
    pktgen_cmd "$dev_file" "dst_max $FLOOD_DST_IP"
    pktgen_cmd "$dev_file" "dst_mac ff:ff:ff:ff:ff:ff"

    # Giới hạn PPS nếu được cấu hình (0 = không giới hạn)
    if [[ "$FLOOD_PPS" -gt 0 ]]; then
        pktgen_cmd "$dev_file" "rate $FLOOD_PPS"
    fi

    ok "pktgen đã cấu hình: src=$FLOOD_SRC_IP → dst=$FLOOD_DST_IP, size=64B"
}

start_flood() {
    log "Bắt đầu flood (sẽ tự stop sau ${FLOOD_DURATION}s)..."
    echo "start" > /proc/net/pktgen/pgctrl &
    PKTGEN_PID=$!
}

stop_flood() {
    echo "stop" > /proc/net/pktgen/pgctrl 2>/dev/null || true
    # Chờ pktgen dừng hẳn
    sleep 1
}

# ══════════════════════════════════════════════════════════════════════════════
# PHẦN 3: Đo CPU và throughput
# ══════════════════════════════════════════════════════════════════════════════

measure_cpu_usage() {
    # Đo CPU usage trong N giây, trả về phần trăm trung bình
    # mpstat: measure CPU stats, -u: report CPU utilization
    # Lấy dòng "Average" và field "%idle", rồi tính 100 - idle = usage
    local duration=$1
    local cpu_idle
    cpu_idle=$(mpstat -u 1 "$duration" 2>/dev/null \
        | awk '/^Average/ && /all/ {print $NF}' \
        | tail -1)

    if [[ -z "$cpu_idle" ]]; then
        echo "0"
        return
    fi
    # Tính 100 - idle = CPU usage
    echo "$(echo "scale=2; 100 - $cpu_idle" | bc)"
}

measure_pps() {
    # Đọc số packet đã được xử lý từ pktgen stats
    # /proc/net/pktgen/<iface> chứa thống kê sau khi flood
    local dev_file="/proc/net/pktgen/${IFACE}"
    if [[ ! -f "$dev_file" ]]; then
        echo "0"
        return
    fi

    # Tìm dòng "Result:" chứa thông tin packets và thời gian
    # Ví dụ: "Result: OK: 5000000(c4823761 ns) usec, 5000000 (64byte,0frags)"
    local result_line
    result_line=$(grep "Result:" "$dev_file" 2>/dev/null || echo "")

    if [[ -z "$result_line" ]]; then
        echo "0"
        return
    fi

    # Trích xuất số packets và thời gian (nanoseconds)
    local packets ns_elapsed pps
    packets=$(echo "$result_line" | grep -oP '\d+(?=\()' | head -1)
    ns_elapsed=$(echo "$result_line" | grep -oP '(?<=\(c)\d+(?= ns\))' | head -1)

    if [[ -z "$packets" || -z "$ns_elapsed" || "$ns_elapsed" -eq 0 ]]; then
        echo "0"
        return
    fi

    # PPS = packets / (nanoseconds / 1_000_000_000)
    pps=$(echo "scale=0; $packets * 1000000000 / $ns_elapsed" | bc)
    echo "$pps"
}

measure_rx_dropped() {
    # Đọc số packet bị DROP từ interface stats
    # Đây là con số quan trọng: XDP drop sẽ tăng rx_dropped,
    # còn iptables drop sẽ tăng counter khác (processed rồi mới drop)
    local rx_dropped
    rx_dropped=$(ip -s link show "$IFACE" 2>/dev/null \
        | awk '/RX:/{getline; print $4}' \
        | head -1)
    echo "${rx_dropped:-0}"
}

# ══════════════════════════════════════════════════════════════════════════════
# PHẦN 4: Hai phase benchmark
# ══════════════════════════════════════════════════════════════════════════════

phase_iptables() {
    header "PHASE A: Benchmark iptables DROP"
    log "Thêm iptables rule: DROP tất cả packet từ $FLOOD_SRC_IP"

    # Thêm rule DROP vào INPUT chain — đây là cách tường lửa truyền thống hoạt động:
    # packet đi vào kernel stack → traverse iptables chains → DROP ở đây
    # Toàn bộ overhead của kernel network stack (TCP/IP parsing, routing lookup...)
    # vẫn xảy ra TRƯỚC khi iptables có cơ hội drop.
    iptables -I INPUT -s "$FLOOD_SRC_IP" -j DROP
    iptables -I FORWARD -s "$FLOOD_SRC_IP" -j DROP
    ok "iptables rule đã thêm"

    # Reset pktgen stats trước khi đo
    setup_pktgen

    # Lưu rx_dropped baseline trước khi flood
    local rx_before
    rx_before=$(measure_rx_dropped)

    # Bắt đầu flood và đo CPU song song
    log "Bắt đầu flood ${FLOOD_DURATION}s, đo CPU usage..."
    start_flood
    IPTABLES_CPU=$(measure_cpu_usage "$FLOOD_DURATION")
    stop_flood

    # Đo throughput từ pktgen stats
    IPTABLES_PPS=$(measure_pps)

    # Đo rx_dropped sau flood
    local rx_after
    rx_after=$(measure_rx_dropped)
    IPTABLES_RXDROP=$(( rx_after - rx_before ))

    ok "Phase A hoàn tất:"
    log "  CPU usage:   ${IPTABLES_CPU}%"
    log "  PPS:         ${IPTABLES_PPS} pps"
    log "  RX dropped:  ${IPTABLES_RXDROP} packets"

    # Dọn dẹp iptables rules
    iptables -D INPUT -s "$FLOOD_SRC_IP" -j DROP 2>/dev/null || true
    iptables -D FORWARD -s "$FLOOD_SRC_IP" -j DROP 2>/dev/null || true

    # Xóa pktgen device để cấu hình lại cho phase tiếp theo
    echo "rem_device_all" > /proc/net/pktgen/kpktgend_0 2>/dev/null || true
    sleep 1
}

phase_xdp() {
    header "PHASE B: Benchmark XDP DROP"

    # Kiểm tra XDP object file đã tồn tại chưa
    if [[ ! -f "$XDP_OBJ" ]]; then
        warn "Không tìm thấy $XDP_OBJ"
        warn "XDP chưa được compile. Chạy: cd edge-node/kernel && make"
        warn "Phase XDP sẽ bị bỏ qua."
        XDP_CPU="N/A (chưa compile)"
        XDP_PPS="N/A"
        XDP_RXDROP="N/A"
        return
    fi

    # Load XDP program vào kernel và attach vào interface
    # XDP_DRV mode (native): chạy ở tầng driver, TRƯỚC khi packet
    # vào kernel network stack — đây là lý do XDP nhanh hơn iptables.
    # Nếu driver không hỗ trợ native mode (VirtualBox NIC), dùng XDP_SKB
    # (generic mode) — vẫn nhanh hơn iptables nhưng không đạt line-rate.
    log "Đang load XDP program vào interface $IFACE..."
    if ! ip link set "$IFACE" xdp obj "$XDP_OBJ" sec xdp 2>/dev/null; then
        warn "Native XDP không được hỗ trợ trên driver này, thử XDP generic mode..."
        ip link set "$IFACE" xdp obj "$XDP_OBJ" sec xdp verbose 2>&1 || {
            err "Không thể load XDP program."
            XDP_CPU="N/A (load failed)"
            XDP_PPS="N/A"
            XDP_RXDROP="N/A"
            return
        }
    fi
    ok "XDP program đã attach vào $IFACE"

    # Thêm FLOOD_SRC_IP vào eBPF blacklist Map
    # (XDP sẽ DROP packet từ IP này ngay tại driver level)
    log "Thêm $FLOOD_SRC_IP vào eBPF blacklist Map..."
    if command -v python3 &>/dev/null && [[ -f "edge-node/userspace/map_manager.py" ]]; then
        python3 edge-node/userspace/map_manager.py block "$FLOOD_SRC_IP" || {
            warn "Không thể thêm IP vào Map qua Python. Thử dùng bpftool..."
            local key_hex
            key_hex=$(python3 -c "
import socket, struct
packed = socket.inet_aton('$FLOOD_SRC_IP')
print(' '.join(f'{b:02x}' for b in packed))
" 2>/dev/null || echo "")
            if [[ -n "$key_hex" ]]; then
                bpftool map update pinned "$XDP_MAP_PIN" \
                    key hex $key_hex value hex 01 2>/dev/null || \
                    warn "Cả bpftool cũng thất bại — XDP sẽ không DROP packet"
            fi
        }
    fi

    # Reset và cấu hình lại pktgen
    setup_pktgen

    local rx_before
    rx_before=$(measure_rx_dropped)

    log "Bắt đầu flood ${FLOOD_DURATION}s, đo CPU usage..."
    start_flood
    XDP_CPU=$(measure_cpu_usage "$FLOOD_DURATION")
    stop_flood

    XDP_PPS=$(measure_pps)

    local rx_after
    rx_after=$(measure_rx_dropped)
    XDP_RXDROP=$(( rx_after - rx_before ))

    ok "Phase B hoàn tất:"
    log "  CPU usage:   ${XDP_CPU}%"
    log "  PPS:         ${XDP_PPS} pps"
    log "  RX dropped:  ${XDP_RXDROP} packets"

    # Gỡ XDP khỏi interface sau khi đo
    ip link set "$IFACE" xdp off 2>/dev/null || true
    echo "rem_device_all" > /proc/net/pktgen/kpktgend_0 2>/dev/null || true
}

# ══════════════════════════════════════════════════════════════════════════════
# PHẦN 5: Tổng hợp kết quả và lưu CSV
# ══════════════════════════════════════════════════════════════════════════════

print_comparison() {
    header "KẾT QUẢ SO SÁNH: XDP vs iptables"

    printf "\n  %-22s  %15s  %15s\n" "Metric" "iptables" "XDP"
    printf "  %-22s  %15s  %15s\n" "──────────────────────" "───────────────" "───────────────"
    printf "  %-22s  %15s  %15s\n" "CPU Usage (%)" "$IPTABLES_CPU" "$XDP_CPU"
    printf "  %-22s  %15s  %15s\n" "Throughput (pps)" "$IPTABLES_PPS" "$XDP_PPS"
    printf "  %-22s  %15s  %15s\n" "RX Dropped (packets)" "$IPTABLES_RXDROP" "$XDP_RXDROP"

    # Tính mức cải thiện nếu cả hai đều có số liệu thật
    if [[ "$IPTABLES_CPU" =~ ^[0-9] && "$XDP_CPU" =~ ^[0-9] ]]; then
        local cpu_improvement
        cpu_improvement=$(echo "scale=1; ($IPTABLES_CPU - $XDP_CPU) / $IPTABLES_CPU * 100" | bc 2>/dev/null || echo "?")
        printf "\n  ${GREEN}✓ XDP giảm CPU usage ${cpu_improvement}%% so với iptables${RESET}\n"
    fi

    echo ""
    echo "  💡 Giải thích kết quả:"
    echo "     - XDP DROP xảy ra tại driver level, TRƯỚC khi packet"
    echo "       vào sk_buff (kernel socket buffer). Không có allocation,"
    echo "       không có routing lookup, không có netfilter traversal."
    echo "     - iptables DROP xảy ra SAU khi packet đã được parse đầy đủ"
    echo "       bởi kernel network stack — mọi overhead đã xảy ra rồi."
    echo "     - Sự chênh lệch CPU usage = overhead của kernel stack."
}

save_results() {
    mkdir -p "$RESULTS_DIR"

    # Lưu CSV với metadata đầy đủ để tái hiện thí nghiệm sau này
    cat > "$RESULTS_FILE" << EOF
# pktgen_flood.sh benchmark results
# Timestamp: $(date -Iseconds)
# Interface: $IFACE
# Flood src IP: $FLOOD_SRC_IP
# Flood duration: ${FLOOD_DURATION}s
# Packet size: 64 bytes
# Kernel: $(uname -r)
# VM: $(hostname)
#
mechanism,cpu_percent,throughput_pps,rx_dropped_packets
iptables,$IPTABLES_CPU,$IPTABLES_PPS,$IPTABLES_RXDROP
xdp,$XDP_CPU,$XDP_PPS,$XDP_RXDROP
EOF

    ok "Kết quả đã lưu: $RESULTS_FILE"
    log "(Dùng file CSV này để vẽ biểu đồ bar chart trong báo cáo Tháng 3)"
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
main() {
    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════════════════╗"
    echo "║   pktgen Benchmark: XDP vs iptables         ║"
    echo "║   Interface: $IFACE  |  Duration: ${FLOOD_DURATION}s       ║"
    echo "╚══════════════════════════════════════════════╝"
    echo -e "${RESET}"

    check_deps
    cleanup_all

    [[ "$RUN_IPTABLES" == true ]] && phase_iptables
    [[ "$RUN_XDP" == true ]]      && phase_xdp

    print_comparison
    save_results

    log "Benchmark hoàn tất lúc $(date)"
}

main "$@"