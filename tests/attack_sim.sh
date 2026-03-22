#!/bin/bash
# attack_sim.sh — Mô phỏng kịch bản tấn công để kiểm thử hệ thống end-to-end
#
# Kịch bản 1: Dò quét diện rộng bằng nmap -> chạm Honeypot -> bị chặn toàn mạng
# Kịch bản 2: Brute-force SSH vào Unused IP -> bị phát hiện và đồng bộ blacklist
# Yêu cầu: nmap, hydra cài sẵn trên máy Attacker VM (192.168.56.99)
#!/usr/bin/env bash
# =============================================================================
# attack_sim.sh — Giả lập kẻ tấn công để kiểm thử hệ thống Honeypot
#
# Mục đích:
#   Script này chạy trên máy "Attacker" (VM thứ 3 trong lab), giả lập
#   các hành vi tấn công thực tế để kích hoạt Honeypot và kiểm tra
#   toàn bộ luồng: Honeypot phát hiện → Redis đồng bộ → XDP chặn.
#
# Kịch bản được test:
#   1. Port scan (nmap)         — chạm vào unused IPs của Honeypot
#   2. SSH brute-force          — thử đăng nhập vào FakeSSHService
#   3. Telnet brute-force       — thử đăng nhập vào FakeTelnetService
#   4. HTTP probing             — quét web với curl
#   5. Xác minh bị chặn        — ping/curl sau khi bị blacklist
#
# Cách dùng:
#   chmod +x tests/attack_sim.sh
#   ./tests/attack_sim.sh [TARGET_IP] [OPTIONS]
#
# Ví dụ:
#   ./tests/attack_sim.sh 192.168.56.10          # chạy tất cả kịch bản
#   ./tests/attack_sim.sh 192.168.56.10 --scan   # chỉ port scan
#   ./tests/attack_sim.sh 192.168.56.10 --brute  # chỉ brute-force
#   ./tests/attack_sim.sh 192.168.56.10 --verify # chỉ kiểm tra bị chặn chưa
#
# Yêu cầu cài đặt trên máy Attacker:
#   sudo apt install nmap hydra curl netcat-openbsd
#
# Lưu ý môi trường lab (khớp với network-topology.md):
#   VM1 — Edge Node 1:  192.168.56.10  (chạy XDP + node_agent)
#   VM2 — Edge Node 2:  192.168.56.11  (chạy XDP + node_agent)
#   VM3 — Attacker:     192.168.56.20  (chạy script này)
#   Honeypot chạy trên VM1, cổng: SSH=2222, Telnet=2323, HTTP=8080
# =============================================================================

set -euo pipefail

# ── Màu sắc cho output dễ đọc ─────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Cấu hình mặc định (override bằng biến môi trường hoặc argument) ───────────
TARGET_IP="${1:-192.168.56.10}"
SSH_PORT="${HONEYPOT_SSH_PORT:-2222}"
TELNET_PORT="${HONEYPOT_TELNET_PORT:-2323}"
HTTP_PORT="${HONEYPOT_HTTP_PORT:-8080}"

# Wordlist ngắn để brute-force nhanh trong môi trường lab
# (không cần dùng rockyou.txt — Honeypot sẽ phát hiện ngay lần đầu)
USERLIST="/tmp/honeypot_test_users.txt"
PASSLIST="/tmp/honeypot_test_passes.txt"

# Timeout (giây) chờ sau mỗi kịch bản để Redis đồng bộ
SYNC_WAIT=3

# Log file để ghi kết quả
LOG_FILE="attack_sim_$(date +%Y%m%d_%H%M%S).log"

# ── Tiện ích log ──────────────────────────────────────────────────────────────
log()  { echo -e "${CYAN}[$(date +%H:%M:%S)]${RESET} $*" | tee -a "$LOG_FILE"; }
ok()   { echo -e "${GREEN}[✓]${RESET} $*" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*" | tee -a "$LOG_FILE"; }
fail() { echo -e "${RED}[✗]${RESET} $*" | tee -a "$LOG_FILE"; }
header() {
    echo "" | tee -a "$LOG_FILE"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════${RESET}" | tee -a "$LOG_FILE"
    echo -e "${BOLD}  $*${RESET}" | tee -a "$LOG_FILE"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════${RESET}" | tee -a "$LOG_FILE"
}

# ── Kiểm tra dependencies ─────────────────────────────────────────────────────
check_deps() {
    local missing=()
    for cmd in nmap hydra curl nc; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        fail "Thiếu công cụ: ${missing[*]}"
        fail "Cài đặt: sudo apt install nmap hydra curl netcat-openbsd"
        exit 1
    fi
    ok "Tất cả dependencies đã có."
}

# ── Tạo wordlist ngắn cho lab ─────────────────────────────────────────────────
create_wordlists() {
    # Usernames phổ biến — đủ để Honeypot ghi nhận brute-force attempt
    cat > "$USERLIST" << 'EOF'
root
admin
ubuntu
user
test
pi
oracle
EOF

    # Passwords phổ biến — Honeypot sẽ log tất cả, không cần đúng
    cat > "$PASSLIST" << 'EOF'
password
123456
admin
root
toor
pass
qwerty
EOF
    ok "Đã tạo wordlist tạm tại $USERLIST và $PASSLIST"
}

# ══════════════════════════════════════════════════════════════════════════════
# KỊCH BẢN 1: Port Scan — đây là trigger chắc chắn nhất
# Nmap quét dải IP, tất yếu "chạm" vào các unused IPs mà Honeypot đang giữ.
# Chỉ cần 1 gói SYN đến honeypot IP là đủ để trigger on_intrusion.
# ══════════════════════════════════════════════════════════════════════════════
scenario_port_scan() {
    header "Kịch bản 1: Port Scan (nmap)"
    log "Target: $TARGET_IP — Quét các cổng honeypot"

    # Quét nhanh các cổng dịch vụ giả — đây là hành vi rõ ràng nhất của recon
    log "Quét cổng SSH giả ($SSH_PORT), Telnet giả ($TELNET_PORT), HTTP giả ($HTTP_PORT)..."
    nmap -sS -p "$SSH_PORT,$TELNET_PORT,$HTTP_PORT" \
         --open -T4 \
         "$TARGET_IP" \
         2>&1 | tee -a "$LOG_FILE" || true

    log "Chờ ${SYNC_WAIT}s để Redis đồng bộ đến các edge node..."
    sleep "$SYNC_WAIT"

    # Quét thêm một dải rộng hơn để đảm bảo chạm vào unused IPs
    # (Honeypot assign unused IPs trong cùng subnet)
    log "Quét rộng subnet để chạm vào unused IPs của Honeypot..."
    TARGET_SUBNET=$(echo "$TARGET_IP" | cut -d. -f1-3)
    nmap -sn "${TARGET_SUBNET}.0/24" \
         --exclude "$TARGET_IP" \
         -T4 \
         2>&1 | tee -a "$LOG_FILE" || true

    sleep "$SYNC_WAIT"
    ok "Kịch bản 1 hoàn tất. Kiểm tra log honeypot để xác nhận IP bị ghi nhận."
}

# ══════════════════════════════════════════════════════════════════════════════
# KỊCH BẢN 2: SSH Brute-force
# Hydra thử nhiều username/password trên cổng SSH giả.
# FakeSSHService sẽ ghi nhận từng lần thử và báo về Honeypot orchestrator.
# ══════════════════════════════════════════════════════════════════════════════
scenario_ssh_brute() {
    header "Kịch bản 2: SSH Brute-force (hydra)"
    log "Target: $TARGET_IP:$SSH_PORT"
    log "Wordlist: $(wc -l < "$USERLIST") users × $(wc -l < "$PASSLIST") passes"

    # -t 4: 4 kết nối song song — đủ để tạo nhiều hit, không quá aggressive
    # -f:   dừng khi tìm được kết hợp đúng (trong lab không có kết hợp đúng,
    #        nên hydra sẽ thử hết list rồi dừng)
    # -V:   verbose để thấy từng attempt trong log
    # -o:   lưu output ra file
    hydra -L "$USERLIST" \
          -P "$PASSLIST" \
          -t 4 \
          -f \
          -V \
          -o "${LOG_FILE%.log}_hydra_ssh.txt" \
          "ssh://$TARGET_IP:$SSH_PORT" \
          2>&1 | tee -a "$LOG_FILE" || true
    # "|| true" vì hydra exit code != 0 khi không tìm được pass — điều bình thường

    sleep "$SYNC_WAIT"
    ok "Kịch bản 2 hoàn tất."
}

# ══════════════════════════════════════════════════════════════════════════════
# KỊCH BẢN 3: Telnet Brute-force
# FakeTelnetService thu username/password, sau đó trả về "Login incorrect".
# ══════════════════════════════════════════════════════════════════════════════
scenario_telnet_brute() {
    header "Kịch bản 3: Telnet Brute-force (hydra)"
    log "Target: $TARGET_IP:$TELNET_PORT"

    hydra -L "$USERLIST" \
          -P "$PASSLIST" \
          -t 2 \
          -V \
          -o "${LOG_FILE%.log}_hydra_telnet.txt" \
          "telnet://$TARGET_IP:$TELNET_PORT" \
          2>&1 | tee -a "$LOG_FILE" || true

    sleep "$SYNC_WAIT"
    ok "Kịch bản 3 hoàn tất."
}

# ══════════════════════════════════════════════════════════════════════════════
# KỊCH BẢN 4: HTTP Probing
# Dùng curl để probe các path phổ biến mà attacker thường thử.
# FakeHTTPService ghi nhận request line và user-agent.
# ══════════════════════════════════════════════════════════════════════════════
scenario_http_probe() {
    header "Kịch bản 4: HTTP Probing (curl)"
    log "Target: http://$TARGET_IP:$HTTP_PORT"

    # Danh sách path phổ biến mà attacker thường quét
    local paths=(
        "/"
        "/admin"
        "/login"
        "/wp-admin"
        "/phpmyadmin"
        "/.env"
        "/api/v1"
        "/shell"
    )

    for path in "${paths[@]}"; do
        log "Probe: $path"
        curl --silent \
             --max-time 5 \
             --user-agent "Mozilla/5.0 (compatible; Googlebot/2.1)" \
             --output /dev/null \
             --write-out "HTTP %{http_code} — %{time_total}s\n" \
             "http://$TARGET_IP:$HTTP_PORT$path" \
             2>&1 | tee -a "$LOG_FILE" || true
        sleep 0.2
    done

    sleep "$SYNC_WAIT"
    ok "Kịch bản 4 hoàn tất."
}

# ══════════════════════════════════════════════════════════════════════════════
# KỊCH BẢN 5: Xác minh bị chặn
# Sau khi Honeypot đã report IP này lên Redis và các edge node đã cập nhật
# eBPF Map, thử kết nối lại — kết quả mong đợi là timeout hoàn toàn.
#
# Phân biệt "bị chặn bởi XDP" và "từ chối kết nối":
#   - Bị chặn XDP: packet bị DROP ở driver level → curl/ping timeout
#   - Bình thường (firewall reject): nhận RST/ICMP unreachable ngay lập tức
# ══════════════════════════════════════════════════════════════════════════════
scenario_verify_blocked() {
    header "Kịch bản 5: Xác minh bị chặn (sau khi Honeypot report)"
    log "Chờ thêm 5s để đảm bảo eBPF Map đã được cập nhật trên tất cả node..."
    sleep 5

    log "Thử ping (mong đợi: timeout nếu bị XDP DROP)..."
    local ping_result
    if ping -c 3 -W 2 "$TARGET_IP" &>/dev/null; then
        warn "Ping thành công — IP chưa bị chặn hoặc XDP chưa load."
    else
        ok "Ping timeout — có thể đã bị chặn bởi XDP (hoặc ICMP bị firewall)."
    fi

    log "Thử HTTP (mong đợi: connection timeout nếu bị XDP DROP)..."
    local http_result
    http_result=$(curl --silent \
                       --max-time 5 \
                       --connect-timeout 3 \
                       --write-out "%{http_code}|%{time_connect}|%{time_total}" \
                       --output /dev/null \
                       "http://$TARGET_IP:$HTTP_PORT/" 2>&1 || echo "TIMEOUT")

    if echo "$http_result" | grep -q "TIMEOUT\|000"; then
        ok "HTTP timeout — XDP đang DROP packets từ IP này. ✓"
        ok "Luồng đầy đủ hoạt động: Honeypot → Redis → NodeAgent → eBPF Map → XDP DROP"
    else
        warn "HTTP vẫn trả về response: $http_result"
        warn "Kiểm tra: (1) node_agent đang chạy chưa? (2) xdp_filter đã load chưa?"
    fi

    log "Thử kết nối SSH (mong đợi: timeout)..."
    if nc -z -w 3 "$TARGET_IP" "$SSH_PORT" 2>/dev/null; then
        warn "SSH port vẫn accessible — chưa bị chặn."
    else
        ok "SSH port không accessible (timeout) — XDP đang DROP. ✓"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# TỔNG HỢP: In thống kê cuối
# ══════════════════════════════════════════════════════════════════════════════
print_summary() {
    header "Tóm tắt kết quả"
    log "Log đầy đủ được lưu tại: $LOG_FILE"
    log ""
    log "Để kiểm tra kết quả trên Edge Node, chạy các lệnh sau trên VM1:"
    log "  # Xem log honeypot:"
    log "  tail -50 /home/vagrant/honeypot/honeypot.log"
    log ""
    log "  # Xem log node_agent:"
    log "  tail -50 /home/vagrant/edge-node/userspace/node_agent.log"
    log ""
    log "  # Kiểm tra eBPF Map đang chặn những IP nào:"
    log "  sudo python3 edge-node/userspace/map_manager.py list"
    log ""
    log "  # Kiểm tra thủ công Redis blacklist:"
    log "  redis-cli SMEMBERS firewall:persistent:blacklist"
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN — parse arguments và chạy kịch bản
# ══════════════════════════════════════════════════════════════════════════════
main() {
    echo -e "${BOLD}${CYAN}"
    echo "╔══════════════════════════════════════════╗"
    echo "║   Distributed Firewall — Attack Sim     ║"
    echo "║   Target: $TARGET_IP                    ║"
    echo "╚══════════════════════════════════════════╝"
    echo -e "${RESET}"

    log "Bắt đầu lúc: $(date)"
    log "Target IP: $TARGET_IP"
    log "SSH port: $SSH_PORT | Telnet port: $TELNET_PORT | HTTP port: $HTTP_PORT"

    check_deps
    create_wordlists

    # Parse option flag (argument thứ 2)
    local mode="${2:---all}"

    case "$mode" in
        --scan)
            scenario_port_scan
            ;;
        --brute)
            scenario_ssh_brute
            scenario_telnet_brute
            ;;
        --http)
            scenario_http_probe
            ;;
        --verify)
            scenario_verify_blocked
            ;;
        --all | *)
            log "Chạy tất cả kịch bản theo thứ tự..."
            scenario_port_scan
            scenario_ssh_brute
            scenario_telnet_brute
            scenario_http_probe
            scenario_verify_blocked
            ;;
    esac

    print_summary
    log "Hoàn tất lúc: $(date)"
}

main "$@"