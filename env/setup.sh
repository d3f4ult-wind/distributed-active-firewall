#!/bin/bash
# Script cài đặt tự động cho từng node trong hệ thống.
# Cài đặt: libbpf, clang, llvm (cho eBPF), redis-server, python3, pip.
# Chạy script này trên mỗi VM sau khi clone repository về.
# Sử dụng: ./setup.sh [edge|honeypot|broker]
#!/usr/bin/env bash
# =============================================================================
# setup.sh — Cài đặt tự động môi trường cho từng VM
#
# Được gọi bởi Vagrant provisioner với biến môi trường NODE_ROLE:
#   edge_and_honeypot  — VM1: cài tất cả (XDP tools, Redis, Python deps)
#   edge_only          — VM2: chỉ cài XDP tools + Python deps (không Redis)
#   attacker           — VM3: chỉ cài công cụ tấn công
#
# Cũng có thể chạy thủ công trên VM đã có sẵn:
#   sudo NODE_ROLE=edge_and_honeypot bash setup.sh
# =============================================================================

set -euo pipefail

# ── Màu sắc ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; RESET='\033[0m'
log()    { echo -e "${CYAN}[setup]${RESET} $*"; }
ok()     { echo -e "${GREEN}[  OK ]${RESET} $*"; }
section(){ echo -e "\n${YELLOW}▶ $*${RESET}"; }

# ── Biến môi trường (Vagrant truyền vào, hoặc set thủ công) ──────────────────
NODE_ROLE="${NODE_ROLE:-edge_and_honeypot}"
NODE_ID="${NODE_ID:-edge-node-1}"
REDIS_HOST="${REDIS_HOST:-127.0.0.1}"
REDIS_PORT="${REDIS_PORT:-6379}"
NODE_IP="${NODE_IP:-192.168.56.10}"

PROJECT_DIR="/home/vagrant/project"
VENV_DIR="/home/vagrant/venv"

log "Bắt đầu setup cho role: $NODE_ROLE (NODE_ID=$NODE_ID)"

# ══════════════════════════════════════════════════════════════════════════════
# BƯỚC 1: Cập nhật hệ thống (chạy cho tất cả role)
# ══════════════════════════════════════════════════════════════════════════════
section "Cập nhật apt package list"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
ok "apt update xong"

# ══════════════════════════════════════════════════════════════════════════════
# BƯỚC 2: Cài đặt theo từng role
# ══════════════════════════════════════════════════════════════════════════════

install_common_tools() {
    section "Cài đặt công cụ chung"
    apt-get install -y -qq \
        python3.11 python3.11-venv python3-pip \
        git curl wget net-tools \
        iproute2 iputils-ping tcpdump \
        netcat-openbsd
    ok "Common tools đã cài xong"
}

install_ebpf_tools() {
    section "Cài đặt eBPF/XDP tools"

    # libbpf-dev: header files và shared library để compile + link XDP programs
    # linux-tools: cung cấp bpftool để inspect/pin eBPF objects
    # clang + llvm: compiler để build xdp_filter.c → xdp_filter.o (eBPF bytecode)
    # linux-headers: cần thiết để build eBPF program (include kernel headers)
    KERNEL_VER=$(uname -r)
    apt-get install -y -qq \
        libbpf-dev \
        linux-tools-"${KERNEL_VER}" \
        linux-tools-generic \
        clang \
        llvm \
        gcc \
        make \
        linux-headers-"${KERNEL_VER}" \
        pkg-config

    # Mount BPF filesystem nếu chưa có
    # eBPF Map được "pin" tại /sys/fs/bpf/ để userspace có thể truy cập
    if ! mountpoint -q /sys/fs/bpf; then
        mount -t bpf bpf /sys/fs/bpf
        log "Đã mount BPF filesystem tại /sys/fs/bpf"
    fi

    # Đảm bảo BPF filesystem tự mount khi reboot
    if ! grep -q "bpf" /etc/fstab; then
        echo "bpf    /sys/fs/bpf    bpf    defaults    0 0" >> /etc/fstab
        log "Đã thêm BPF filesystem vào /etc/fstab"
    fi

    ok "eBPF/XDP tools đã cài xong"
    log "Kernel version: $KERNEL_VER"
    log "bpftool version: $(bpftool version 2>/dev/null | head -1 || echo 'chưa tìm thấy')"
}

install_redis() {
    section "Cài đặt Redis server"
    apt-get install -y -qq redis-server

    # Cấu hình Redis để lắng nghe trên tất cả interface
    # (mặc định chỉ bind 127.0.0.1 — VM2 không kết nối được)
    sed -i 's/^bind 127.0.0.1 -::1/bind 0.0.0.0/' /etc/redis/redis.conf

    # Tắt protected mode vì đây là môi trường lab (không expose ra internet)
    sed -i 's/^protected-mode yes/protected-mode no/' /etc/redis/redis.conf

    systemctl restart redis-server
    systemctl enable redis-server

    ok "Redis đã cài và đang chạy"
    log "Redis status: $(redis-cli ping)"
}

install_python_deps() {
    section "Cài đặt Python dependencies trong virtualenv"

    # Tạo virtualenv tách biệt — tránh conflict với system Python
    python3.11 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"

    pip install --quiet --upgrade pip

    # Cài deps cho honeypot
    if [ -f "$PROJECT_DIR/honeypot/requirements.txt" ]; then
        pip install --quiet -r "$PROJECT_DIR/honeypot/requirements.txt"
        ok "Honeypot deps đã cài"
    fi

    # Cài thêm deps cho edge-node
    pip install --quiet "redis[hiredis]>=5.0.0"
    ok "Edge-node deps đã cài"

    deactivate
    ok "Python virtualenv sẵn sàng tại $VENV_DIR"
}

install_attack_tools() {
    section "Cài đặt công cụ tấn công (cho VM Attacker)"
    apt-get install -y -qq \
        nmap \
        hydra \
        curl \
        netcat-openbsd
    ok "Attack tools đã cài: nmap, hydra, curl, nc"
}

# ══════════════════════════════════════════════════════════════════════════════
# BƯỚC 3: Cấu hình kernel — SYN Cookie và các tham số mạng
# Áp dụng cho edge nodes (VM1, VM2) — phần multistate firewall trong proposal
# ══════════════════════════════════════════════════════════════════════════════
configure_kernel_network() {
    section "Cấu hình kernel networking"

    # SYN Cookie: bảo vệ TCP stack khỏi SYN Flood mà không cần XDP xử lý
    # Đây là "tầng stateful" phía sau XDP trong kiến trúc multistate firewall
    sysctl -w net.ipv4.tcp_syncookies=1

    # Tăng backlog queue để chịu được nhiều kết nối đồng thời hơn khi benchmark
    sysctl -w net.ipv4.tcp_max_syn_backlog=4096
    sysctl -w net.core.somaxconn=4096

    # Tắt IPv6 để đơn giản hóa (đề tài chỉ xử lý IPv4)
    sysctl -w net.ipv6.conf.all.disable_ipv6=1
    sysctl -w net.ipv6.conf.default.disable_ipv6=1

    # Lưu cấu hình để áp dụng sau reboot
    cat >> /etc/sysctl.conf << 'EOF'

# === Distributed Firewall Lab Settings ===
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.core.somaxconn = 4096
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF

    ok "Kernel network params đã được cấu hình"
    log "SYN Cookie: $(sysctl -n net.ipv4.tcp_syncookies)"
}

# ══════════════════════════════════════════════════════════════════════════════
# BƯỚC 4: Tạo file .env cho từng VM
# ══════════════════════════════════════════════════════════════════════════════
create_env_file() {
    section "Tạo file .env"
    ENV_FILE="$PROJECT_DIR/.env"

    cat > "$ENV_FILE" << EOF
# Auto-generated by setup.sh cho $NODE_ID
# Chỉnh sửa nếu cần thay đổi cấu hình

# Redis
REDIS_HOST=$REDIS_HOST
REDIS_PORT=$REDIS_PORT
REDIS_PASSWORD=

# Node identity
NODE_ID=$NODE_ID
NODE_IP=$NODE_IP

# Honeypot ports (chỉ dùng trên VM1)
HONEYPOT_SSH_PORT=2222
HONEYPOT_TELNET_PORT=2323
HONEYPOT_HTTP_PORT=8080
HONEYPOT_HIT_THRESHOLD=1

# eBPF Map
# Đặt USE_REAL_EBPF=true sau khi xdp_filter.c đã được compile và load
USE_REAL_EBPF=false
EBPF_MAP_PIN_PATH=/sys/fs/bpf/xdp_blacklist
EOF

    chown vagrant:vagrant "$ENV_FILE"
    ok "Đã tạo .env tại $ENV_FILE"
}

# ══════════════════════════════════════════════════════════════════════════════
# BƯỚC 5: Tạo systemd service để auto-start khi reboot
# ══════════════════════════════════════════════════════════════════════════════
create_systemd_services() {
    section "Tạo systemd services"

    # Service cho node_agent (chạy trên cả VM1 và VM2)
    cat > /etc/systemd/system/firewall-agent.service << EOF
[Unit]
Description=Distributed Firewall Node Agent
After=network.target redis.service
Wants=redis.service

[Service]
Type=simple
User=vagrant
WorkingDirectory=$PROJECT_DIR
EnvironmentFile=$PROJECT_DIR/.env
ExecStart=$VENV_DIR/bin/python edge-node/userspace/node_agent.py
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    # Service cho honeypot (chỉ cần trên VM1, nhưng tạo sẵn cũng không hại)
    cat > /etc/systemd/system/firewall-honeypot.service << EOF
[Unit]
Description=Distributed Firewall Honeypot
After=network.target redis.service
Wants=redis.service

[Service]
Type=simple
User=vagrant
WorkingDirectory=$PROJECT_DIR/honeypot
EnvironmentFile=$PROJECT_DIR/.env
ExecStart=$VENV_DIR/bin/python honeypot.py
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload

    # Chỉ enable (chưa start) — vì XDP chưa load, USE_REAL_EBPF=false
    # Sau khi load XDP xong, chạy: sudo systemctl start firewall-agent
    systemctl enable firewall-agent.service
    if [ "$NODE_ROLE" = "edge_and_honeypot" ]; then
        systemctl enable firewall-honeypot.service
    fi

    ok "systemd services đã tạo (chưa start — chờ XDP load)"
    log "Để start thủ công: sudo systemctl start firewall-agent firewall-honeypot"
}

# ══════════════════════════════════════════════════════════════════════════════
# BƯỚC 6: Shortcuts / aliases tiện dụng cho vagrant user
# ══════════════════════════════════════════════════════════════════════════════
setup_aliases() {
    ALIASES_FILE="/home/vagrant/.bash_aliases"
    cat >> "$ALIASES_FILE" << 'EOF'

# === Distributed Firewall Lab Aliases ===
alias fw-agent-start='sudo systemctl start firewall-agent'
alias fw-agent-stop='sudo systemctl stop firewall-agent'
alias fw-agent-log='journalctl -u firewall-agent -f'

alias fw-honeypot-start='sudo systemctl start firewall-honeypot'
alias fw-honeypot-stop='sudo systemctl stop firewall-honeypot'
alias fw-honeypot-log='journalctl -u firewall-honeypot -f'

alias fw-map-list='sudo python3 /home/vagrant/project/edge-node/userspace/map_manager.py list'
alias fw-blacklist='redis-cli SMEMBERS firewall:persistent:blacklist'
alias fw-redis-sub='redis-cli SUBSCRIBE firewall:blacklist:add firewall:events'

alias act='source /home/vagrant/venv/bin/activate'
EOF
    chown vagrant:vagrant "$ALIASES_FILE"
    ok "Aliases đã thêm vào ~/.bash_aliases"
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN — Chạy theo role
# ══════════════════════════════════════════════════════════════════════════════
case "$NODE_ROLE" in
    edge_and_honeypot)
        install_common_tools
        install_ebpf_tools
        install_redis
        install_python_deps
        configure_kernel_network
        create_env_file
        create_systemd_services
        setup_aliases
        ;;
    edge_only)
        install_common_tools
        install_ebpf_tools
        install_python_deps
        configure_kernel_network
        create_env_file
        create_systemd_services
        setup_aliases
        ;;
    attacker)
        install_common_tools
        install_attack_tools
        ;;
    *)
        echo "NODE_ROLE không hợp lệ: $NODE_ROLE"
        echo "Chọn một trong: edge_and_honeypot | edge_only | attacker"
        exit 1
        ;;
esac

# ── In tóm tắt cuối ────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}║   Setup hoàn tất cho: $NODE_ROLE    ${RESET}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${RESET}"

if [ "$NODE_ROLE" != "attacker" ]; then
    echo ""
    log "Bước tiếp theo:"
    log "  1. vagrant ssh edge1"
    log "  2. cd project && act  (activate virtualenv)"
    log "  3. Chạy test ngay:  pytest tests/ -v"
    log "  4. Sau khi có XDP:  USE_REAL_EBPF=true sudo systemctl start firewall-agent"
fi