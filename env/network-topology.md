# Sơ đồ mạng và cấu hình IP các VM (Network Topology)
# Ghi rõ địa chỉ IP, subnet, vai trò của từng máy ảo trong môi trường VirtualBox.
# Ví dụ:
# - 192.168.56.10 : Redis Broker
# - 192.168.56.11 : Edge Node 1
# - 192.168.56.12 : Honeypot
# - 192.168.56.99 : Attacker (máy tấn công giả lập)
# --------------------------------------------------------------------------------
# Network Topology — Lab Environment

## Sơ đồ mạng

```
Host Machine (VirtualBox)
│
├── Host-only Network: 192.168.56.0/24
│   │
│   ├── VM1 — edge-node-1       192.168.56.10
│   │         eth0: NAT (internet)
│   │         eth1: 192.168.56.10 (host-only)
│   │         Chạy: Redis, Honeypot, XDP, node_agent
│   │
│   ├── VM2 — edge-node-2       192.168.56.11
│   │         eth0: NAT (internet)
│   │         eth1: 192.168.56.11 (host-only)
│   │         Chạy: XDP, node_agent (Redis client → VM1)
│   │
│   └── VM3 — attacker          192.168.56.20
│             eth0: NAT (internet)
│             eth1: 192.168.56.20 (host-only)
│             Chạy: nmap, hydra, attack_sim.sh
│
└── XDP attach interface: eth1 (host-only NIC) trên VM1 và VM2
```

## Cấu hình từng VM

| VM  | Hostname     | IP             | RAM   | CPU | Role                        |
|-----|--------------|----------------|-------|-----|-----------------------------|
| VM1 | edge-node-1  | 192.168.56.10  | 1024M | 2   | Edge + Redis + Honeypot     |
| VM2 | edge-node-2  | 192.168.56.11  | 512M  | 2   | Edge only                   |
| VM3 | attacker     | 192.168.56.20  | 512M  | 1   | Attack simulation           |

## Services và ports

| Service         | VM  | Port  | Ghi chú                          |
|-----------------|-----|-------|----------------------------------|
| Redis           | VM1 | 6379  | Bind 0.0.0.0 (lab only)          |
| Honeypot SSH    | VM1 | 2222  | FakeSSHService                   |
| Honeypot Telnet | VM1 | 2323  | FakeTelnetService                |
| Honeypot HTTP   | VM1 | 8080  | FakeHTTPService                  |
| XDP attach      | VM1 | -     | eth1 (192.168.56.10)             |
| XDP attach      | VM2 | -     | eth1 (192.168.56.11)             |

## XDP Interface

XDP program được attach vào interface **eth1** (host-only NIC) — đây là interface
nhận traffic từ attacker VM. Không attach vào eth0 (NAT) để tránh ảnh hưởng
đến kết nối internet của VM.

Lệnh attach (sau khi compile xdp_filter.c):
```bash
# Trên VM1 và VM2
sudo ip link set eth1 xdp obj build/xdp_filter.o sec xdp
# Kiểm tra
sudo ip link show eth1
```