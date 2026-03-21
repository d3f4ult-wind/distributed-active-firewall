#!/bin/bash
# attack_sim.sh — Mô phỏng kịch bản tấn công để kiểm thử hệ thống end-to-end
#
# Kịch bản 1: Dò quét diện rộng bằng nmap -> chạm Honeypot -> bị chặn toàn mạng
# Kịch bản 2: Brute-force SSH vào Unused IP -> bị phát hiện và đồng bộ blacklist
# Yêu cầu: nmap, hydra cài sẵn trên máy Attacker VM (192.168.56.99)
