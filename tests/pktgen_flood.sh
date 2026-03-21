#!/bin/bash
# pktgen_flood.sh — Benchmark hiệu năng XDP so với iptables dưới tải cao
#
# Sử dụng pktgen (Linux kernel packet generator) để 'bắn' gói tin tốc độ cao.
# Đo và ghi lại: CPU usage, packet throughput (pps), drop rate.
# Chạy 2 lần: một lần với XDP, một lần với iptables -> xuất kết quả vào results/raw/
