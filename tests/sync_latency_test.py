# sync_latency_test.py — Đo độ trễ đồng bộ blacklist giữa các node
#
# Chức năng: Đo thời gian (milliseconds) từ lúc Honeypot publish IP lên Redis
# đến lúc tất cả Edge Node xác nhận đã cập nhật xong eBPF Map.
# Đây là chỉ số quan trọng nhất để chứng minh tính 'gần như tức thời' của hệ thống.
# Kết quả được lưu vào results/raw/sync_latency.csv