# node_agent.py — Agent chính chạy liên tục trên mỗi Edge Node
#
# Chức năng: Subscribe vào kênh Redis Pub/Sub, lắng nghe thông báo IP xấu mới.
# Khi nhận được IP từ Honeypot qua Redis, gọi map_manager.py để cập nhật blacklist
# vào eBPF Map ngay lập tức — đây là bước 'Đồng bộ' trong chu trình Phát hiện->Chặn.
# Đọc cấu hình kết nối Redis từ file .env (không hardcode IP vào đây).