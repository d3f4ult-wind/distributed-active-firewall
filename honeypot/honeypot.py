# honeypot.py — Điều phối chính của hệ thống Honeypot
#
# Chức năng: Khởi động tất cả các dịch vụ giả mạo (SSH, Telnet) và lắng nghe.
# Bất kỳ kết nối nào đến các Unused IP đều bị coi là hành vi đáng ngờ.
# Khi phát hiện kẻ tấn công, gọi reporter.py để phát tín hiệu lên Redis.
# Đây là bước 'Phát hiện' trong chu trình Phát hiện -> Đồng bộ -> Chặn.