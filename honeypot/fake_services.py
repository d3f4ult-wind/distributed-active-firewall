# fake_services.py — Các dịch vụ giả mạo để dụ kẻ tấn công
#
# Chức năng: Mở các cổng dịch vụ phổ biến (SSH:22, Telnet:23) trên Unused IPs.
# Ghi nhận thông tin kẻ tấn công: IP nguồn, timestamp, loại tấn công (scan/brute-force).
# KHÔNG cung cấp dịch vụ thật — mọi kết nối đến đây đều là bẫy.