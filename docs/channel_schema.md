# Định dạng Message trao đổi qua Redis (Interface Contract)
# Đây là 'hợp đồng giao tiếp' giữa Honeypot và các Edge Node.
# Mọi thay đổi định dạng message phải được cập nhật ở đây trước khi sửa code.
# Ví dụ format: { 'ip': '1.2.3.4', 'timestamp': '...', 'reason': 'port_scan' }