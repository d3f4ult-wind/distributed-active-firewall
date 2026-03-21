# map_manager.py — Quản lý eBPF LRU Hash Map từ userspace
#
# Chức năng: Cung cấp các hàm thêm/xóa IP vào eBPF Map đang chạy trong kernel.
# Đây là cầu nối giữa thế giới Python (userspace) và bộ nhớ eBPF (kernel space).
# Sử dụng thư viện pyroute2 hoặc ctypes để ghi trực tiếp vào Map file descriptor.