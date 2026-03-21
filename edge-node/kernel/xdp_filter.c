/*
 * xdp_filter.c — Chương trình XDP chạy trong Linux Kernel space
 *
 * Chức năng: Kiểm tra IP nguồn của mỗi gói tin đến.
 * Nếu IP nằm trong eBPF LRU Hash Map (blacklist), lập tức DROP gói tin.
 * Nếu không có trong blacklist, trả về XDP_PASS để xử lý bình thường.
 *
 * Compile bằng: make (xem Makefile cùng thư mục)
 * Output: ../build/xdp_filter.o
 */
