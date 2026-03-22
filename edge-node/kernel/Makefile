# Makefile — Biên dịch chương trình XDP/eBPF từ C sang BPF bytecode
#
# Yêu cầu: clang, llvm, libbpf-dev đã được cài đặt (xem env/setup.sh)
# Lệnh build  : make
# Lệnh clean  : make clean
# Output file : ../build/xdp_filter.o (được git-ignore, không commit)
# -------------------------------------------------------------------
# Makefile — Compile xdp_filter.c thành eBPF object file
#
# Cách dùng:
#   make          — compile xdp_filter.c → build/xdp_filter.o
#   make clean    — xóa build/
#   make load     — compile + attach vào IFACE (mặc định: eth1)
#   make unload   — gỡ XDP khỏi IFACE
#   make verify   — kiểm tra program đã load chưa bằng bpftool
#
# Biến có thể override:
#   make load IFACE=eth0
#   make load IFACE=ens3

# ── Cấu hình ──────────────────────────────────────────────────────────────────
IFACE     ?= eth1
SRC        = xdp_filter.c
OBJ        = build/xdp_filter.o
BPF_SEC    = xdp

# clang bắt buộc (gcc không hỗ trợ -target bpf)
CC         = clang

# Flags giải thích:
#   -O2           : Bắt buộc — verifier yêu cầu optimized code
#   -g            : Thêm BTF (BPF Type Format) debug info
#   -target bpf   : Compile thành eBPF bytecode, không phải x86
#   -D__TARGET_ARCH_x86 : Khai báo target arch cho bpf_tracing.h
#   -I/usr/include/bpf  : Path đến libbpf headers (libbpf-dev)
CFLAGS     = -O2 -g -target bpf \
             -D__TARGET_ARCH_x86 \
             -I/usr/include/bpf \
             -Wall -Wno-unused-value -Wno-pointer-sign \
             -Wno-compare-distinct-pointer-types

# ── Targets ───────────────────────────────────────────────────────────────────
.PHONY: all clean load unload verify help

all: $(OBJ)

$(OBJ): $(SRC) | build/
	@echo "[CC]  $< → $@"
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "[OK]  Compile thành công: $@"
	@echo "      Kiểm tra: llvm-objdump -S $@"

build/:
	mkdir -p build

clean:
	rm -rf build/
	@echo "[OK]  Đã xóa build/"

load: $(OBJ)
	@echo "[XDP] Đang attach vào interface $(IFACE)..."
	sudo ip link set $(IFACE) xdp obj $(OBJ) sec $(BPF_SEC) verbose
	@echo "[OK]  XDP đã attach. Kiểm tra: ip link show $(IFACE)"

unload:
	@echo "[XDP] Đang gỡ XDP khỏi $(IFACE)..."
	sudo ip link set $(IFACE) xdp off
	@echo "[OK]  XDP đã gỡ"

verify:
	@echo "[INFO] Kiểm tra XDP program trên $(IFACE):"
	ip link show $(IFACE) | grep xdp || echo "  Không có XDP program nào đang chạy"
	@echo ""
	@echo "[INFO] eBPF Map tại /sys/fs/bpf/xdp_blacklist:"
	@sudo bpftool map show pinned /sys/fs/bpf/xdp_blacklist 2>/dev/null || \
		echo "  Map chưa được pin (XDP chưa load?)"

help:
	@echo "Targets: all | clean | load | unload | verify"
	@echo "Ví dụ:   make load IFACE=eth1"