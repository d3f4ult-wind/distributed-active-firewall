# map_manager.py — Quản lý eBPF LRU Hash Map từ userspace
# Chức năng: Cung cấp các hàm thêm/xóa IP vào eBPF Map đang chạy trong kernel.
# Đây là cầu nối giữa thế giới Python (userspace) và bộ nhớ eBPF (kernel space).
# Sử dụng thư viện pyroute2 hoặc ctypes để ghi trực tiếp vào Map file descriptor.
"""
map_manager.py — Đọc/ghi eBPF LRU Hash Map từ userspace Python.

Vị trí trong kiến trúc:
  Đây là tầng thấp nhất phía userspace — nó "chạm tay" trực tiếp vào
  kernel memory thông qua file descriptor của eBPF Map.

  node_agent.py
      └── RealEbpfMap (trong node_agent.py)
              └── EbpfMapManager  ← file này
                      └── libbpf.so / bpftool  ← kernel boundary
                              └── eBPF LRU Hash Map (trong kernel)
                                      └── XDP hook: DROP packet

Hai implementation được cung cấp:

  1. LibbpfMapManager  — Dùng ctypes gọi trực tiếp vào libbpf.so.
       Ưu điểm: Nhanh (~microseconds), không tạo process mới.
       Dùng khi: Production (hot path khi nhận IP từ Redis).

  2. BpftoolMapManager — Dùng subprocess gọi `bpftool map`.
       Ưu điểm: Dễ debug, không cần libbpf header, output dạng JSON.
       Dùng khi: Admin script, monitoring, kiểm tra Map từ CLI.

Cách eBPF Map được truy cập (kiến thức nền quan trọng):
  Khi xdp_filter.c load vào kernel, nó "pin" Map vào BPF filesystem:
      /sys/fs/bpf/xdp_blacklist
  Đây giống như một "file" đặc biệt — userspace mở file này để lấy
  file descriptor (fd), rồi dùng fd để gọi bpf() syscall.

  Trong Map, mỗi entry có dạng:
      key:   IPv4 address dưới dạng __u32 (4 bytes, network byte order)
      value: __u8 = 1  (chỉ cần key tồn tại là đủ, value không quan trọng)

  Ví dụ: "192.168.1.100"
      → socket.inet_aton("192.168.1.100") → b'\xc0\xa8\x01\x64'
      → struct.unpack("!I", ...) → 3232235876
      → ctypes.c_uint32(3232235876) → key cho bpf_map_update_elem()
"""

import asyncio
import ctypes
import ctypes.util
import ipaddress
import json
import logging
import os
import socket
import struct
import subprocess
from abc import ABC, abstractmethod
from typing import Optional

logger = logging.getLogger("edge_node.map_manager")


# ══════════════════════════════════════════════════════════════════════════════
# PHẦN 1: Các hằng số và kiểu dữ liệu dùng chung với kernel
# ══════════════════════════════════════════════════════════════════════════════

# Các hằng số này phải khớp chính xác với định nghĩa trong linux/bpf.h
# và xdp_filter.c — nếu sai, bpf() syscall sẽ trả về EINVAL.

BPF_MAP_LOOKUP_ELEM = 1   # syscall command: tìm một key
BPF_MAP_UPDATE_ELEM = 2   # syscall command: thêm/cập nhật một entry
BPF_MAP_DELETE_ELEM = 3   # syscall command: xóa một entry
BPF_MAP_GET_NEXT_KEY = 4  # syscall command: iterate qua các key

# Flags cho BPF_MAP_UPDATE_ELEM — khớp với linux/bpf.h
BPF_ANY     = 0  # Tạo mới hoặc cập nhật (ta dùng cái này)
BPF_NOEXIST = 1  # Chỉ tạo mới, lỗi nếu đã tồn tại
BPF_EXIST   = 2  # Chỉ cập nhật, lỗi nếu chưa tồn tại

# Path mặc định nơi xdp_filter.c pin Map — phải khớp với C code
DEFAULT_MAP_PIN_PATH = "/sys/fs/bpf/xdp_blacklist"


class BpfAttr(ctypes.Structure):
    """
    Struct truyền vào bpf() syscall — ánh xạ 1:1 với union bpf_attr trong kernel.

    Lý do dùng ctypes.Structure:
      bpf() syscall nhận một pointer đến một vùng memory có layout cụ thể.
      ctypes.Structure đảm bảo Python tạo ra đúng layout đó trong memory,
      không có padding ẩn hay thứ tự byte sai.

    Trường hợp dùng ở đây là cho BPF_MAP_*_ELEM operations,
    tương ứng với anonymous struct thứ 2 trong union bpf_attr:
        struct {
            __u32   map_fd;
            __u64   key;
            union { __u64 value; __u64 next_key; };
            __u64   flags;
        };

    Tại sao key và value là __u64 (pointer) chứ không phải __u32 (giá trị)?
      Vì bpf() không nhận giá trị trực tiếp — nó nhận POINTER đến giá trị.
      Ta phải tạo biến C, rồi truyền địa chỉ của biến đó (cast sang __u64).
      Đây là chi tiết quan trọng nhất khi dùng ctypes với bpf syscall.
    """
    _fields_ = [
        ("map_fd", ctypes.c_uint32),
        ("pad0",   ctypes.c_uint32),   # padding để align key về offset 8
        ("key",    ctypes.c_uint64),   # pointer đến key buffer
        ("value",  ctypes.c_uint64),   # pointer đến value buffer (hoặc next_key)
        ("flags",  ctypes.c_uint64),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# PHẦN 2: Abstract base class cho Map Manager
# ══════════════════════════════════════════════════════════════════════════════

class EbpfMapManager(ABC):
    """
    Interface chung cho tất cả cách truy cập eBPF Map.
    Tách biệt với EbpfMapInterface trong node_agent.py vì:
      - EbpfMapInterface: hợp đồng ở tầng NodeAgent (async, high-level)
      - EbpfMapManager:   hợp đồng ở tầng kernel interface (sync, low-level)
    node_agent.RealEbpfMap sẽ wrap EbpfMapManager thành async.
    """

    @abstractmethod
    def open(self) -> None:
        """Mở file descriptor đến Map. Phải gọi trước mọi thao tác khác."""
        ...

    @abstractmethod
    def close(self) -> None:
        """Giải phóng file descriptor."""
        ...

    @abstractmethod
    def block_ip(self, ip: str) -> bool:
        """Thêm IP vào Map. Trả về True nếu thành công."""
        ...

    @abstractmethod
    def unblock_ip(self, ip: str) -> bool:
        """Xóa IP khỏi Map. Trả về True nếu thành công."""
        ...

    @abstractmethod
    def is_blocked(self, ip: str) -> bool:
        """Kiểm tra IP có trong Map không."""
        ...

    @abstractmethod
    def get_all_blocked_ips(self) -> list[str]:
        """Lấy toàn bộ IP đang bị block."""
        ...

    # Context manager support — cho phép dùng `with LibbpfMapManager() as mgr:`
    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()


# ══════════════════════════════════════════════════════════════════════════════
# PHẦN 3: LibbpfMapManager — giao tiếp trực tiếp qua libbpf + ctypes
# ══════════════════════════════════════════════════════════════════════════════

class LibbpfMapManager(EbpfMapManager):
    """
    Giao tiếp với eBPF Map thông qua libbpf.so bằng ctypes.

    Đây là implementation dùng cho production vì:
      - Mỗi thao tác block/unblock là một syscall duy nhất
      - Latency cỡ microseconds (không có process spawn overhead)
      - Phù hợp cho cold start khi cần load hàng nghìn IP một lúc

    Yêu cầu:
      - libbpf.so phải được cài: `apt install libbpf-dev`
      - Map phải được pin tại DEFAULT_MAP_PIN_PATH bởi xdp_filter.c
      - Chạy với quyền root (hoặc CAP_BPF capability)

    Sơ đồ gọi hàm:
      block_ip("1.2.3.4")
          → _ip_to_key("1.2.3.4")        # chuyển string → c_uint32
          → _bpf_map_update(fd, key, val) # gọi libbpf
              → bpf_map_update_elem(fd, &key, &val, BPF_ANY)  # libbpf C
                  → bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr))  # syscall
    """

    def __init__(self, map_pin_path: str = DEFAULT_MAP_PIN_PATH):
        self.map_pin_path = map_pin_path
        self._fd: Optional[int] = None
        self._libbpf: Optional[ctypes.CDLL] = None

    # ── Khởi tạo ──────────────────────────────────────────────────────────────

    def open(self) -> None:
        """
        Tải libbpf.so và mở file descriptor đến pinned Map.

        Tại sao phải gọi bpf_obj_get() thay vì open() thông thường?
          /sys/fs/bpf/xdp_blacklist không phải file thông thường —
          nó là BPF object. Ta cần bpf_obj_get() để lấy fd hợp lệ.
        """
        # Tìm và load libbpf
        lib_path = ctypes.util.find_library("bpf")
        if not lib_path:
            # Thử path cứng phổ biến trên Ubuntu/Debian
            for candidate in ["/usr/lib/x86_64-linux-gnu/libbpf.so.0",
                               "/usr/lib/libbpf.so.0",
                               "/usr/local/lib/libbpf.so"]:
                if os.path.exists(candidate):
                    lib_path = candidate
                    break
        if not lib_path:
            raise FileNotFoundError(
                "Không tìm thấy libbpf.so. "
                "Cài đặt: sudo apt install libbpf-dev"
            )

        self._libbpf = ctypes.CDLL(lib_path, use_errno=True)

        # Khai báo signature của hàm bpf_obj_get() trong libbpf:
        #   int bpf_obj_get(const char *pathname);
        # Trả về fd >= 0 nếu thành công, -1 nếu lỗi (errno được set).
        self._libbpf.bpf_obj_get.restype = ctypes.c_int
        self._libbpf.bpf_obj_get.argtypes = [ctypes.c_char_p]

        fd = self._libbpf.bpf_obj_get(self.map_pin_path.encode())
        if fd < 0:
            errno = ctypes.get_errno()
            raise OSError(
                errno,
                f"bpf_obj_get('{self.map_pin_path}') thất bại: "
                f"{os.strerror(errno)}. "
                f"Kiểm tra: (1) xdp_filter đã load chưa? "
                f"(2) Chạy với quyền root chưa? "
                f"(3) Path map đúng chưa?"
            )

        self._fd = fd
        logger.info(f"Đã mở eBPF Map fd={fd} tại '{self.map_pin_path}'")

    def close(self) -> None:
        if self._fd is not None and self._fd >= 0:
            os.close(self._fd)
            self._fd = None
            logger.debug("Đã đóng eBPF Map fd.")

    # ── Thao tác chính ────────────────────────────────────────────────────────

    def block_ip(self, ip: str) -> bool:
        """
        Thêm IP vào LRU Hash Map → XDP sẽ DROP mọi packet từ IP này.

        Dùng BPF_ANY flag để:
          - Nếu IP chưa có: tạo entry mới
          - Nếu IP đã có:   cập nhật (trong trường hợp này giống no-op
            vì value luôn là 1, nhưng tránh được lỗi EEXIST)

        Lưu ý về LRU:
          BPF_MAP_TYPE_LRU_HASH tự quản lý bộ nhớ — khi Map đầy,
          kernel tự xóa entry ít được dùng nhất (LRU eviction).
          Ta không cần lo về việc Map bị đầy.
        """
        self._assert_open()
        try:
            key = self._ip_to_c_key(ip)
            value = ctypes.c_uint8(1)
            ret = self._bpf_map_update(key, value, BPF_ANY)
            if ret == 0:
                logger.debug(f"block_ip({ip}): OK")
                return True
            else:
                errno = ctypes.get_errno()
                logger.error(f"block_ip({ip}): lỗi errno={errno} ({os.strerror(errno)})")
                return False
        except ValueError as exc:
            logger.error(f"block_ip: IP không hợp lệ '{ip}': {exc}")
            return False

    def unblock_ip(self, ip: str) -> bool:
        """
        Xóa IP khỏi Map → XDP cho phép packet đi qua.

        bpf_map_delete_elem() trả về -ENOENT nếu key không tồn tại.
        Ta coi trường hợp này là "thành công" (idempotent operation)
        vì kết quả cuối cùng đều là IP không có trong Map.
        """
        self._assert_open()
        try:
            key = self._ip_to_c_key(ip)
            ret = self._bpf_map_delete(key)
            if ret == 0:
                logger.debug(f"unblock_ip({ip}): OK")
                return True
            else:
                errno = ctypes.get_errno()
                if errno == 2:  # ENOENT — IP không có trong Map
                    logger.debug(f"unblock_ip({ip}): IP không có trong Map (OK)")
                    return True  # idempotent
                logger.error(f"unblock_ip({ip}): lỗi errno={errno} ({os.strerror(errno)})")
                return False
        except ValueError as exc:
            logger.error(f"unblock_ip: IP không hợp lệ '{ip}': {exc}")
            return False

    def is_blocked(self, ip: str) -> bool:
        """
        Kiểm tra IP có trong Map không bằng BPF_MAP_LOOKUP_ELEM.

        Trả về True nếu lookup thành công (key tồn tại).
        Trả về False nếu errno == ENOENT (key không tồn tại).
        """
        self._assert_open()
        try:
            key = self._ip_to_c_key(ip)
            value = ctypes.c_uint8(0)  # buffer để nhận value
            ret = self._bpf_map_lookup(key, value)
            return ret == 0
        except ValueError:
            return False

    def get_all_blocked_ips(self) -> list[str]:
        """
        Iterate qua toàn bộ Map bằng BPF_MAP_GET_NEXT_KEY.

        Thuật toán iterate eBPF Map:
          1. Gọi GET_NEXT_KEY với key=NULL → trả về key đầu tiên
          2. Gọi GET_NEXT_KEY với key=k1   → trả về k2
          3. Gọi GET_NEXT_KEY với key=k2   → trả về k3
          ... tiếp tục cho đến khi trả về -ENOENT (hết Map)

        Lưu ý quan trọng:
          LRU Map có thể bị evict entry trong lúc iterate nếu có
          concurrent writes. Đây là trade-off chấp nhận được cho
          mục đích monitoring/logging — không dùng cho control path.
        """
        self._assert_open()
        blocked_ips = []
        current_key = ctypes.c_uint32(0)
        next_key = ctypes.c_uint32(0)

        # Bắt đầu iteration: truyền NULL pointer cho prev_key
        ret = self._bpf_map_get_next_key(None, next_key)
        if ret != 0:
            # Map rỗng hoặc lỗi
            return []

        current_key.value = next_key.value
        blocked_ips.append(self._c_key_to_ip(current_key))

        # Tiếp tục lấy key kế tiếp
        while True:
            ret = self._bpf_map_get_next_key(current_key, next_key)
            if ret != 0:
                # errno == ENOENT nghĩa là đã hết Map — thoát vòng lặp
                break
            current_key.value = next_key.value
            blocked_ips.append(self._c_key_to_ip(current_key))

        return blocked_ips

    # ── Helper: chuyển đổi IP ─────────────────────────────────────────────────

    @staticmethod
    def _ip_to_c_key(ip_str: str) -> ctypes.c_uint32:
        """
        Chuyển IPv4 string → ctypes.c_uint32 (network byte order).

        Ví dụ minh hoạ bước chuyển đổi:
          "192.168.1.100"
          → socket.inet_aton()     → b'\xc0\xa8\x01\x64'  (4 bytes)
          → struct.unpack("!I")    → (3232235876,)          (big-endian uint32)
          → ctypes.c_uint32(...)   → c_uint32(3232235876)  (C type cho ctypes)

        Tại sao dùng "!I" (network byte order, big-endian)?
          IPv4 trong eBPF Map được lưu theo network byte order —
          đây là convention của Linux kernel networking stack.
          Nếu dùng host byte order (little-endian trên x86), key sẽ không
          khớp với key mà XDP code tạo ra, dẫn đến lookup miss.
        """
        try:
            packed = socket.inet_aton(ip_str)         # "1.2.3.4" → 4 bytes
            ip_int = struct.unpack("!I", packed)[0]   # bytes → big-endian uint32
            return ctypes.c_uint32(ip_int)
        except OSError:
            raise ValueError(f"'{ip_str}' không phải IPv4 hợp lệ")

    @staticmethod
    def _c_key_to_ip(key: ctypes.c_uint32) -> str:
        """
        Chuyển ngược: ctypes.c_uint32 → IPv4 string.
        Dùng khi iterate Map để đọc ra IP dạng người đọc được.
        """
        packed = struct.pack("!I", key.value)  # uint32 → 4 bytes big-endian
        return socket.inet_ntoa(packed)        # 4 bytes → "1.2.3.4"

    # ── Helper: wrapper cho bpf() syscall ─────────────────────────────────────

    def _bpf_map_update(
        self,
        key: ctypes.c_uint32,
        value: ctypes.c_uint8,
        flags: int = BPF_ANY,
    ) -> int:
        """
        Wrap syscall: bpf(BPF_MAP_UPDATE_ELEM, attr, sizeof(attr))

        Tại sao phải dùng ctypes.addressof() để lấy địa chỉ?
          bpf() nhận POINTER đến key/value, không phải giá trị trực tiếp.
          ctypes.addressof(key) trả về địa chỉ memory của biến C 'key',
          cast sang c_uint64 vì kernel dùng __u64 để lưu pointer.
        """
        attr = BpfAttr(
            map_fd=self._fd,
            key=ctypes.addressof(key),
            value=ctypes.addressof(value),
            flags=flags,
        )
        return self._bpf_syscall(BPF_MAP_UPDATE_ELEM, attr)

    def _bpf_map_delete(self, key: ctypes.c_uint32) -> int:
        """Wrap syscall: bpf(BPF_MAP_DELETE_ELEM, ...)"""
        attr = BpfAttr(
            map_fd=self._fd,
            key=ctypes.addressof(key),
        )
        return self._bpf_syscall(BPF_MAP_DELETE_ELEM, attr)

    def _bpf_map_lookup(
        self,
        key: ctypes.c_uint32,
        value: ctypes.c_uint8,
    ) -> int:
        """Wrap syscall: bpf(BPF_MAP_LOOKUP_ELEM, ...)"""
        attr = BpfAttr(
            map_fd=self._fd,
            key=ctypes.addressof(key),
            value=ctypes.addressof(value),
        )
        return self._bpf_syscall(BPF_MAP_LOOKUP_ELEM, attr)

    def _bpf_map_get_next_key(
        self,
        current_key: Optional[ctypes.c_uint32],
        next_key: ctypes.c_uint32,
    ) -> int:
        """
        Wrap syscall: bpf(BPF_MAP_GET_NEXT_KEY, ...)
        current_key=None để lấy key đầu tiên (bắt đầu iteration).
        """
        attr = BpfAttr(
            map_fd=self._fd,
            # Nếu current_key là None, truyền 0 (NULL pointer)
            key=ctypes.addressof(current_key) if current_key is not None else 0,
            value=ctypes.addressof(next_key),  # next_key trả về qua trường 'value'
        )
        return self._bpf_syscall(BPF_MAP_GET_NEXT_KEY, attr)

    @staticmethod
    def _bpf_syscall(cmd: int, attr: BpfAttr) -> int:
        """
        Gọi bpf() syscall trực tiếp qua ctypes.

        Tại sao không dùng libbpf ở đây mà gọi syscall thẳng?
          Các hàm map operation (update/delete/lookup) trong libbpf
          thực chất chỉ là thin wrapper quanh syscall bpf() này.
          Gọi thẳng ngắn gọn hơn và không phụ thuộc vào việc libbpf
          export đúng symbol hay không trên mọi distro.

        Số syscall 321 là NR_bpf trên x86_64 Linux.
        Nếu chạy trên ARM64 (Raspberry Pi), số này là 280.
        """
        NR_BPF = 321  # x86_64; ARM64: 280

        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        libc.syscall.restype = ctypes.c_long
        libc.syscall.argtypes = [ctypes.c_long, ctypes.c_int,
                                  ctypes.c_void_p, ctypes.c_uint]

        ret = libc.syscall(
            NR_BPF,
            ctypes.c_int(cmd),
            ctypes.byref(attr),
            ctypes.c_uint(ctypes.sizeof(attr)),
        )
        return int(ret)

    def _assert_open(self) -> None:
        if self._fd is None:
            raise RuntimeError("Map chưa được open(). Gọi open() hoặc dùng context manager.")


# ══════════════════════════════════════════════════════════════════════════════
# PHẦN 4: BpftoolMapManager — dùng subprocess bpftool (cho admin/debug)
# ══════════════════════════════════════════════════════════════════════════════

class BpftoolMapManager(EbpfMapManager):
    """
    Giao tiếp với eBPF Map thông qua công cụ CLI 'bpftool'.

    Không dùng cho hot path vì mỗi thao tác spawn một subprocess (~10-50ms).
    Dùng khi:
      - Debug: kiểm tra nhanh nội dung Map từ terminal
      - Admin script: `python map_manager.py list`
      - Unit test trên máy chưa có libbpf-dev

    Ví dụ lệnh bpftool tương đương:
      block:   bpftool map update pinned /sys/fs/bpf/xdp_blacklist \
                   key hex c0 a8 01 64  value hex 01
      unblock: bpftool map delete pinned /sys/fs/bpf/xdp_blacklist \
                   key hex c0 a8 01 64
      lookup:  bpftool map lookup pinned /sys/fs/bpf/xdp_blacklist \
                   key hex c0 a8 01 64
      list:    bpftool map dump pinned /sys/fs/bpf/xdp_blacklist -j
    """

    def __init__(self, map_pin_path: str = DEFAULT_MAP_PIN_PATH):
        self.map_pin_path = map_pin_path
        self._bpftool_path: Optional[str] = None

    def open(self) -> None:
        """Kiểm tra bpftool có sẵn không."""
        import shutil
        path = shutil.which("bpftool")
        if not path:
            raise FileNotFoundError(
                "bpftool không tìm thấy trong PATH. "
                "Cài đặt: sudo apt install linux-tools-$(uname -r)"
            )
        self._bpftool_path = path
        logger.info(f"BpftoolMapManager sẵn sàng: {path}")

    def close(self) -> None:
        self._bpftool_path = None

    def block_ip(self, ip: str) -> bool:
        """
        bpftool map update pinned <path> key hex <bytes> value hex 01

        Chuyển IP thành hex bytes để truyền cho bpftool:
          "1.2.3.4" → b'\x01\x02\x03\x04' → "01 02 03 04"
        """
        key_hex = self._ip_to_hex(ip)
        cmd = [
            self._bpftool_path, "map", "update",
            "pinned", self.map_pin_path,
            "key", "hex", *key_hex.split(),
            "value", "hex", "01",
        ]
        return self._run(cmd, f"block_ip({ip})")

    def unblock_ip(self, ip: str) -> bool:
        key_hex = self._ip_to_hex(ip)
        cmd = [
            self._bpftool_path, "map", "delete",
            "pinned", self.map_pin_path,
            "key", "hex", *key_hex.split(),
        ]
        # Bpftool trả về lỗi nếu key không tồn tại, nhưng ta vẫn coi là OK
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0 or "No such" in result.stderr:
            logger.debug(f"unblock_ip({ip}): OK")
            return True
        logger.error(f"unblock_ip({ip}): {result.stderr.strip()}")
        return False

    def is_blocked(self, ip: str) -> bool:
        key_hex = self._ip_to_hex(ip)
        cmd = [
            self._bpftool_path, "map", "lookup",
            "pinned", self.map_pin_path,
            "key", "hex", *key_hex.split(),
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.returncode == 0

    def get_all_blocked_ips(self) -> list[str]:
        """
        bpftool map dump pinned <path> --json
        Trả về JSON array, mỗi phần tử có dạng:
          {"key": ["0xc0","0xa8","0x01","0x64"], "value": ["0x01"]}
        Ta parse "key" bytes → IP string.
        """
        cmd = [
            self._bpftool_path, "map", "dump",
            "pinned", self.map_pin_path,
            "--json",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            logger.error(f"get_all_blocked_ips: {result.stderr.strip()}")
            return []

        try:
            entries = json.loads(result.stdout)
            ips = []
            for entry in entries:
                key_bytes = bytes(int(b, 16) for b in entry["key"])
                ips.append(socket.inet_ntoa(key_bytes))
            return ips
        except (json.JSONDecodeError, KeyError, ValueError) as exc:
            logger.error(f"Parse bpftool output lỗi: {exc}")
            return []

    @staticmethod
    def _ip_to_hex(ip: str) -> str:
        """
        "192.168.1.100" → "c0 a8 01 64"
        Đây là format bpftool dùng để nhận key dạng raw bytes.
        """
        packed = socket.inet_aton(ip)
        return " ".join(f"{b:02x}" for b in packed)

    def _run(self, cmd: list, label: str) -> bool:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            logger.debug(f"{label}: OK")
            return True
        logger.error(f"{label}: {result.stderr.strip()}")
        return False


# ══════════════════════════════════════════════════════════════════════════════
# PHẦN 5: AsyncMapManager — wrap đồng bộ thành async để dùng với node_agent
# ══════════════════════════════════════════════════════════════════════════════

class AsyncMapManager:
    """
    Wrapper async cho EbpfMapManager.

    Tại sao cần wrapper này?
      LibbpfMapManager là synchronous (gọi syscall blocking).
      node_agent.py chạy trên asyncio event loop.
      Nếu gọi syscall trực tiếp từ coroutine, nó sẽ BLOCK toàn bộ
      event loop trong thời gian syscall thực thi — điều này phá vỡ
      tính async của node_agent, đặc biệt khi cold start load hàng
      nghìn IP liên tiếp.

    Giải pháp: asyncio.get_event_loop().run_in_executor() chạy
    synchronous call trong một thread pool riêng, giữ event loop
    luôn unblocked.

    Trong thực tế, một syscall bpf() chỉ tốn vài microseconds nên
    tác động là rất nhỏ. Nhưng đây là best practice để code sạch
    và sẵn sàng cho trường hợp worst-case.
    """

    def __init__(self, manager: EbpfMapManager):
        self._mgr = manager
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    async def __aenter__(self):
        self._loop = asyncio.get_running_loop()
        await self._run_sync(self._mgr.open)
        return self

    async def __aexit__(self, *args):
        await self._run_sync(self._mgr.close)

    async def block_ip(self, ip: str) -> bool:
        return await self._run_sync(self._mgr.block_ip, ip)

    async def unblock_ip(self, ip: str) -> bool:
        return await self._run_sync(self._mgr.unblock_ip, ip)

    async def is_blocked(self, ip: str) -> bool:
        return await self._run_sync(self._mgr.is_blocked, ip)

    async def get_all_blocked_ips(self) -> list[str]:
        return await self._run_sync(self._mgr.get_all_blocked_ips)

    async def _run_sync(self, func, *args):
        """Chạy synchronous function trong thread pool."""
        loop = self._loop or asyncio.get_running_loop()
        return await loop.run_in_executor(None, func, *args)


# ══════════════════════════════════════════════════════════════════════════════
# PHẦN 6: RealEbpfMap — implement EbpfMapInterface dùng AsyncMapManager
# Đây là class sẽ được truyền vào NodeAgent(..., ebpf_map=RealEbpfMap())
# ══════════════════════════════════════════════════════════════════════════════

def make_real_ebpf_map(map_pin_path: str = DEFAULT_MAP_PIN_PATH):
    """
    Factory function trả về một object implement EbpfMapInterface
    bằng cách dùng LibbpfMapManager.

    Tại sao là factory function chứ không phải class?
      Để giữ node_agent.py không cần import map_manager.py — tránh
      circular dependency và giữ interface tách biệt với implementation.

    Cách dùng trong node_agent.py (Tuần 3):
      from map_manager import make_real_ebpf_map
      agent = NodeAgent(ebpf_map=make_real_ebpf_map())

    Implementation dùng composition thay vì kế thừa để giữ linh hoạt.
    """
    from node_agent import EbpfMapInterface, BlockResult

    class _RealEbpfMap(EbpfMapInterface):
        def __init__(self):
            self._sync_mgr = LibbpfMapManager(map_pin_path)
            self._async_mgr = AsyncMapManager(self._sync_mgr)
            self._initialized = False

        async def _ensure_open(self):
            if not self._initialized:
                await self._async_mgr._run_sync(self._sync_mgr.open)
                self._initialized = True

        async def block_ip(self, ip: str) -> BlockResult:
            await self._ensure_open()
            success = await self._async_mgr.block_ip(ip)
            return BlockResult(
                success=success, ip=ip, action="block",
                message="" if success else "libbpf syscall thất bại"
            )

        async def unblock_ip(self, ip: str) -> BlockResult:
            await self._ensure_open()
            success = await self._async_mgr.unblock_ip(ip)
            return BlockResult(
                success=success, ip=ip, action="unblock",
                message="" if success else "libbpf syscall thất bại"
            )

        async def get_blocked_ips(self) -> list[str]:
            await self._ensure_open()
            return await self._async_mgr.get_all_blocked_ips()

        async def is_blocked(self, ip: str) -> bool:
            await self._ensure_open()
            return await self._async_mgr.is_blocked(ip)

    return _RealEbpfMap()


# ══════════════════════════════════════════════════════════════════════════════
# PHẦN 7: CLI admin tool
# ══════════════════════════════════════════════════════════════════════════════

def _cli():
    """
    Dùng map_manager.py như một admin tool từ CLI:

      sudo python map_manager.py list
      sudo python map_manager.py block 1.2.3.4
      sudo python map_manager.py unblock 1.2.3.4
      sudo python map_manager.py check 1.2.3.4

    Dùng BpftoolMapManager vì dễ debug hơn (output human-readable).
    """
    import sys
    if len(sys.argv) < 2:
        print("Dùng: python map_manager.py [list|block|unblock|check] [ip]")
        sys.exit(1)

    cmd = sys.argv[1].lower()
    with BpftoolMapManager() as mgr:
        if cmd == "list":
            ips = mgr.get_all_blocked_ips()
            if not ips:
                print("Map trống (không có IP nào bị chặn).")
            else:
                print(f"Đang chặn {len(ips)} IP:")
                for ip in sorted(ips):
                    print(f"  {ip}")

        elif cmd in ("block", "unblock", "check"):
            if len(sys.argv) < 3:
                print(f"Dùng: python map_manager.py {cmd} <ip>")
                sys.exit(1)
            ip = sys.argv[2]
            if cmd == "block":
                ok = mgr.block_ip(ip)
                print(f"{'✓ Đã block' if ok else '✗ Lỗi khi block'} {ip}")
            elif cmd == "unblock":
                ok = mgr.unblock_ip(ip)
                print(f"{'✓ Đã unblock' if ok else '✗ Lỗi khi unblock'} {ip}")
            elif cmd == "check":
                blocked = mgr.is_blocked(ip)
                print(f"{ip}: {'BỊ CHẶN 🔒' if blocked else 'Được phép ✓'}")
        else:
            print(f"Lệnh không hợp lệ: {cmd}")
            sys.exit(1)


if __name__ == "__main__":
    _cli()