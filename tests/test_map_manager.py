"""
test_map_manager.py — Unit test cho map_manager.py.

Thách thức khi test map_manager:
  LibbpfMapManager gọi bpf() syscall — không thể chạy trên máy thường,
  cần môi trường Linux với kernel eBPF và Map đã được load.

Giải pháp: mock ở 2 tầng khác nhau.

  Tầng 1 — MockEbpfMapManager:
    Implement EbpfMapManager bằng dict Python thuần.
    Test toàn bộ logic: IP conversion, idempotent unblock, iteration...
    mà không cần bất kỳ thứ gì liên quan đến kernel.

  Tầng 2 — Patch ctypes (test nâng cao):
    Dùng unittest.mock.patch để thay thế ctypes calls bằng mock.
    Kiểm tra rằng _ip_to_c_key(), BpfAttr layout, và syscall number
    được truyền đúng — mà vẫn không cần kernel thật.

Chạy:
  pytest tests/test_map_manager.py -v
"""

import asyncio
import ctypes
import socket
import struct
import sys
import os
from unittest.mock import MagicMock, patch, call

import pytest
import pytest_asyncio

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "edge-node", "userspace"))

from map_manager import (
    LibbpfMapManager,
    BpftoolMapManager,
    AsyncMapManager,
    EbpfMapManager,
    BpfAttr,
    BPF_MAP_UPDATE_ELEM,
    BPF_MAP_DELETE_ELEM,
    BPF_MAP_LOOKUP_ELEM,
    BPF_ANY,
    DEFAULT_MAP_PIN_PATH,
)


# ══════════════════════════════════════════════════════════════════════════════
# MockEbpfMapManager — implementation giả cho test
# ══════════════════════════════════════════════════════════════════════════════

class MockEbpfMapManager(EbpfMapManager):
    """
    Dùng dict Python để giả lập eBPF LRU Hash Map.
    Dùng trong unit test và trong quá trình dev trước khi có kernel module.
    """
    def __init__(self):
        self._store: dict[str, int] = {}
        self._is_open = False

    def open(self) -> None:
        self._is_open = True

    def close(self) -> None:
        self._is_open = False

    def block_ip(self, ip: str) -> bool:
        self._store[ip] = 1
        return True

    def unblock_ip(self, ip: str) -> bool:
        self._store.pop(ip, None)  # idempotent — không lỗi nếu key không có
        return True

    def is_blocked(self, ip: str) -> bool:
        return ip in self._store

    def get_all_blocked_ips(self) -> list[str]:
        return list(self._store.keys())

    def read_stats(self) -> dict[str, int]:
        return {"dropped": 0, "passed": 0}

# ══════════════════════════════════════════════════════════════════════════════
# TEST 1: Logic IP conversion — quan trọng nhất
# Sai ở đây → mọi thứ đều sai (key không khớp với XDP C code)
# ══════════════════════════════════════════════════════════════════════════════

class TestIpConversion:
    """
    Kiểm tra chuyển đổi IPv4 string ↔ ctypes.c_uint32.

    Đây là test quan trọng nhất vì nếu byte order sai,
    XDP sẽ không bao giờ match được key, IP sẽ không bị chặn.
    """

    def test_loopback_converts_correctly(self):
        """127.0.0.1 phải ra 0x7f000001 = 2130706433"""
        key = LibbpfMapManager._ip_to_c_key("127.0.0.1")
        assert isinstance(key, ctypes.c_uint32)
        # 127=0x7f, 0, 0, 1 → big-endian: 0x7f000001
        assert key.value == 0x7F000001

    def test_common_private_ip(self):
        """192.168.1.1 → 0xC0A80101 = 3232235777"""
        key = LibbpfMapManager._ip_to_c_key("192.168.1.1")
        assert key.value == 0xC0A80101

    def test_broadcast_address(self):
        """255.255.255.255 → 0xFFFFFFFF = 4294967295"""
        key = LibbpfMapManager._ip_to_c_key("255.255.255.255")
        assert key.value == 0xFFFFFFFF

    def test_zero_address(self):
        """0.0.0.0 → 0x00000000 = 0"""
        key = LibbpfMapManager._ip_to_c_key("0.0.0.0")
        assert key.value == 0

    def test_invalid_ip_raises_value_error(self):
        """IP không hợp lệ phải raise ValueError, không crash."""
        with pytest.raises(ValueError, match="không phải IPv4"):
            LibbpfMapManager._ip_to_c_key("999.999.999.999")

        with pytest.raises(ValueError):
            LibbpfMapManager._ip_to_c_key("not-an-ip")

    def test_roundtrip_ip_to_key_and_back(self):
        """
        Chuyển IP → key → IP phải cho ra IP gốc.
        Kiểm tra tính nhất quán của hai chiều conversion.
        """
        test_ips = [
            "10.0.0.1",
            "172.16.254.1",
            "192.168.100.200",
            "1.1.1.1",
        ]
        for ip in test_ips:
            key = LibbpfMapManager._ip_to_c_key(ip)
            recovered = LibbpfMapManager._c_key_to_ip(key)
            assert recovered == ip, f"Roundtrip thất bại: {ip} → {key.value} → {recovered}"

    def test_byte_order_is_network_order(self):
        """
        Xác nhận dùng NETWORK byte order (big-endian), không phải host order.

        Trên x86_64 (little-endian), host order và network order khác nhau.
        Test này đảm bảo ta không vô tình dùng host order.

        IP "1.2.3.4":
          Network order (big-endian): 0x01020304
          Host order (little-endian): 0x04030201  ← SAI
        """
        key = LibbpfMapManager._ip_to_c_key("1.2.3.4")
        assert key.value == 0x01020304, (
            f"Byte order sai! Nhận {hex(key.value)}, mong đợi 0x01020304. "
            "Kiểm tra lại struct.unpack('!I', ...) — '!' là network byte order."
        )


# ══════════════════════════════════════════════════════════════════════════════
# TEST 2: Logic Map operations với MockEbpfMapManager
# ══════════════════════════════════════════════════════════════════════════════

class TestMapOperationsWithMock:
    """
    Kiểm tra logic block/unblock/iterate với MockEbpfMapManager.
    Không cần kernel — chạy được trên bất kỳ máy nào.
    """

    def test_block_then_check(self):
        with MockEbpfMapManager() as mgr:
            assert not mgr.is_blocked("10.0.0.1")
            assert mgr.block_ip("10.0.0.1")
            assert mgr.is_blocked("10.0.0.1")

    def test_block_then_unblock(self):
        with MockEbpfMapManager() as mgr:
            mgr.block_ip("10.0.0.2")
            assert mgr.is_blocked("10.0.0.2")
            mgr.unblock_ip("10.0.0.2")
            assert not mgr.is_blocked("10.0.0.2")

    def test_unblock_nonexistent_is_idempotent(self):
        """
        Unblock IP chưa bao giờ bị block không được raise exception.
        Đây là thiết kế idempotent — quan trọng cho cold start sync.
        """
        with MockEbpfMapManager() as mgr:
            result = mgr.unblock_ip("192.168.99.99")
            assert result is True  # không crash, trả về True

    def test_block_multiple_ips(self):
        ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "172.16.0.100"]
        with MockEbpfMapManager() as mgr:
            for ip in ips:
                mgr.block_ip(ip)
            blocked = set(mgr.get_all_blocked_ips())
            assert blocked == set(ips)

    def test_block_same_ip_twice_is_idempotent(self):
        """Block cùng IP 2 lần — Map chỉ có 1 entry."""
        with MockEbpfMapManager() as mgr:
            mgr.block_ip("10.0.0.1")
            mgr.block_ip("10.0.0.1")  # lần 2
            all_ips = mgr.get_all_blocked_ips()
            assert all_ips.count("10.0.0.1") == 1

    def test_get_all_empty_map(self):
        with MockEbpfMapManager() as mgr:
            assert mgr.get_all_blocked_ips() == []

    def test_partial_unblock(self):
        """Unblock một IP trong khi các IP khác vẫn còn trong Map."""
        with MockEbpfMapManager() as mgr:
            for ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3"]:
                mgr.block_ip(ip)
            mgr.unblock_ip("2.2.2.2")
            remaining = set(mgr.get_all_blocked_ips())
            assert remaining == {"1.1.1.1", "3.3.3.3"}
            assert "2.2.2.2" not in remaining


# ══════════════════════════════════════════════════════════════════════════════
# TEST 3: BpfAttr layout — kiểm tra struct memory layout
# ══════════════════════════════════════════════════════════════════════════════

class TestBpfAttrLayout:
    """
    Kiểm tra BpfAttr struct có đúng size và offset không.

    Tại sao test này quan trọng?
      Nếu struct layout sai (vd: thiếu padding), kernel sẽ đọc sai
      field và syscall sẽ fail hoặc, tệ hơn, ghi sai vào kernel memory.
      Test này "đóng đinh" layout trước khi chạy trên kernel thật.

    Layout mong đợi (theo union bpf_attr, phần cho map ops):
      offset 0:  map_fd  (4 bytes)
      offset 4:  pad0    (4 bytes padding)
      offset 8:  key     (8 bytes — __u64 pointer)
      offset 16: value   (8 bytes — __u64 pointer)
      offset 24: flags   (8 bytes — __u64)
      total:     32 bytes
    """

    def test_bpf_attr_size(self):
        """BpfAttr phải đúng 32 bytes."""
        assert ctypes.sizeof(BpfAttr) == 32, (
            f"BpfAttr size sai: {ctypes.sizeof(BpfAttr)} bytes, mong đợi 32 bytes. "
            "Kiểm tra lại _fields_ — có thể thiếu padding."
        )

    def test_map_fd_offset(self):
        """map_fd phải ở offset 0."""
        assert BpfAttr.map_fd.offset == 0

    def test_key_offset(self):
        """key phải ở offset 8 (sau map_fd 4 bytes + pad 4 bytes)."""
        assert BpfAttr.key.offset == 8

    def test_value_offset(self):
        """value phải ở offset 16."""
        assert BpfAttr.value.offset == 16

    def test_flags_offset(self):
        """flags phải ở offset 24."""
        assert BpfAttr.flags.offset == 24

    def test_map_fd_is_set_correctly(self):
        """Kiểm tra map_fd được gán đúng vào struct."""
        attr = BpfAttr(map_fd=42)
        assert attr.map_fd == 42

    def test_flags_default_zero(self):
        """flags mặc định phải là 0 khi không truyền vào."""
        attr = BpfAttr(map_fd=1)
        assert attr.flags == 0


# ══════════════════════════════════════════════════════════════════════════════
# TEST 4: LibbpfMapManager với mock syscall
# Kiểm tra rằng các tham số truyền vào syscall là đúng
# ══════════════════════════════════════════════════════════════════════════════

class TestLibbpfWithMockedSyscall:
    """
    Patch toàn bộ tầng libbpf để kiểm tra LibbpfMapManager
    truyền đúng tham số vào syscall.

    Kỹ thuật dùng: mock _bpf_syscall ở class level, inject fd giả.
    """

    def _make_manager_with_mock_fd(self):
        """Tạo LibbpfMapManager với fd giả (không mở file thật)."""
        mgr = LibbpfMapManager.__new__(LibbpfMapManager)
        mgr.map_pin_path = DEFAULT_MAP_PIN_PATH
        mgr._fd = 5  # fd giả
        mgr._libbpf = None
        return mgr

    def test_block_ip_calls_update_with_bpf_any(self):
        """
        block_ip() phải gọi _bpf_map_update() với flag BPF_ANY (=0).
        Flag sai → kernel từ chối hoặc hành vi không đúng.
        """
        mgr = self._make_manager_with_mock_fd()

        with patch.object(LibbpfMapManager, '_bpf_map_update', return_value=0) as mock_update:
            result = mgr.block_ip("10.0.0.1")

        assert result is True
        mock_update.assert_called_once()
        # Kiểm tra argument thứ 3 (flags) là BPF_ANY
        _, _, flags_arg = mock_update.call_args[0]
        assert flags_arg == BPF_ANY

    def test_block_ip_passes_correct_key(self):
        """
        block_ip("1.2.3.4") phải truyền key có value = 0x01020304.
        Đây là kiểm tra tích hợp giữa _ip_to_c_key và _bpf_map_update.
        """
        mgr = self._make_manager_with_mock_fd()
        captured_key = []

        def capture_update(key, value, flags):
            captured_key.append(key.value)
            return 0

        with patch.object(LibbpfMapManager, '_bpf_map_update', side_effect=capture_update):
            mgr.block_ip("1.2.3.4")

        assert len(captured_key) == 1
        assert captured_key[0] == 0x01020304

    def test_unblock_ip_calls_delete(self):
        """unblock_ip() phải gọi _bpf_map_delete(), không gọi _bpf_map_update()."""
        mgr = self._make_manager_with_mock_fd()

        with patch.object(LibbpfMapManager, '_bpf_map_delete', return_value=0) as mock_del:
            with patch.object(LibbpfMapManager, '_bpf_map_update') as mock_upd:
                result = mgr.unblock_ip("10.0.0.1")

        assert result is True
        mock_del.assert_called_once()
        mock_upd.assert_not_called()

    def test_unblock_enoent_returns_true(self):
        """
        Nếu delete trả về -1 với errno=ENOENT (key không tồn tại),
        unblock_ip() vẫn phải trả về True (idempotent).
        """
        mgr = self._make_manager_with_mock_fd()

        with patch.object(LibbpfMapManager, '_bpf_map_delete', return_value=-1):
            with patch('ctypes.get_errno', return_value=2):  # 2 = ENOENT
                result = mgr.unblock_ip("10.0.0.1")

        assert result is True  # idempotent

    def test_block_failure_returns_false(self):
        """Nếu syscall trả về lỗi (không phải ENOENT), block_ip() trả về False."""
        mgr = self._make_manager_with_mock_fd()

        with patch.object(LibbpfMapManager, '_bpf_map_update', return_value=-1):
            with patch('ctypes.get_errno', return_value=1):  # 1 = EPERM
                result = mgr.block_ip("10.0.0.1")

        assert result is False

    def test_assert_open_raises_when_not_opened(self):
        """Gọi block_ip() trước open() phải raise RuntimeError."""
        mgr = LibbpfMapManager.__new__(LibbpfMapManager)
        mgr._fd = None

        with pytest.raises(RuntimeError, match="chưa được open"):
            mgr.block_ip("10.0.0.1")


# ══════════════════════════════════════════════════════════════════════════════
# TEST 5: AsyncMapManager — kiểm tra việc wrap async đúng cách
# ══════════════════════════════════════════════════════════════════════════════

class TestAsyncMapManager:
    """
    Kiểm tra AsyncMapManager gọi đúng method của EbpfMapManager,
    và không block event loop khi thực hiện thao tác đồng bộ.
    """

    @pytest.mark.asyncio
    async def test_async_block_delegates_to_sync(self):
        """async block_ip() phải gọi synchronous block_ip() bên dưới."""
        mock_mgr = MockEbpfMapManager()
        mock_mgr.open()

        async_mgr = AsyncMapManager(mock_mgr)
        async_mgr._loop = asyncio.get_running_loop()

        result = await async_mgr.block_ip("10.0.0.99")
        assert result is True
        assert mock_mgr.is_blocked("10.0.0.99")

    @pytest.mark.asyncio
    async def test_async_context_manager(self):
        """Kiểm tra __aenter__/__aexit__ gọi open() và close() đúng lúc."""
        mock_mgr = MockEbpfMapManager()

        assert not mock_mgr._is_open

        async with AsyncMapManager(mock_mgr) as amgr:
            assert mock_mgr._is_open  # open() đã được gọi
            await amgr.block_ip("1.2.3.4")

        assert not mock_mgr._is_open  # close() đã được gọi

    @pytest.mark.asyncio
    async def test_concurrent_block_operations(self):
        """
        Nhiều coroutine block_ip() đồng thời không được gây race condition.
        MockEbpfMapManager dùng dict Python nên GIL bảo vệ, nhưng
        test này kiểm tra rằng AsyncMapManager không serialize sai.
        """
        mock_mgr = MockEbpfMapManager()
        async_mgr = AsyncMapManager(mock_mgr)
        async_mgr._loop = asyncio.get_running_loop()
        mock_mgr.open()

        ips = [f"10.0.{i}.{j}" for i in range(5) for j in range(5)]
        await asyncio.gather(*[async_mgr.block_ip(ip) for ip in ips])

        blocked = set(mock_mgr.get_all_blocked_ips())
        assert blocked == set(ips), "Tất cả 25 IP phải được block đồng thời"


# ── Chạy trực tiếp ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import subprocess
    result = subprocess.run(
        ["python", "-m", "pytest", __file__, "-v", "--tb=short"],
        cwd=os.path.dirname(os.path.dirname(__file__))
    )
    sys.exit(result.returncode)