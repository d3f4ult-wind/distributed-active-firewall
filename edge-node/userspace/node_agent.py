# node_agent.py — Agent chính chạy liên tục trên mỗi Edge Node
#
# Chức năng: Subscribe vào kênh Redis Pub/Sub, lắng nghe thông báo IP xấu mới.
# Khi nhận được IP từ Honeypot qua Redis, gọi map_manager.py để cập nhật blacklist
# vào eBPF Map ngay lập tức — đây là bước 'Đồng bộ' trong chu trình Phát hiện->Chặn.
# Đọc cấu hình kết nối Redis từ file .env (không hardcode IP vào đây).
"""
node_agent.py — Agent chạy trên mỗi Edge Firewall Node.

Nhiệm vụ:
  1. [Cold Start]   Khi khởi động, đọc persistent blacklist từ Redis Set
                    rồi nạp toàn bộ vào eBPF LRU Hash Map (tránh khoảng
                    trống bảo mật khi node bị restart).
  2. [Subscribe]    Subscribe Redis Pub/Sub channel "firewall:blacklist:add"
                    để nhận lệnh chặn IP mới theo thời gian thực.
  3. [Apply]        Với mỗi IP nhận được, gọi EbpfMapInterface để ghi vào
                    eBPF Map — XDP kernel module sẽ tự động drop gói tin
                    từ IP đó ở tốc độ line-rate.
  4. [Reconnect]    Tự động kết nối lại Redis khi mất kết nối, không cần
                    admin can thiệp.

Thiết kế quan trọng — Abstract Layer:
  node_agent.py KHÔNG gọi trực tiếp syscall libbpf. Thay vào đó, nó
  gọi qua EbpfMapInterface (định nghĩa bên dưới). Hiện tại, interface
  này có 2 implementation:

    ┌─────────────────────────────────────────────────────────────────┐
    │  EbpfMapInterface  (abstract)                                   │
    │         │                                                       │
    │    ┌────┴────────────────────────┐                              │
    │    │                             │                              │
    │  MockEbpfMap               RealEbpfMap  ← implement SAU khi     │
    │  (dùng ngay bây giờ,         (Tháng 1)   xdp_filter.c xong      │
    │   chỉ log ra stdout)                                            │
    └─────────────────────────────────────────────────────────────────┘

  Khi XDP kernel module sẵn sàng (Tuần 3), chỉ cần viết RealEbpfMap
  và truyền vào constructor của NodeAgent — không cần sửa một dòng
  nào trong NodeAgent hay logic subscribe.

Luồng dữ liệu đầy đủ:
  [Honeypot]
      └─► Redis PUBLISH "firewall:blacklist:add"
              └─► [node_agent.py] nhận message
                      └─► parse JSON, lấy field "ip"
                              └─► EbpfMapInterface.block_ip(ip)
                                      └─► [RealEbpfMap] ghi vào eBPF LRU Hash Map
                                                └─► [XDP kernel hook] DROP packet
"""

import asyncio
import json
import logging
import os
import signal
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import redis.asyncio as aioredis

# Import channel constants từ reporter.py để dùng chung — tránh hardcode string
# (khi node_agent chạy trên máy khác, chỉ cần copy file reporter.py sang
#  hoặc tách constants ra một file riêng shared/constants.py sau này)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "honeypot"))
try:
    from reporter import (
        CHANNEL_BLACKLIST_ADD,
        CHANNEL_BLACKLIST_REMOVE,
        CHANNEL_EVENTS,
        PERSISTENT_BLACKLIST_KEY,
        MESSAGE_VERSION,
    )
except ImportError:
    # Fallback nếu chạy độc lập (không có honeypot/ trong path)
    CHANNEL_BLACKLIST_ADD = "firewall:blacklist:add"
    CHANNEL_BLACKLIST_REMOVE = "firewall:blacklist:remove"
    CHANNEL_EVENTS = "firewall:events"
    PERSISTENT_BLACKLIST_KEY = "firewall:persistent:blacklist"
    MESSAGE_VERSION = "1.0"

# ── Cấu hình Logging ──────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("node_agent.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("edge_node.agent")


# ══════════════════════════════════════════════════════════════════════════════
# PHẦN 1: Abstract Interface cho eBPF Map
# Đây là "hợp đồng" giữa node_agent và tầng eBPF bên dưới.
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class BlockResult:
    """
    Kết quả của một thao tác block/unblock IP.
    Dùng dataclass thay vì tuple để code dễ đọc hơn.
    """
    success: bool
    ip: str
    action: str          # "block" hoặc "unblock"
    message: str = ""    # Mô tả lỗi nếu success=False


class EbpfMapInterface(ABC):
    """
    Abstract base class định nghĩa interface với eBPF LRU Hash Map.

    Tại sao cần abstract class ở đây?
      - Hiện tại (Tháng 1-2), XDP kernel module chưa tồn tại.
        Ta dùng MockEbpfMap để hệ thống chạy được end-to-end.
      - Khi XDP xong (Tháng 1 Tuần 3), ta viết RealEbpfMap implement
        interface này, truyền vào NodeAgent, mọi thứ hoạt động ngay —
        không cần refactor bất kỳ logic nào.
      - Đây là pattern Dependency Injection + Strategy Pattern.
    """

    @abstractmethod
    async def block_ip(self, ip: str) -> BlockResult:
        """
        Thêm IP vào eBPF LRU Hash Map.
        XDP sẽ tự động DROP mọi packet từ IP này.
        """
        ...

    @abstractmethod
    async def unblock_ip(self, ip: str) -> BlockResult:
        """
        Xóa IP khỏi eBPF LRU Hash Map.
        XDP sẽ cho phép packet từ IP này đi qua.
        """
        ...

    @abstractmethod
    async def get_blocked_ips(self) -> list[str]:
        """Trả về danh sách tất cả IP đang bị chặn trong Map."""
        ...

    @abstractmethod
    async def is_blocked(self, ip: str) -> bool:
        """Kiểm tra một IP có đang bị chặn không."""
        ...


class MockEbpfMap(EbpfMapInterface):
    """
    Implementation giả — chỉ lưu IP trong memory Python.

    Dùng trong giai đoạn Tháng 2 khi XDP chưa sẵn sàng.
    Hoàn toàn functional cho mục đích test end-to-end flow:
    Honeypot → Redis → node_agent → (mock) eBPF Map.

    Lợi ích: cho phép đo latency end-to-end thật sự (Redis round-trip,
    JSON parsing...) ngay cả khi chưa có kernel module.
    """

    def __init__(self):
        # Dùng set thay vì list vì thao tác check (is_blocked) là O(1)
        self._blocked: set[str] = set()

    async def block_ip(self, ip: str) -> BlockResult:
        self._blocked.add(ip)
        logger.info(f"[MockeBPF] ✓ Đã BLOCK IP: {ip} (hiện có {len(self._blocked)} IP bị chặn)")
        return BlockResult(success=True, ip=ip, action="block")

    async def unblock_ip(self, ip: str) -> BlockResult:
        existed = ip in self._blocked
        self._blocked.discard(ip)
        msg = "OK" if existed else "IP không tồn tại trong Map"
        logger.info(f"[MockeBPF] ✓ Đã UNBLOCK IP: {ip} ({msg})")
        return BlockResult(success=True, ip=ip, action="unblock", message=msg)

    async def get_blocked_ips(self) -> list[str]:
        return list(self._blocked)

    async def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked


class RealEbpfMap(EbpfMapInterface):
    """
    Implementation thật — giao tiếp với eBPF LRU Hash Map qua libbpf.

    *** CHƯA IMPLEMENT — SẼ VIẾT Ở TUẦN 3 KHI XDP MODULE SẴN SÀNG ***

    Kế hoạch implement:
      - Dùng thư viện `bpf` (Python binding của libbpf) hoặc ctypes
        để gọi bpf_map_update_elem() / bpf_map_delete_elem().
      - map_fd được lấy bằng cách mở pinned map tại /sys/fs/bpf/xdp_blacklist
        (xdp_filter.c sẽ pin map này khi load).
      - Định dạng key trong Map: IPv4 address dưới dạng __u32 (big-endian).
        Ví dụ: "192.168.1.100" → socket.inet_aton() → struct.unpack("!I", ...)

    Ghi chú về eBPF LRU Hash Map:
      - BPF_MAP_TYPE_LRU_HASH tự động đẩy entry cũ nhất khi đầy.
      - Max entries được set trong xdp_filter.c (dự kiến 65536).
      - Không cần lo về việc Map bị đầy — kernel tự quản lý.
    """

    def __init__(self, map_pin_path: str = "/sys/fs/bpf/xdp_blacklist"):
        self.map_pin_path = map_pin_path
        # TODO (Tuần 3): Mở map fd từ pinned path
        # self._map_fd = bpf_obj_get(map_pin_path)
        raise NotImplementedError(
            "RealEbpfMap chưa implement. Dùng MockEbpfMap cho đến khi "
            "xdp_filter.c sẵn sàng và map được pin tại /sys/fs/bpf/."
        )

    async def block_ip(self, ip: str) -> BlockResult:
        # TODO (Tuần 3):
        # import socket, struct
        # ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
        # key = ctypes.c_uint32(ip_int)
        # value = ctypes.c_uint8(1)   # value không quan trọng, chỉ cần key tồn tại
        # ret = libbpf.bpf_map_update_elem(self._map_fd, key, value, BPF_ANY)
        # return BlockResult(success=(ret == 0), ip=ip, action="block")
        raise NotImplementedError

    async def unblock_ip(self, ip: str) -> BlockResult:
        # TODO (Tuần 3):
        # ret = libbpf.bpf_map_delete_elem(self._map_fd, key)
        raise NotImplementedError

    async def get_blocked_ips(self) -> list[str]:
        raise NotImplementedError

    async def is_blocked(self, ip: str) -> bool:
        raise NotImplementedError


# ══════════════════════════════════════════════════════════════════════════════
# PHẦN 2: NodeAgent — logic chính của agent
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class AgentStats:
    """Thống kê hoạt động của agent — hữu ích để đo latency sau này."""
    messages_received: int = 0
    ips_blocked: int = 0
    ips_unblocked: int = 0
    errors: int = 0
    cold_start_ips_loaded: int = 0
    reconnects: int = 0
    last_message_at: Optional[str] = None


class NodeAgent:
    """
    Agent chạy trên mỗi Edge Firewall Node.

    Nhận message từ Redis Pub/Sub và cập nhật eBPF Map tương ứng.

    Constructor nhận ebpf_map: EbpfMapInterface — đây là Dependency Injection.
    Khi test: truyền MockEbpfMap().
    Khi production: truyền RealEbpfMap(map_pin_path="/sys/fs/bpf/xdp_blacklist").
    """

    def __init__(
        self,
        redis_host: str = "127.0.0.1",
        redis_port: int = 6379,
        redis_password: Optional[str] = None,
        ebpf_map: Optional[EbpfMapInterface] = None,
        # Thời gian chờ (giây) trước khi thử reconnect Redis
        reconnect_delay: float = 3.0,
        # Thời gian chờ tối đa khi reconnect (exponential backoff cap)
        reconnect_max_delay: float = 60.0,
        node_id: Optional[str] = None,
    ):
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.redis_password = redis_password
        # Nếu không truyền ebpf_map, dùng Mock (an toàn cho dev/test)
        self.ebpf_map: EbpfMapInterface = ebpf_map or MockEbpfMap()
        self.reconnect_delay = reconnect_delay
        self.reconnect_max_delay = reconnect_max_delay
        # node_id dùng để phân biệt log khi có nhiều node
        self.node_id = node_id or os.getenv("NODE_ID", "node-unknown")

        self.stats = AgentStats()
        self._running = False
        self._redis: Optional[aioredis.Redis] = None

    # ── Vòng đời chính ────────────────────────────────────────────────────────

    async def run(self) -> None:
        """
        Điểm vào chính của agent.

        Vòng lặp bên ngoài xử lý reconnect: nếu Redis mất kết nối,
        agent sẽ đợi một lúc rồi thử lại thay vì crash hoàn toàn.
        Đây là thiết kế quan trọng cho hệ thống chạy 24/7.
        """
        self._running = True
        delay = self.reconnect_delay  # delay hiện tại (sẽ tăng theo exponential backoff)

        logger.info("═" * 60)
        logger.info(f"  Edge Node Agent [{self.node_id}] đang khởi động...")
        logger.info(f"  eBPF backend: {type(self.ebpf_map).__name__}")
        logger.info("═" * 60)

        while self._running:
            try:
                await self._connect_redis()

                # ── Cold Start: Nạp blacklist cũ vào eBPF Map ──
                await self._cold_start_sync()

                # ── Reset delay khi kết nối thành công ──
                delay = self.reconnect_delay
                if self.stats.reconnects > 0:
                    logger.info(f"✓ Đã kết nối lại Redis thành công (lần #{self.stats.reconnects}).")

                # ── Subscribe và xử lý message ──
                await self._subscribe_and_process()

            except (
                aioredis.ConnectionError,
                aioredis.TimeoutError,
                ConnectionRefusedError,
                OSError,
            ) as exc:
                if not self._running:
                    break
                self.stats.reconnects += 1
                logger.warning(
                    f"⚠ Mất kết nối Redis: {exc}. "
                    f"Thử lại sau {delay:.0f}s (lần #{self.stats.reconnects})..."
                )
                await asyncio.sleep(delay)
                # Exponential backoff: tăng delay nhưng không vượt quá cap
                delay = min(delay * 2, self.reconnect_max_delay)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.exception(f"Lỗi không xác định: {exc}")
                self.stats.errors += 1
                await asyncio.sleep(delay)

        await self._cleanup()

    async def stop(self) -> None:
        """Dừng agent gracefully."""
        self._running = False

    # ── Kết nối Redis ─────────────────────────────────────────────────────────

    async def _connect_redis(self) -> None:
        """Tạo Redis client mới. Gọi lại mỗi lần reconnect."""
        if self._redis:
            try:
                await self._redis.aclose()
            except Exception:
                pass

        self._redis = aioredis.Redis(
            host=self.redis_host,
            port=self.redis_port,
            password=self.redis_password,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_timeout=30,  # Dài hơn Honeypot vì subscribe cần giữ kết nối lâu
        )
        await self._redis.ping()
        logger.info(f"✓ Kết nối Redis tại {self.redis_host}:{self.redis_port}")

    # ── Cold Start Sync ───────────────────────────────────────────────────────

    async def _cold_start_sync(self) -> None:
        """
        Đồng bộ trạng thái khi khởi động lạnh.

        Vấn đề cần giải quyết:
          Pub/Sub là "fire and forget" — nếu node bị restart trong lúc
          Honeypot đã publish 50 IP, node sẽ không bao giờ nhận được
          50 message đó. Kết quả: eBPF Map của node bị thiếu 50 IP.

        Giải pháp:
          reporter.py đồng thời lưu mỗi IP vào Redis Set bền vững.
          Khi node khởi động, đọc Set đó và nạp vào eBPF Map TRƯỚC KHI
          subscribe — đảm bảo trạng thái luôn đồng bộ.

        Thứ tự quan trọng:
          Load từ Set → Subscribe Pub/Sub (không được đảo ngược,
          nếu không sẽ có race condition trong khoảng thời gian nhỏ)
        """
        logger.info("Đang thực hiện cold start sync từ Redis persistent blacklist...")

        persistent_ips = await self._redis.smembers(PERSISTENT_BLACKLIST_KEY)

        if not persistent_ips:
            logger.info("Persistent blacklist trống — đây là lần khởi động đầu tiên.")
            return

        loaded_count = 0
        for ip in persistent_ips:
            result = await self.ebpf_map.block_ip(ip)
            if result.success:
                loaded_count += 1
            else:
                logger.error(f"Cold start: không thể block IP {ip}: {result.message}")
                self.stats.errors += 1

        self.stats.cold_start_ips_loaded = loaded_count
        logger.info(
            f"✓ Cold start hoàn tất: đã nạp {loaded_count}/{len(persistent_ips)} "
            f"IP vào eBPF Map."
        )

    # ── Subscribe và xử lý ────────────────────────────────────────────────────

    async def _subscribe_and_process(self) -> None:
        """
        Subscribe Redis Pub/Sub và xử lý message trong vòng lặp vô hạn.

        Lý do dùng Pub/Sub thay vì polling (BRPOP trên List):
          - Push model: message đến ngay lập tức, không có delay poll.
          - Nhiều subscriber nhận cùng một message đồng thời —
            phù hợp với mô hình "1 Honeypot, nhiều Edge Node".
          - Latency thấp hơn polling, phù hợp với mục tiêu "gần như
            tức thời" của đề tài.
        """
        pubsub = self._redis.pubsub()

        # Subscribe cả 2 channel: add và remove
        await pubsub.subscribe(CHANNEL_BLACKLIST_ADD, CHANNEL_BLACKLIST_REMOVE)
        logger.info(
            f"✓ Đang lắng nghe Redis channels:\n"
            f"    - {CHANNEL_BLACKLIST_ADD}\n"
            f"    - {CHANNEL_BLACKLIST_REMOVE}"
        )

        try:
            async for raw_message in pubsub.listen():
                if not self._running:
                    break

                # pubsub.listen() trả về cả message kiểu "subscribe" (confirmation)
                # và "message" (dữ liệu thật). Ta chỉ xử lý loại sau.
                if raw_message["type"] != "message":
                    continue

                await self._handle_message(raw_message)

        finally:
            await pubsub.unsubscribe()
            await pubsub.aclose()

    async def _handle_message(self, raw_message: dict) -> None:
        """
        Xử lý một message nhận được từ Redis Pub/Sub.

        Đây là hàm "hot path" — được gọi với mỗi IP được phát hiện.
        Ta cần nó nhanh và không raise exception (để không break vòng lặp).
        """
        channel = raw_message.get("channel", "")
        data_str = raw_message.get("data", "")

        # ── Parse JSON ──
        try:
            message = json.loads(data_str)
        except json.JSONDecodeError as exc:
            logger.error(f"Message không phải JSON hợp lệ: {exc} | Raw: {data_str!r}")
            self.stats.errors += 1
            return

        # ── Kiểm tra version để tương thích ngược ──
        msg_version = message.get("version", "unknown")
        if msg_version != MESSAGE_VERSION:
            logger.warning(
                f"Message version không khớp: nhận {msg_version}, "
                f"mong đợi {MESSAGE_VERSION}. Vẫn xử lý tiếp..."
            )

        attacker_ip = message.get("ip")
        if not attacker_ip:
            logger.error(f"Message không có field 'ip': {message}")
            self.stats.errors += 1
            return

        # ── Ghi log nhận message ──
        self.stats.messages_received += 1
        self.stats.last_message_at = datetime.now(timezone.utc).isoformat()
        recv_ts = self.stats.last_message_at

        logger.info(
            f"📨 [{self.node_id}] Nhận message từ channel '{channel}' | "
            f"IP={attacker_ip} | Source={message.get('source_service', '?')} | "
            f"Hit={message.get('hit_count', '?')} | Recv={recv_ts}"
        )

        # ── Thực thi lệnh tương ứng ──
        if channel == CHANNEL_BLACKLIST_ADD:
            await self._do_block(attacker_ip, message)
        elif channel == CHANNEL_BLACKLIST_REMOVE:
            await self._do_unblock(attacker_ip, message)
        else:
            logger.warning(f"Message từ channel không xác định: {channel}")

    async def _do_block(self, ip: str, message: dict) -> None:
        """Gọi eBPF interface để block IP, log kết quả."""
        # Kiểm tra xem IP có đang bị block chưa để tránh log lặp
        already_blocked = await self.ebpf_map.is_blocked(ip)
        if already_blocked:
            logger.debug(f"IP {ip} đã có trong Map, bỏ qua.")
            return

        result = await self.ebpf_map.block_ip(ip)

        if result.success:
            self.stats.ips_blocked += 1
            logger.warning(
                f"🔒 [{self.node_id}] ĐÃ CHẶN IP: {ip} | "
                f"Tổng đang chặn: {self.stats.ips_blocked}"
            )
        else:
            self.stats.errors += 1
            logger.error(f"❌ [{self.node_id}] Không thể chặn IP {ip}: {result.message}")

    async def _do_unblock(self, ip: str, message: dict) -> None:
        """Gọi eBPF interface để unblock IP, log kết quả."""
        result = await self.ebpf_map.unblock_ip(ip)

        if result.success:
            self.stats.ips_unblocked += 1
            logger.info(
                f"🔓 [{self.node_id}] ĐÃ GỠ CHẶN IP: {ip} | "
                f"Lý do: {message.get('reason', 'không rõ')}"
            )
        else:
            self.stats.errors += 1
            logger.error(f"❌ [{self.node_id}] Không thể gỡ chặn IP {ip}: {result.message}")

    # ── Cleanup ───────────────────────────────────────────────────────────────

    async def _cleanup(self) -> None:
        logger.info(f"Agent [{self.node_id}] đang dọn dẹp...")
        if self._redis:
            try:
                await self._redis.aclose()
            except Exception:
                pass
        logger.info(
            f"Agent [{self.node_id}] đã dừng. Thống kê cuối:\n"
            f"  Messages nhận: {self.stats.messages_received}\n"
            f"  IPs đã chặn:   {self.stats.ips_blocked}\n"
            f"  IPs gỡ chặn:   {self.stats.ips_unblocked}\n"
            f"  Lỗi:           {self.stats.errors}\n"
            f"  Reconnects:    {self.stats.reconnects}\n"
            f"  Cold start IPs:{self.stats.cold_start_ips_loaded}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# PHẦN 3: Entrypoint
# ══════════════════════════════════════════════════════════════════════════════

async def main() -> None:
    """
    Điểm vào khi chạy node_agent.py trực tiếp.

    Đọc cấu hình từ environment variables — cách này phù hợp với
    triển khai trên nhiều VM vì mỗi VM có .env riêng.

    Biến môi trường:
      REDIS_HOST          Redis server IP (default: 127.0.0.1)
      REDIS_PORT          Redis server port (default: 6379)
      REDIS_PASSWORD      Redis password nếu có
      NODE_ID             Tên node này (vd: "edge-node-1"), dùng để log
      USE_REAL_EBPF       "true" để dùng RealEbpfMap (cần XDP module)
      EBPF_MAP_PIN_PATH   Path pinned map (default: /sys/fs/bpf/xdp_blacklist)
    """
    use_real_ebpf = os.getenv("USE_REAL_EBPF", "false").lower() == "true"

    if use_real_ebpf:
        map_path = os.getenv("EBPF_MAP_PIN_PATH", "/sys/fs/bpf/xdp_blacklist")
        ebpf_map = RealEbpfMap(map_pin_path=map_path)
        logger.info(f"Chế độ: Real eBPF Map tại '{map_path}'")
    else:
        ebpf_map = MockEbpfMap()
        logger.info("Chế độ: Mock eBPF Map (dùng cho dev/test)")

    agent = NodeAgent(
        redis_host=os.getenv("REDIS_HOST", "127.0.0.1"),
        redis_port=int(os.getenv("REDIS_PORT", "6379")),
        redis_password=os.getenv("REDIS_PASSWORD") or None,
        ebpf_map=ebpf_map,
        node_id=os.getenv("NODE_ID", "edge-node-1"),
    )

    loop = asyncio.get_running_loop()

    async def shutdown(sig_name: str) -> None:
        logger.info(f"Nhận tín hiệu {sig_name}...")
        await agent.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(
            sig, lambda s=sig: asyncio.create_task(shutdown(s.name))
        )

    await agent.run()


if __name__ == "__main__":
    asyncio.run(main())