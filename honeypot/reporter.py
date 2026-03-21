# reporter.py — Báo cáo IP xấu lên kênh đồng bộ trung tâm Redis Pub/Sub channel.
# Chức năng: Publish IP kẻ tấn công lên Redis channel theo định dạng channel_schema.md.
# Đây là bước 'Phát tín hiệu' trong chu trình Phát hiện -> Đồng bộ -> Chặn.
# Tất cả Edge Node đang subscribe sẽ nhận được thông tin này gần như tức thời.
"""
Đây là "cầu nối" duy nhất giữa Honeypot và các Edge Firewall Node.
Honeypot không biết gì về eBPF Map — nó chỉ biết gửi message đúng schema
lên Redis. Phần còn lại là việc của node_agent.py bên edge-node.

Channel naming convention (khớp với docs/channel_schema.md):
  firewall:blacklist:add     — yêu cầu tất cả node chặn một IP
  firewall:blacklist:remove  — (dự phòng tương lai) gỡ chặn một IP
  firewall:events            — log sự kiện honeypot để monitoring

Message format (JSON):
  {
    "version": "1.0",
    "action": "block",
    "ip": "1.2.3.4",
    "source": "honeypot",
    "source_service": "SSH",
    "source_port": 2222,
    "hit_count": 3,
    "timestamp": "2025-01-15T10:30:00+00:00",
    "extra": { ...tuỳ ý... }
  }

Tại sao dùng Pub/Sub thay vì List/Set của Redis?
  - Pub/Sub là push model: node nhận message ngay lập tức, không cần poll.
  - Phù hợp với yêu cầu "gần như tức thời" của đề tài.
  - Dễ scale: thêm edge-node mới chỉ cần subscribe vào cùng channel.
  - Nhược điểm: nếu node offline thì mất message → giải pháp: khi node
    khởi động lại, nó đọc danh sách từ Redis Set (persistent blacklist)
    trước, rồi mới subscribe — xem node_agent.py để biết chi tiết.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

import redis.asyncio as aioredis

logger = logging.getLogger("honeypot.reporter")

# Tên các channel — định nghĩa ở đây để node_agent.py import cùng constant
CHANNEL_BLACKLIST_ADD = "firewall:blacklist:add"
CHANNEL_BLACKLIST_REMOVE = "firewall:blacklist:remove"
CHANNEL_EVENTS = "firewall:events"

# Redis Set key lưu blacklist bền vững (persistent) — dùng khi node khởi động lại
PERSISTENT_BLACKLIST_KEY = "firewall:persistent:blacklist"

MESSAGE_VERSION = "1.0"


class BlacklistReporter:
    """
    Chịu trách nhiệm kết nối Redis và publish message theo đúng schema.

    Thiết kế dùng redis.asyncio (thư viện async chính thức của redis-py)
    để không block event loop của honeypot.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 6379,
        password: Optional[str] = None,
        db: int = 0,
    ):
        self.host = host
        self.port = port
        self.password = password
        self.db = db
        self._client: Optional[aioredis.Redis] = None

    # ── Vòng đời kết nối ──────────────────────────────────────────────────────

    async def connect(self) -> None:
        """Tạo connection pool đến Redis. Gọi 1 lần khi khởi động."""
        self._client = aioredis.Redis(
            host=self.host,
            port=self.port,
            password=self.password,
            db=self.db,
            decode_responses=True,  # tự decode bytes → str
            socket_connect_timeout=5,
            socket_timeout=5,
            retry_on_timeout=True,
        )
        # Kiểm tra kết nối thật sự
        await self._client.ping()

    async def disconnect(self) -> None:
        """Đóng kết nối Redis gracefully."""
        if self._client:
            await self._client.aclose()
            self._client = None

    # ── Publish methods ───────────────────────────────────────────────────────

    async def report_attacker(
        self,
        attacker_ip: str,
        source_service: str,
        source_port: int,
        hit_count: int = 1,
        timestamp: Optional[str] = None,
        extra: Optional[dict] = None,
    ) -> None:
        """
        Publish lệnh chặn IP lên Redis.

        Thực hiện 2 việc song song:
          1. PUBLISH lên channel Pub/Sub → các node đang online nhận ngay.
          2. SADD vào Redis Set bền vững → các node khởi động lại sau này
             có thể đọc để sync trạng thái.

        Args:
            attacker_ip:    IP cần chặn.
            source_service: Dịch vụ honeypot phát hiện (SSH / Telnet / HTTP).
            source_port:    Port dịch vụ đó.
            hit_count:      Số lần IP này chạm vào honeypot.
            timestamp:      ISO 8601 UTC, tự tạo nếu không truyền.
            extra:          Thông tin bổ sung tuỳ ý (username thử, v.v.).
        """
        if not self._client:
            raise RuntimeError("BlacklistReporter chưa được connect(). Gọi connect() trước.")

        ts = timestamp or datetime.now(timezone.utc).isoformat()

        message = {
            "version": MESSAGE_VERSION,
            "action": "block",
            "ip": attacker_ip,
            "source": "honeypot",
            "source_service": source_service,
            "source_port": source_port,
            "hit_count": hit_count,
            "timestamp": ts,
            "extra": extra or {},
        }
        message_json = json.dumps(message, ensure_ascii=False)

        # 1. Publish Pub/Sub → tức thời đến các node đang online
        subscribers = await self._client.publish(CHANNEL_BLACKLIST_ADD, message_json)
        logger.debug(
            f"Published '{attacker_ip}' lên {CHANNEL_BLACKLIST_ADD} "
            f"({subscribers} subscriber(s) nhận được)"
        )

        # 2. Lưu vào persistent Set → dành cho node khởi động lại sau này
        # Chỉ lưu IP string (không lưu toàn bộ JSON) để tiết kiệm bộ nhớ.
        # node_agent.py sẽ chỉ cần IP để cập nhật eBPF Map.
        await self._client.sadd(PERSISTENT_BLACKLIST_KEY, attacker_ip)
        logger.debug(f"Đã thêm '{attacker_ip}' vào {PERSISTENT_BLACKLIST_KEY}")

        # 3. Publish sự kiện log lên channel events (dành cho monitoring dashboard)
        event = {
            "version": MESSAGE_VERSION,
            "event_type": "intrusion_detected",
            "ip": attacker_ip,
            "service": source_service,
            "port": source_port,
            "timestamp": ts,
        }
        await self._client.publish(CHANNEL_EVENTS, json.dumps(event, ensure_ascii=False))

    async def remove_from_blacklist(
        self, ip: str, reason: str = "manual"
    ) -> None:
        """
        Gỡ một IP khỏi blacklist (dùng khi quản trị viên whitelist nhầm).

        Publish lên CHANNEL_BLACKLIST_REMOVE → node_agent xóa IP khỏi eBPF Map.
        """
        if not self._client:
            raise RuntimeError("Chưa connect()")

        message = {
            "version": MESSAGE_VERSION,
            "action": "unblock",
            "ip": ip,
            "source": "admin",
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await self._client.publish(
            CHANNEL_BLACKLIST_REMOVE, json.dumps(message, ensure_ascii=False)
        )
        await self._client.srem(PERSISTENT_BLACKLIST_KEY, ip)
        logger.info(f"Đã gỡ '{ip}' khỏi blacklist. Lý do: {reason}")

    async def get_persistent_blacklist(self) -> set[str]:
        """
        Đọc toàn bộ blacklist bền vững từ Redis.

        Dùng bởi node_agent.py khi khởi động lại để đồng bộ trạng thái.
        """
        if not self._client:
            raise RuntimeError("Chưa connect()")
        return await self._client.smembers(PERSISTENT_BLACKLIST_KEY)