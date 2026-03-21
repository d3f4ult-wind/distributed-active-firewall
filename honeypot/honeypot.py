# honeypot.py — Điều phối chính của hệ thống Honeypot
# Chức năng: Khởi động tất cả các dịch vụ giả mạo (SSH, Telnet) và lắng nghe.
# Bất kỳ kết nối nào đến các Unused IP đều bị coi là hành vi đáng ngờ.
# Khi phát hiện kẻ tấn công, gọi reporter.py để phát tín hiệu lên Redis.
# Đây là bước 'Phát hiện' trong chu trình Phát hiện -> Đồng bộ -> Chặn.
"""
Vai trò:
  - Khởi động các dịch vụ giả mạo (fake_services.py)
  - Nhận sự kiện "phát hiện kẻ xâm nhập" từ các dịch vụ đó
  - Ghi log chi tiết
  - Chuyển thông tin IP kẻ tấn công sang reporter.py để publish lên Redis

Interface với XDP/eBPF:
  - Honeypot KHÔNG trực tiếp chạm vào eBPF Map.
  - Honeypot chỉ publish lên Redis channel "firewall:blacklist:add".
  - Node agent ở edge-node/userspace/node_agent.py sẽ subscribe và cập nhật Map.
  - Định dạng message: xem docs/channel_schema.md
"""

import asyncio
import logging
import signal
import sys
from datetime import datetime, timezone
from typing import Optional

from fake_services import FakeSSHService, FakeTelnetService, FakeHTTPService
from reporter import BlacklistReporter

# ── Cấu hình Logging ──────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("honeypot.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger("honeypot.main")


class HoneypotOrchestrator:
    """
    Điều phối toàn bộ vòng đời của hệ thống Honeypot.

    Sơ đồ phụ thuộc:
        HoneypotOrchestrator
            ├── FakeSSHService     ──┐
            ├── FakeTelnetService  ──┼──► on_intrusion_detected() ──► BlacklistReporter
            └── FakeHTTPService    ──┘                                        │
                                                                              ▼
                                                                    Redis Pub/Sub channel
                                                                    "firewall:blacklist:add"
                                                                              │
                                                                    (edge-node/node_agent.py
                                                                     subscribe & cập nhật
                                                                     eBPF LRU Hash Map)
    """

    def __init__(
        self,
        redis_host: str = "127.0.0.1",
        redis_port: int = 6379,
        redis_password: Optional[str] = None,
        # Danh sách (host, port) cho từng dịch vụ giả
        ssh_bind: tuple[str, int] = ("0.0.0.0", 2222),
        telnet_bind: tuple[str, int] = ("0.0.0.0", 2323),
        http_bind: tuple[str, int] = ("0.0.0.0", 8080),
        # Ngưỡng: bao nhiêu lần hit thì mới report (tránh false-positive lẻ tẻ)
        hit_threshold: int = 1,
    ):
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.redis_password = redis_password
        self.ssh_bind = ssh_bind
        self.telnet_bind = telnet_bind
        self.http_bind = http_bind
        self.hit_threshold = hit_threshold

        # Đếm số lần một IP chạm vào honeypot (để áp threshold)
        # key: ip_str, value: hit_count
        self._hit_counter: dict[str, int] = {}

        # Set các IP đã được report rồi (tránh báo trùng lặp)
        self._reported_ips: set[str] = set()

        self.reporter: Optional[BlacklistReporter] = None
        self._services: list = []
        self._running = False

    # ── Public API ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Khởi động honeypot: kết nối Redis rồi bật tất cả dịch vụ giả."""
        logger.info("═" * 60)
        logger.info("  Honeypot System đang khởi động...")
        logger.info("═" * 60)

        # 1. Kết nối Redis trước — nếu lỗi thì dừng hẳn, không mở dịch vụ giả
        self.reporter = BlacklistReporter(
            host=self.redis_host,
            port=self.redis_port,
            password=self.redis_password,
        )
        await self.reporter.connect()
        logger.info(f"✓ Đã kết nối Redis tại {self.redis_host}:{self.redis_port}")

        # 2. Khởi tạo các dịch vụ giả, truyền callback on_intrusion_detected vào
        callback = self.on_intrusion_detected

        self._services = [
            FakeSSHService(*self.ssh_bind, on_intrusion=callback),
            FakeTelnetService(*self.telnet_bind, on_intrusion=callback),
            FakeHTTPService(*self.http_bind, on_intrusion=callback),
        ]

        # 3. Bật tất cả dịch vụ đồng thời
        tasks = [asyncio.create_task(svc.serve_forever()) for svc in self._services]
        self._running = True

        logger.info(f"✓ SSH giả mạo lắng nghe tại {self.ssh_bind[0]}:{self.ssh_bind[1]}")
        logger.info(f"✓ Telnet giả mạo lắng nghe tại {self.telnet_bind[0]}:{self.telnet_bind[1]}")
        logger.info(f"✓ HTTP giả mạo lắng nghe tại {self.http_bind[0]}:{self.http_bind[1]}")
        logger.info("Honeypot đang hoạt động. Chờ kẻ xâm nhập...")
        logger.info("═" * 60)

        # Chờ tất cả task (sẽ chạy mãi cho đến khi bị cancel)
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            pass
        finally:
            await self.stop()

    async def stop(self) -> None:
        """Dừng tất cả dịch vụ và ngắt kết nối Redis."""
        if not self._running:
            return
        self._running = False
        logger.info("Đang tắt Honeypot...")
        for svc in self._services:
            await svc.stop()
        if self.reporter:
            await self.reporter.disconnect()
        logger.info("Honeypot đã dừng hoàn toàn.")

    async def on_intrusion_detected(
        self,
        attacker_ip: str,
        service_name: str,
        port: int,
        extra_info: Optional[dict] = None,
    ) -> None:
        """
        Callback được gọi bởi mỗi FakeService khi phát hiện kẻ xâm nhập.

        Đây là trái tim của honeypot: nhận event → đánh giá → report lên Redis.

        Args:
            attacker_ip:  Địa chỉ IP của kẻ tấn công.
            service_name: Tên dịch vụ bị chạm (vd: "SSH", "Telnet", "HTTP").
            port:         Cổng dịch vụ bị chạm.
            extra_info:   Dict tuỳ ý chứa thêm chi tiết (username thử, user-agent...).
        """
        extra_info = extra_info or {}
        timestamp = datetime.now(timezone.utc).isoformat()

        # Tăng bộ đếm hit
        self._hit_counter[attacker_ip] = self._hit_counter.get(attacker_ip, 0) + 1
        hit_count = self._hit_counter[attacker_ip]

        logger.warning(
            f"🚨 PHÁT HIỆN XÂM NHẬP | IP={attacker_ip} | Dịch vụ={service_name}:{port} "
            f"| Hit #{hit_count} | Extra={extra_info}"
        )

        # Kiểm tra threshold và chống báo trùng
        if hit_count < self.hit_threshold:
            logger.info(
                f"   IP {attacker_ip} chưa đủ ngưỡng ({hit_count}/{self.hit_threshold}), chưa report."
            )
            return

        if attacker_ip in self._reported_ips:
            # IP đã bị chặn rồi, chỉ log thêm chứ không publish nữa
            logger.info(f"   IP {attacker_ip} đã được report trước đó, bỏ qua.")
            return

        # Đánh dấu đã report
        self._reported_ips.add(attacker_ip)

        # Publish lên Redis → edge-node nhận và cập nhật eBPF Map
        await self.reporter.report_attacker(
            attacker_ip=attacker_ip,
            source_service=service_name,
            source_port=port,
            hit_count=hit_count,
            timestamp=timestamp,
            extra=extra_info,
        )

        logger.warning(
            f"📡 ĐÃ PUBLISH lên Redis: IP {attacker_ip} bị đưa vào blacklist toàn mạng."
        )

    def get_stats(self) -> dict:
        """
        Trả về thống kê hiện tại — hữu ích để gọi từ một HTTP status endpoint sau này.
        """
        return {
            "total_unique_ips_detected": len(self._hit_counter),
            "total_ips_reported": len(self._reported_ips),
            "hit_counts": dict(self._hit_counter),
            "reported_ips": list(self._reported_ips),
        }


# ── Entrypoint ─────────────────────────────────────────────────────────────────

async def main() -> None:
    import os

    orchestrator = HoneypotOrchestrator(
        redis_host=os.getenv("REDIS_HOST", "127.0.0.1"),
        redis_port=int(os.getenv("REDIS_PORT", "6379")),
        redis_password=os.getenv("REDIS_PASSWORD", None),
        ssh_bind=("0.0.0.0", int(os.getenv("HONEYPOT_SSH_PORT", "2222"))),
        telnet_bind=("0.0.0.0", int(os.getenv("HONEYPOT_TELNET_PORT", "2323"))),
        http_bind=("0.0.0.0", int(os.getenv("HONEYPOT_HTTP_PORT", "8080"))),
        hit_threshold=int(os.getenv("HONEYPOT_HIT_THRESHOLD", "1")),
    )

    # Xử lý tắt graceful khi nhận Ctrl+C hoặc SIGTERM
    loop = asyncio.get_running_loop()

    async def shutdown(sig_name: str) -> None:
        logger.info(f"Nhận tín hiệu {sig_name}, đang tắt...")
        await orchestrator.stop()
        loop.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(
            sig, lambda s=sig: asyncio.create_task(shutdown(s.name))
        )

    await orchestrator.start()


if __name__ == "__main__":
    asyncio.run(main())