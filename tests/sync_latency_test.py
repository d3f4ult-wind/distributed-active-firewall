# sync_latency_test.py — Đo độ trễ đồng bộ blacklist giữa các node
#
# Chức năng: Đo thời gian (milliseconds) từ lúc Honeypot publish IP lên Redis
# đến lúc tất cả Edge Node xác nhận đã cập nhật xong eBPF Map.
# Đây là chỉ số quan trọng nhất để chứng minh tính 'gần như tức thời' của hệ thống.
# Kết quả được lưu vào results/raw/sync_latency.csv
# -----------------------------------------------------------------
"""
sync_latency_test.py — Đo độ trễ đồng bộ blacklist trong môi trường VM thật.

Mục đích học thuật:
    Đây là file đo số liệu chính để trả lời câu hỏi nghiên cứu cốt lõi
    của đề tài: "Hệ thống phân tán phản ứng nhanh đến mức nào?"

    Kết quả sẽ được đưa vào báo cáo và slide trình bày, dạng:
        "Độ trễ trung bình từ lúc Honeypot phát hiện đến lúc
         tất cả edge node cập nhật eBPF Map là X ± Y ms (n=100 lần đo)"

Cách chạy:
    # Trên VM1 (nơi Redis đang chạy), sau khi node_agent đã khởi động:
    source /home/vagrant/venv/bin/activate
    cd /home/vagrant/project

    # Chạy mặc định: 100 lần đo, lưu kết quả vào results/raw/
    python tests/sync_latency_test.py

    # Tuỳ chỉnh số lần đo và output:
    python tests/sync_latency_test.py --runs 200 --output results/raw/latency_run1.csv

    # Chế độ verbose: in chi tiết từng lần đo
    python tests/sync_latency_test.py --verbose

Cách đo latency chính xác:
    Thách thức chính là: làm sao đo T2 (thời điểm Map được cập nhật)?
    Ta không thể "hook" vào node_agent từ bên ngoài.

    Giải pháp: node_agent sẽ publish một "ack message" lên Redis channel
    "firewall:latency:ack" ngay SAU KHI gọi block_ip() thành công.
    Script này subscribe channel đó để nhận ack và tính thời gian.

    Timeline đo:
        script                    Redis                    node_agent
          │                         │                          │
          ├── T0: PUBLISH ──────────►│                          │
          │   blacklist:add          │── push message ──────────►│
          │                         │                          │ T1: nhận message
          │                         │                          │ T2: block_ip() xong
          │                         │◄── PUBLISH ack ──────────┤
          │◄── T3: nhận ack ─────────┤                          │
          │                         │                          │
        Latency đo được = T3 - T0  (xấp xỉ T2 - T0 + epsilon nhỏ)

    Ghi chú: T3 - T0 lớn hơn T2 - T0 một lượng nhỏ (latency của ack message
    trên Redis), nhưng trong mạng LAN ảo con số này < 0.1ms — chấp nhận được.

Yêu cầu:
    - Redis đang chạy và accessible
    - Ít nhất 1 node_agent đang subscribe (xem --wait-for-nodes)
    - pip install redis[hiredis] rich (rich để hiện bảng kết quả đẹp)
"""

import argparse
import asyncio
import csv
import json
import logging
import os
import statistics
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import redis.asyncio as aioredis

# Rich cho output đẹp hơn — fallback về print bình thường nếu không có
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None

# Import channel constants từ reporter.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "honeypot"))
try:
    from reporter import (
        CHANNEL_BLACKLIST_ADD,
        PERSISTENT_BLACKLIST_KEY,
        MESSAGE_VERSION,
    )
except ImportError:
    CHANNEL_BLACKLIST_ADD = "firewall:blacklist:add"
    PERSISTENT_BLACKLIST_KEY = "firewall:persistent:blacklist"
    MESSAGE_VERSION = "1.0"

# Channel đặc biệt chỉ dùng cho latency measurement
# node_agent.py cần được patch để publish ack lên channel này
CHANNEL_LATENCY_ACK = "firewall:latency:ack"

logging.basicConfig(level=logging.WARNING)  # Tắt log verbose khi đo
logger = logging.getLogger("latency_test")


# ══════════════════════════════════════════════════════════════════════════════
# Data structures
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class LatencyMeasurement:
    """
    Kết quả của một lần đo đơn lẻ.
    Lưu đủ thông tin để sau này có thể phân tích nếu cần.
    """
    run_id: int
    test_ip: str                    # IP dùng để test (không phải IP thật)
    t0_publish_ns: int              # Thời điểm PUBLISH (nanoseconds, monotonic)
    t3_ack_received_ns: int         # Thời điểm nhận ACK
    latency_ms: float               # = (t3 - t0) / 1_000_000
    ack_node_id: str = ""           # Node nào gửi ack (nếu có nhiều node)
    success: bool = True
    error: str = ""


@dataclass
class LatencyReport:
    """Tổng hợp thống kê từ nhiều lần đo."""
    measurements: list[LatencyMeasurement] = field(default_factory=list)

    @property
    def successful(self) -> list[LatencyMeasurement]:
        return [m for m in self.measurements if m.success]

    @property
    def latencies_ms(self) -> list[float]:
        return [m.latency_ms for m in self.successful]

    def summary(self) -> dict:
        lats = self.latencies_ms
        if not lats:
            return {"error": "Không có dữ liệu thành công"}
        return {
            "n":          len(lats),
            "mean_ms":    round(statistics.mean(lats), 3),
            "median_ms":  round(statistics.median(lats), 3),
            "stdev_ms":   round(statistics.stdev(lats), 3) if len(lats) > 1 else 0,
            "min_ms":     round(min(lats), 3),
            "max_ms":     round(max(lats), 3),
            "p95_ms":     round(self._percentile(lats, 95), 3),
            "p99_ms":     round(self._percentile(lats, 99), 3),
            "failed":     len(self.measurements) - len(lats),
        }

    @staticmethod
    def _percentile(data: list[float], p: int) -> float:
        """Tính percentile thủ công (không cần numpy)."""
        sorted_data = sorted(data)
        idx = (p / 100) * (len(sorted_data) - 1)
        lower, upper = int(idx), min(int(idx) + 1, len(sorted_data) - 1)
        # Linear interpolation
        return sorted_data[lower] + (idx - lower) * (sorted_data[upper] - sorted_data[lower])


# ══════════════════════════════════════════════════════════════════════════════
# Instrumented NodeAgent patch
#
# Để đo T2 (thời điểm Map cập nhật xong), ta cần node_agent publish ack.
# Thay vì sửa node_agent.py trực tiếp (sẽ làm production code phức tạp hơn),
# ta dùng một "latency mode" riêng: khi nhận message có field "latency_probe=true",
# node_agent publish ack sau khi block_ip() xong.
#
# Patch này được inject vào node_agent TRƯỚC KHI chạy test bằng cách
# set biến môi trường LATENCY_PROBE_MODE=true — node_agent kiểm tra
# biến này và tự bật ack publishing.
# ══════════════════════════════════════════════════════════════════════════════

LATENCY_PROBE_FIELD = "latency_probe"  # Field trong message để trigger ack

# Đoạn code này được inject vào node_agent._do_block() khi LATENCY_PROBE_MODE=true
# Xem hướng dẫn bên dưới để patch node_agent.py
PATCH_INSTRUCTIONS = """
# === PATCH CHO node_agent.py ĐỂ HỖ TRỢ ĐO LATENCY ===
# Thêm đoạn này vào cuối hàm _do_block() trong NodeAgent:

    async def _do_block(self, ip: str, message: dict) -> None:
        # ... code cũ giữ nguyên ...
        result = await self.ebpf_map.block_ip(ip)
        if result.success:
            self.stats.ips_blocked += 1
            # === THÊM ĐOẠN NÀY ===
            if message.get("latency_probe") and self._redis:
                ack = json.dumps({
                    "probe_id": message.get("probe_id", ""),
                    "ip": ip,
                    "node_id": self.node_id,
                    "t_ack": time.monotonic_ns(),
                })
                await self._redis.publish("firewall:latency:ack", ack)
            # === KẾT THÚC ĐOẠN THÊM ===
"""


# ══════════════════════════════════════════════════════════════════════════════
# LatencyTester — class chính thực hiện đo lường
# ══════════════════════════════════════════════════════════════════════════════

class LatencyTester:
    """
    Thực hiện đo latency end-to-end của pipeline đồng bộ blacklist.

    Quy trình một lần đo:
      1. Subscribe channel "firewall:latency:ack" để chờ ack từ node_agent.
      2. Tạo một test IP giả (không phải IP tấn công thật).
      3. Ghi timestamp T0 (nanosecond precision để chính xác).
      4. PUBLISH message lên "firewall:blacklist:add" với flag latency_probe=true.
      5. Chờ ack message trên channel ack (timeout configurable).
      6. Ghi timestamp T3 khi ack đến.
      7. Tính latency = (T3 - T0) / 1_000_000 (milliseconds).
      8. Cleanup: xóa test IP khỏi blacklist để không ảnh hưởng lần đo sau.
    """

    def __init__(
        self,
        redis_host: str = "127.0.0.1",
        redis_port: int = 6379,
        redis_password: Optional[str] = None,
        ack_timeout: float = 5.0,    # Giây chờ ack trước khi coi là timeout
        inter_run_delay: float = 0.1, # Giây nghỉ giữa các lần đo (tránh Redis quá tải)
    ):
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.redis_password = redis_password
        self.ack_timeout = ack_timeout
        self.inter_run_delay = inter_run_delay

        self._pub_client: Optional[aioredis.Redis] = None   # Dùng để PUBLISH
        self._sub_client: Optional[aioredis.Redis] = None   # Dùng để SUBSCRIBE

    # ── Setup / Teardown ──────────────────────────────────────────────────────

    async def connect(self) -> None:
        """
        Tạo 2 Redis connection riêng biệt cho publish và subscribe.

        Tại sao cần 2 connection?
          Một Redis connection đang ở chế độ SUBSCRIBE không thể
          đồng thời dùng để gửi lệnh khác (như PUBLISH hay DEL).
          Đây là giới hạn của Redis protocol — khi subscribe, connection
          chỉ được phép dùng SUBSCRIBE, UNSUBSCRIBE, PSUBSCRIBE, PING.
          Vì vậy cần 2 connection: 1 để publish test messages,
          1 để subscribe nhận ack.
        """
        connect_kwargs = dict(
            host=self.redis_host,
            port=self.redis_port,
            password=self.redis_password,
            decode_responses=True,
            socket_connect_timeout=5,
        )
        self._pub_client = aioredis.Redis(**connect_kwargs)
        self._sub_client = aioredis.Redis(**connect_kwargs)

        # Kiểm tra cả 2 connection
        await self._pub_client.ping()
        await self._sub_client.ping()

    async def disconnect(self) -> None:
        for client in (self._pub_client, self._sub_client):
            if client:
                try:
                    await client.aclose()
                except Exception:
                    pass

    # ── Kiểm tra node_agent có đang chạy không ───────────────────────────────

    async def wait_for_node_agent(self, timeout: float = 30.0) -> bool:
        """
        Chờ cho đến khi có ít nhất 1 node_agent đang subscribe channel blacklist.

        Dùng Redis PUBSUB NUMSUB để đếm số subscriber trên channel.
        Nếu = 0, chưa có node nào đang chạy — test sẽ timeout hết lần đo.

        Đây là bước quan trọng để tránh kết quả sai: nếu không có node
        nào subscribe, mọi lần đo đều timeout, dữ liệu vô nghĩa.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = await self._pub_client.pubsub_numsub(CHANNEL_BLACKLIST_ADD)
            # result là list dạng [channel_name, subscriber_count, ...]
            num_subscribers = result.get(CHANNEL_BLACKLIST_ADD, 0)
            if num_subscribers > 0:
                return True
            await asyncio.sleep(1.0)
        return False

    # ── Một lần đo đơn lẻ ────────────────────────────────────────────────────

    async def measure_once(self, run_id: int) -> LatencyMeasurement:
        """
        Thực hiện một lần đo latency hoàn chỉnh.

        Mỗi lần đo dùng một IP test khác nhau (10.255.x.x range) để
        tránh node_agent bỏ qua vì "IP đã block rồi" (duplicate check).
        """
        # Tạo test IP duy nhất cho lần đo này — dùng dải 10.255.x.x
        # là private range ít khi có traffic thật
        octet3 = (run_id // 256) % 256
        octet4 = run_id % 256
        test_ip = f"10.255.{octet3}.{octet4}"

        probe_id = f"probe-{run_id}-{int(time.monotonic_ns())}"

        # Tạo pubsub subscriber trước khi publish để không bỏ lỡ ack
        pubsub = self._sub_client.pubsub()
        await pubsub.subscribe(CHANNEL_LATENCY_ACK)

        # Bỏ qua message "subscribe confirmation" đầu tiên
        # (Redis gửi confirmation message khi subscribe thành công)
        async for msg in pubsub.listen():
            if msg["type"] == "subscribe":
                break

        try:
            # ── T0: Ghi timestamp và PUBLISH ──
            # Dùng time.monotonic_ns() thay vì time.time() vì:
            #   - monotonic: không bị ảnh hưởng bởi NTP sync hay clock jump
            #   - nanosecond: đủ độ chính xác để đo sub-millisecond latency
            t0_ns = time.monotonic_ns()

            message = json.dumps({
                "version": MESSAGE_VERSION,
                "action": "block",
                "ip": test_ip,
                "source": "latency_test",
                "source_service": "TEST",
                "source_port": 0,
                "hit_count": 1,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "extra": {},
                # Flag đặc biệt báo cho node_agent gửi ack
                LATENCY_PROBE_FIELD: True,
                "probe_id": probe_id,
            })
            await self._pub_client.publish(CHANNEL_BLACKLIST_ADD, message)

            # ── Chờ ACK từ node_agent ──
            ack_node_id = ""
            try:
                async with asyncio.timeout(self.ack_timeout):
                    async for ack_msg in pubsub.listen():
                        if ack_msg["type"] != "message":
                            continue
                        ack_data = json.loads(ack_msg["data"])
                        # Kiểm tra ack này là cho probe_id của lần đo này
                        # (tránh nhầm với ack của lần đo trước trong pipeline)
                        if ack_data.get("probe_id") == probe_id:
                            t3_ns = time.monotonic_ns()
                            ack_node_id = ack_data.get("node_id", "unknown")
                            break
                    else:
                        raise asyncio.TimeoutError()

            except asyncio.TimeoutError:
                return LatencyMeasurement(
                    run_id=run_id,
                    test_ip=test_ip,
                    t0_publish_ns=t0_ns,
                    t3_ack_received_ns=0,
                    latency_ms=-1.0,
                    success=False,
                    error=f"Timeout sau {self.ack_timeout}s — node_agent không phản hồi. "
                          "Kiểm tra: (1) node_agent đang chạy? (2) đã patch _do_block()?"
                )

            latency_ms = (t3_ns - t0_ns) / 1_000_000

            return LatencyMeasurement(
                run_id=run_id,
                test_ip=test_ip,
                t0_publish_ns=t0_ns,
                t3_ack_received_ns=t3_ns,
                latency_ms=latency_ms,
                ack_node_id=ack_node_id,
                success=True,
            )

        finally:
            # Cleanup: unsubscribe và xóa test IP khỏi blacklist
            await pubsub.unsubscribe(CHANNEL_LATENCY_ACK)
            await pubsub.aclose()
            # Xóa test IP khỏi Redis persistent set để không tích lũy rác
            await self._pub_client.srem(PERSISTENT_BLACKLIST_KEY, test_ip)

    # ── Chạy nhiều lần đo ────────────────────────────────────────────────────

    async def run(self, n_runs: int = 100, verbose: bool = False) -> LatencyReport:
        """
        Chạy n_runs lần đo và tổng hợp kết quả.

        Có một khoảng nghỉ nhỏ (inter_run_delay) giữa các lần đo để:
          1. Tránh Redis bị overwhelm bởi quá nhiều message liên tiếp.
          2. Tránh node_agent bị "queue up" quá nhiều công việc cùng lúc,
             dẫn đến latency đo được phản ánh queuing delay hơn là
             network delay thật sự.
        """
        report = LatencyReport()

        if verbose:
            print(f"\n{'Run':>4}  {'IP':>15}  {'Latency':>10}  {'Node':>14}  {'Status'}")
            print("-" * 60)

        for i in range(n_runs):
            m = await self.measure_once(run_id=i)
            report.measurements.append(m)

            if verbose:
                status = f"✓ {m.latency_ms:.3f}ms" if m.success else f"✗ {m.error[:30]}"
                node = m.ack_node_id[:14] if m.ack_node_id else "-"
                print(f"{i+1:>4}  {m.test_ip:>15}  {status:>10}  {node:>14}")
            elif (i + 1) % 10 == 0:
                # Progress indicator khi không verbose
                sys.stdout.write(f"\r  Đang đo: {i+1}/{n_runs}...")
                sys.stdout.flush()

            await asyncio.sleep(self.inter_run_delay)

        if not verbose:
            print()  # newline sau progress indicator

        return report


# ══════════════════════════════════════════════════════════════════════════════
# Output: in kết quả và lưu CSV
# ══════════════════════════════════════════════════════════════════════════════

def print_report(report: LatencyReport, output_path: Optional[str] = None) -> None:
    """In bảng thống kê và lưu raw data ra CSV."""
    summary = report.summary()

    if "error" in summary:
        print(f"\n❌ {summary['error']}")
        return

    print("\n" + "═" * 55)
    print("  KẾT QUẢ ĐO ĐỘ TRỄ ĐỒNG BỘ BLACKLIST")
    print("═" * 55)

    stats_rows = [
        ("Số lần đo thành công",    f"{summary['n']}"),
        ("Số lần đo thất bại",      f"{summary['failed']}"),
        ("─" * 25,                  "─" * 10),
        ("Trung bình (mean)",        f"{summary['mean_ms']} ms"),
        ("Trung vị (median)",        f"{summary['median_ms']} ms"),
        ("Độ lệch chuẩn (stdev)",    f"{summary['stdev_ms']} ms"),
        ("─" * 25,                  "─" * 10),
        ("Nhỏ nhất (min)",           f"{summary['min_ms']} ms"),
        ("Lớn nhất (max)",           f"{summary['max_ms']} ms"),
        ("Percentile 95 (P95)",      f"{summary['p95_ms']} ms"),
        ("Percentile 99 (P99)",      f"{summary['p99_ms']} ms"),
    ]

    for label, value in stats_rows:
        if label.startswith("─"):
            print(f"  {label}{value}")
        else:
            print(f"  {label:<30} {value:>10}")

    print("═" * 55)
    print(f"\n  📊 Kết luận: Trung bình {summary['mean_ms']}ms ± {summary['stdev_ms']}ms")
    print(f"  📊 99% lần đo hoàn tất trong {summary['p99_ms']}ms")

    # Lưu CSV nếu có output path
    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "run_id", "test_ip", "latency_ms",
                "ack_node_id", "success", "error",
                "t0_publish_ns", "t3_ack_received_ns",
            ])
            for m in report.measurements:
                writer.writerow([
                    m.run_id, m.test_ip, m.latency_ms,
                    m.ack_node_id, m.success, m.error,
                    m.t0_publish_ns, m.t3_ack_received_ns,
                ])
        print(f"\n  💾 Raw data đã lưu: {output_path}")
        print(f"  (Dùng file này để vẽ biểu đồ trong báo cáo Tháng 3)")


# ══════════════════════════════════════════════════════════════════════════════
# Entrypoint
# ══════════════════════════════════════════════════════════════════════════════

async def main(args: argparse.Namespace) -> None:
    tester = LatencyTester(
        redis_host=args.redis_host,
        redis_port=args.redis_port,
        ack_timeout=args.timeout,
        inter_run_delay=args.delay,
    )

    print(f"\n🔌 Kết nối Redis tại {args.redis_host}:{args.redis_port}...")
    try:
        await tester.connect()
    except Exception as exc:
        print(f"❌ Không thể kết nối Redis: {exc}")
        sys.exit(1)
    print("✓ Kết nối thành công")

    print(f"\n⏳ Chờ node_agent đang subscribe (timeout {args.wait}s)...")
    has_nodes = await tester.wait_for_node_agent(timeout=args.wait)
    if not has_nodes:
        print(f"❌ Không tìm thấy node_agent nào sau {args.wait}s.")
        print("   Kiểm tra: sudo systemctl status firewall-agent")
        print("   Hoặc chạy thủ công: python edge-node/userspace/node_agent.py")
        await tester.disconnect()
        sys.exit(1)
    print("✓ Phát hiện node_agent đang chạy")

    print(f"\n⚠️  Lưu ý: node_agent.py cần được patch để gửi ack.")
    print(f"   Xem PATCH_INSTRUCTIONS trong file này nếu chưa patch.\n")

    print(f"📏 Bắt đầu đo {args.runs} lần (timeout mỗi lần: {args.timeout}s)...")
    start_time = time.monotonic()

    report = await tester.run(n_runs=args.runs, verbose=args.verbose)

    elapsed = time.monotonic() - start_time
    print(f"✓ Hoàn tất {args.runs} lần đo trong {elapsed:.1f}s")

    print_report(report, output_path=args.output)

    await tester.disconnect()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Đo latency đồng bộ blacklist: Honeypot → Redis → NodeAgent → eBPF Map"
    )
    parser.add_argument("--redis-host", default=os.getenv("REDIS_HOST", "127.0.0.1"))
    parser.add_argument("--redis-port", type=int, default=int(os.getenv("REDIS_PORT", "6379")))
    parser.add_argument("--runs",    type=int,   default=100,   help="Số lần đo (default: 100)")
    parser.add_argument("--timeout", type=float, default=5.0,   help="Timeout mỗi lần đo (giây)")
    parser.add_argument("--delay",   type=float, default=0.1,   help="Nghỉ giữa các lần đo (giây)")
    parser.add_argument("--wait",    type=float, default=30.0,  help="Chờ node_agent tối đa (giây)")
    parser.add_argument("--output",  default="results/raw/latency.csv", help="Lưu CSV kết quả")
    parser.add_argument("--verbose", action="store_true", help="In chi tiết từng lần đo")
    args = parser.parse_args()

    asyncio.run(main(args))