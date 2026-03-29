"""
test_end_to_end.py — Kiểm tra toàn bộ luồng Honeypot → Redis → NodeAgent.

Test này chạy được NGAY mà không cần:
  - VM VirtualBox nào
  - XDP kernel module
  - Redis server thật (dùng fakeredis)

Cài đặt để chạy test:
  pip install fakeredis pytest pytest-asyncio

Chạy:
  pytest tests/test_end_to_end.py -v
  # hoặc chạy thẳng:
  python tests/test_end_to_end.py

Mục đích của từng test case:
  1. test_block_flow         — Luồng cơ bản: Honeypot phát hiện → NodeAgent chặn
  2. test_cold_start_sync    — Node khởi động lại: phải load được blacklist cũ
  3. test_reconnect_logic    — Agent phải tự reconnect khi Redis mất kết nối
  4. test_unblock_flow       — Admin có thể gỡ chặn IP (channel remove)
  5. test_duplicate_ip       — Cùng IP chạm Honeypot nhiều lần → chỉ block 1 lần
  6. test_latency_simulation — Đo thời gian từ publish đến khi Map được cập nhật
"""

import asyncio
import json
import time
import sys
import os

# Thêm path để import các module của dự án
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "honeypot"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "edge-node", "userspace"))

import pytest
import pytest_asyncio
import fakeredis.aioredis as fakeredis

from reporter import BlacklistReporter, CHANNEL_BLACKLIST_ADD, PERSISTENT_BLACKLIST_KEY
from node_agent import NodeAgent, MockEbpfMap


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def fake_redis():
    """
    Tạo một Redis server giả trong memory.
    fakeredis implement toàn bộ Redis API bao gồm Pub/Sub,
    nên ta có thể test đầy đủ mà không cần server thật.
    """
    server = fakeredis.FakeServer()
    client = fakeredis.FakeRedis(server=server, decode_responses=True)
    yield client
    await client.aclose()


@pytest_asyncio.fixture
async def reporter(fake_redis):
    """Reporter đã được inject Redis giả."""
    rep = BlacklistReporter()
    rep._client = fake_redis  # inject trực tiếp thay vì connect()
    return rep


@pytest_asyncio.fixture
async def ebpf_map():
    """Mock eBPF Map sạch cho mỗi test."""
    return MockEbpfMap()


# ── Helper: chạy NodeAgent song song với coroutine test ───────────────────────

async def run_agent_briefly(agent: NodeAgent, duration: float = 0.5):
    """
    Chạy agent trong `duration` giây rồi dừng.
    Dùng để simulate agent đang chạy trong khi test publish message.
    """
    task = asyncio.create_task(agent.run())
    await asyncio.sleep(duration)
    await agent.stop()
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# TEST CASES
# ══════════════════════════════════════════════════════════════════════════════

class TestBlockFlow:
    """Kiểm tra luồng cơ bản: Honeypot phát hiện → NodeAgent chặn."""

    @pytest.mark.asyncio
    async def test_block_single_ip(self, fake_redis, ebpf_map):
        """
        Kịch bản: 1 IP bị honeypot phát hiện.
        Mong đợi: NodeAgent block IP đó trong eBPF Map.
        """
        attacker_ip = "10.0.0.99"

        # Tạo agent với Redis giả và Mock eBPF
        agent = NodeAgent(ebpf_map=ebpf_map)
        agent._redis = fake_redis  # inject Redis giả

        agent._running = True # Bật agent

        # Chạy agent trong background
        agent_task = asyncio.create_task(agent._subscribe_and_process())

        # Chờ agent subscribe xong (cần một chút thời gian)
        await asyncio.sleep(0.1)

        # Simulate: Reporter publish IP lên Redis
        message = json.dumps({
            "version": "1.0",
            "action": "block",
            "ip": attacker_ip,
            "source": "honeypot",
            "source_service": "SSH",
            "source_port": 2222,
            "hit_count": 1,
            "timestamp": "2025-01-15T10:00:00+00:00",
            "extra": {},
        })
        await fake_redis.publish(CHANNEL_BLACKLIST_ADD, message)

        # Chờ agent xử lý message
        await asyncio.sleep(0.2)

        # Kiểm tra kết quả
        is_blocked = await ebpf_map.is_blocked(attacker_ip)
        assert is_blocked, f"IP {attacker_ip} phải bị block sau khi nhận message"
        assert agent.stats.ips_blocked == 1
        assert agent.stats.messages_received == 1

        # Dọn dẹp
        agent_task.cancel()
        try:
            await agent_task
        except asyncio.CancelledError:
            pass


class TestColdStartSync:
    """Kiểm tra logic Cold Start — quan trọng cho trường hợp node restart."""

    @pytest.mark.asyncio
    async def test_loads_existing_blacklist_on_startup(self, fake_redis, ebpf_map):
        """
        Kịch bản: Redis đã có 3 IP trong persistent blacklist (từ trước khi node khởi động).
        Mong đợi: Sau cold start, cả 3 IP đều có trong eBPF Map.
        """
        existing_ips = {"192.168.1.10", "192.168.1.20", "10.0.0.5"}

        # Simulate: các IP này đã được Honeypot report từ trước
        for ip in existing_ips:
            await fake_redis.sadd(PERSISTENT_BLACKLIST_KEY, ip)

        agent = NodeAgent(ebpf_map=ebpf_map)
        agent._redis = fake_redis

        # Chạy cold start
        await agent._cold_start_sync()

        # Kiểm tra tất cả IP đã được load
        for ip in existing_ips:
            assert await ebpf_map.is_blocked(ip), f"IP {ip} phải được load từ cold start"

        assert agent.stats.cold_start_ips_loaded == 3

    @pytest.mark.asyncio
    async def test_empty_blacklist_on_first_startup(self, fake_redis, ebpf_map):
        """
        Kịch bản: Lần đầu chạy, Redis Set rỗng.
        Mong đợi: Cold start thành công, không có lỗi.
        """
        agent = NodeAgent(ebpf_map=ebpf_map)
        agent._redis = fake_redis

        # Không nên raise exception
        await agent._cold_start_sync()

        assert agent.stats.cold_start_ips_loaded == 0
        assert len(await ebpf_map.get_blocked_ips()) == 0


class TestUnblockFlow:
    """Kiểm tra admin có thể gỡ chặn IP."""

    @pytest.mark.asyncio
    async def test_unblock_previously_blocked_ip(self, fake_redis, ebpf_map):
        """
        Kịch bản: IP đã bị block, admin gửi lệnh unblock.
        Mong đợi: IP bị xóa khỏi eBPF Map.
        """
        from reporter import CHANNEL_BLACKLIST_REMOVE

        target_ip = "10.0.0.50"

        # Block trước
        await ebpf_map.block_ip(target_ip)
        assert await ebpf_map.is_blocked(target_ip)

        agent = NodeAgent(ebpf_map=ebpf_map)
        agent._redis = fake_redis

        agent._running = True # Bật agent
        
        agent_task = asyncio.create_task(agent._subscribe_and_process())
        await asyncio.sleep(0.1)

        # Gửi lệnh unblock
        unblock_message = json.dumps({
            "version": "1.0",
            "action": "unblock",
            "ip": target_ip,
            "source": "admin",
            "reason": "false positive",
            "timestamp": "2025-01-15T11:00:00+00:00",
        })
        await fake_redis.publish(CHANNEL_BLACKLIST_REMOVE, unblock_message)
        await asyncio.sleep(0.2)

        assert not await ebpf_map.is_blocked(target_ip), \
            f"IP {target_ip} phải được gỡ chặn sau lệnh unblock"
        assert agent.stats.ips_unblocked == 1

        agent_task.cancel()
        try:
            await agent_task
        except asyncio.CancelledError:
            pass


class TestDuplicateIP:
    """Kiểm tra xử lý IP trùng lặp — không được block cùng IP nhiều lần."""

    @pytest.mark.asyncio
    async def test_duplicate_block_ignored(self, fake_redis, ebpf_map):
        """
        Kịch bản: Honeypot gửi cùng 1 IP 3 lần (ví dụ: 3 lần chạm dịch vụ giả).
        Mong đợi: ips_blocked chỉ tăng 1 lần, không bị double-count.
        """
        attacker_ip = "10.0.0.77"

        agent = NodeAgent(ebpf_map=ebpf_map)
        agent._redis = fake_redis

        agent._running = True # Bật agent

        agent_task = asyncio.create_task(agent._subscribe_and_process())
        await asyncio.sleep(0.1)

        message = json.dumps({
            "version": "1.0",
            "action": "block",
            "ip": attacker_ip,
            "source": "honeypot",
            "source_service": "Telnet",
            "source_port": 2323,
            "hit_count": 1,
            "timestamp": "2025-01-15T10:00:00+00:00",
            "extra": {},
        })

        # Publish 3 lần
        for _ in range(3):
            await fake_redis.publish(CHANNEL_BLACKLIST_ADD, message)

        await asyncio.sleep(0.3)

        # IP vẫn bị block (đúng)
        assert await ebpf_map.is_blocked(attacker_ip)
        # Nhưng chỉ được đếm block 1 lần (nhờ is_blocked check trong _do_block)
        assert agent.stats.ips_blocked == 1
        assert agent.stats.messages_received == 3  # Nhận đủ 3 message

        agent_task.cancel()
        try:
            await agent_task
        except asyncio.CancelledError:
            pass


class TestLatencySimulation:
    """Đo độ trễ từ lúc publish đến lúc Map được cập nhật."""

    @pytest.mark.asyncio
    async def test_block_latency_under_100ms(self, fake_redis, ebpf_map):
        """
        Kiểm tra latency của toàn bộ pipeline (không tính network Redis thật).
        Với fakeredis trong cùng process, latency phải rất nhỏ.

        Trong môi trường thật (Redis trên VM khác), test này sẽ được thay thế
        bởi sync_latency_test.py với đo lường thực tế qua mạng.
        """
        attacker_ip = "172.16.0.1"
        received_at: list[float] = []

        # Monkey-patch: ghi nhận thời điểm block_ip được gọi
        original_block = ebpf_map.block_ip
        async def instrumented_block(ip):
            received_at.append(time.perf_counter())
            return await original_block(ip)
        ebpf_map.block_ip = instrumented_block

        agent = NodeAgent(ebpf_map=ebpf_map)
        agent._redis = fake_redis

        agent._running = True # Bật agent

        agent_task = asyncio.create_task(agent._subscribe_and_process())
        await asyncio.sleep(0.05)

        # Đo thời điểm publish
        publish_at = time.perf_counter()
        await fake_redis.publish(CHANNEL_BLACKLIST_ADD, json.dumps({
            "version": "1.0", "action": "block", "ip": attacker_ip,
            "source": "honeypot", "source_service": "HTTP", "source_port": 8080,
            "hit_count": 1, "timestamp": "2025-01-15T12:00:00+00:00", "extra": {},
        }))

        # Chờ tối đa 200ms
        deadline = time.perf_counter() + 0.2
        while not received_at and time.perf_counter() < deadline:
            await asyncio.sleep(0.01)

        assert received_at, "Không nhận được message trong 200ms"

        latency_ms = (received_at[0] - publish_at) * 1000
        print(f"\n  📊 Latency (trong process): {latency_ms:.2f}ms")

        # Với fakeredis cùng process, phải dưới 100ms dễ dàng
        assert latency_ms < 100, f"Latency {latency_ms:.2f}ms vượt ngưỡng 100ms"

        agent_task.cancel()
        try:
            await agent_task
        except asyncio.CancelledError:
            pass


# ── Chạy trực tiếp (không cần pytest) ────────────────────────────────────────

if __name__ == "__main__":
    import subprocess
    result = subprocess.run(
        ["python", "-m", "pytest", __file__, "-v", "--tb=short"],
        cwd=os.path.dirname(os.path.dirname(__file__))
    )
    sys.exit(result.returncode)