# fake_services.py — Các dịch vụ giả mạo để dụ kẻ tấn công
# Chức năng: Mở các cổng dịch vụ phổ biến (SSH:22, Telnet:23) trên Unused IPs.
# Ghi nhận thông tin kẻ tấn công: IP nguồn, timestamp, loại tấn công (scan/brute-force).
# KHÔNG cung cấp dịch vụ thật — mọi kết nối đến đây đều là bẫy.

"""
Mỗi service lắng nghe trên một cổng "mồi". Bất kỳ kết nối nào đến
đây đều bị coi là đáng ngờ (vì đây là IP/port không cung cấp dịch
vụ thật), và callback on_intrusion sẽ được gọi ngay lập tức.

Thiết kế:
  - Mỗi service kế thừa BaseFakeService để tái sử dụng logic chung.
  - Dùng asyncio để xử lý nhiều kết nối đồng thời mà không block.
  - Mỗi service cố tình "tương tác" một chút với kẻ tấn công để thu
    thêm thông tin (username brute-force, user-agent...) trước khi đóng.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Awaitable, Callable, Optional

logger = logging.getLogger("honeypot.services")

# Kiểu của callback mà HoneypotOrchestrator truyền vào
IntrusionCallback = Callable[
    [str, str, int, Optional[dict]],  # (ip, service_name, port, extra_info)
    Awaitable[None],
]


class BaseFakeService(ABC):
    """
    Lớp cơ sở cho tất cả dịch vụ giả mạo.

    Quản lý vòng đời server (start / stop) và xử lý từng kết nối
    đến trong một task asyncio riêng biệt.
    """

    def __init__(self, host: str, port: int, on_intrusion: IntrusionCallback):
        self.host = host
        self.port = port
        self.on_intrusion = on_intrusion
        self._server: Optional[asyncio.AbstractServer] = None

    @property
    @abstractmethod
    def service_name(self) -> str:
        """Tên dịch vụ (SSH, Telnet, HTTP...) dùng để log và report."""
        ...

    @abstractmethod
    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        attacker_ip: str,
    ) -> None:
        """
        Tương tác với kẻ tấn công để thu thêm thông tin.
        Mỗi subclass tự implement theo giao thức của dịch vụ đó.
        """
        ...

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Wrapper nội bộ: lấy IP, gọi callback, rồi gọi handle_connection."""
        peer = writer.get_extra_info("peername")
        attacker_ip = peer[0] if peer else "unknown"

        logger.info(f"[{self.service_name}:{self.port}] Kết nối từ {attacker_ip}")

        # Gọi callback NGAY — dù chưa biết thêm thông tin gì,
        # hành động kết nối vào honeypot đã đủ để đánh dấu đáng ngờ.
        # extra_info sẽ được cập nhật thêm bên trong handle_connection nếu có.
        extra: dict = {}
        await self.on_intrusion(attacker_ip, self.service_name, self.port, extra)

        try:
            # Tương tác thêm để thu info (username, password thử, v.v.)
            await asyncio.wait_for(
                self.handle_connection(reader, writer, attacker_ip),
                timeout=10.0,  # Tối đa 10s, tránh kẻ tấn công giữ kết nối mãi
            )
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as exc:
            logger.debug(f"[{self.service_name}] Exception từ {attacker_ip}: {exc}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def serve_forever(self) -> None:
        """Bật server và chạy mãi cho đến khi bị cancel."""
        self._server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()


# ── SSH Giả mạo ───────────────────────────────────────────────────────────────

class FakeSSHService(BaseFakeService):
    """
    Giả lập SSH banner để dụ kẻ tấn công brute-force.

    Giao thức thực của SSH dùng thư viện paramiko/asyncssh,
    nhưng ở đây chỉ cần bắt chước đủ để thu username/password thử.
    Ta gửi banner SSH hợp lệ, chờ client gửi gì đó, rồi đóng.

    Lưu ý: Đây không phải SSH server thật — không authenticate,
    không encrypt — chỉ để ghi nhận hành vi kẻ tấn công.
    """

    @property
    def service_name(self) -> str:
        return "SSH"

    async def handle_connection(self, reader, writer, attacker_ip) -> None:
        # SSH protocol version string — chuẩn RFC 4253
        banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
        writer.write(banner)
        await writer.drain()

        # Chờ client gửi version string của nó
        try:
            client_version = await reader.readline()
            if client_version:
                logger.info(
                    f"[SSH] {attacker_ip} gửi version: {client_version.decode(errors='replace').strip()}"
                )
        except Exception:
            pass
        # Sau đó im lặng và timeout — không cần làm gì thêm.


# ── Telnet Giả mạo ────────────────────────────────────────────────────────────

class FakeTelnetService(BaseFakeService):
    """
    Giả lập Telnet login prompt để thu username và password thử.

    Telnet không mã hóa, nên kẻ tấn công thường dùng để brute-force
    các thiết bị IoT. Ta hiện prompt, đọc credentials, rồi đóng.
    """

    @property
    def service_name(self) -> str:
        return "Telnet"

    async def handle_connection(self, reader, writer, attacker_ip) -> None:
        # Gửi login prompt đơn giản
        writer.write(b"\r\nUbuntu 22.04 LTS\r\nlogin: ")
        await writer.drain()

        # Đọc username (tối đa 64 byte)
        username_raw = await reader.read(64)
        username = username_raw.decode(errors="replace").strip()

        if username:
            logger.info(f"[Telnet] {attacker_ip} thử username: '{username}'")
            writer.write(b"Password: ")
            await writer.drain()

            password_raw = await reader.read(64)
            password = password_raw.decode(errors="replace").strip()
            if password:
                logger.info(f"[Telnet] {attacker_ip} thử password: '{password}'")

        # Giả vờ fail login
        writer.write(b"\r\nLogin incorrect\r\n")
        await writer.drain()


# ── HTTP Giả mạo ──────────────────────────────────────────────────────────────

class FakeHTTPService(BaseFakeService):
    """
    Giả lập một HTTP server đơn giản.

    Hữu ích để bắt các công cụ quét web (nikto, gobuster, nuclei).
    Ta đọc request line để ghi nhận path/method/user-agent.
    """

    @property
    def service_name(self) -> str:
        return "HTTP"

    async def handle_connection(self, reader, writer, attacker_ip) -> None:
        # Đọc HTTP request (tối đa 2KB, chỉ cần headers)
        raw_request = b""
        try:
            while True:
                chunk = await reader.read(512)
                if not chunk:
                    break
                raw_request += chunk
                if b"\r\n\r\n" in raw_request or len(raw_request) > 2048:
                    break
        except Exception:
            pass

        if raw_request:
            lines = raw_request.decode(errors="replace").splitlines()
            request_line = lines[0] if lines else ""
            user_agent = next(
                (l.split(":", 1)[1].strip() for l in lines if l.lower().startswith("user-agent:")),
                "unknown",
            )
            logger.info(
                f"[HTTP] {attacker_ip} | Request: '{request_line}' | UA: '{user_agent}'"
            )

        # Trả về 200 OK với body giả để kẻ tấn công không nghi ngờ ngay
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html\r\n"
            b"Server: Apache/2.4.52 (Ubuntu)\r\n"
            b"Content-Length: 45\r\n"
            b"\r\n"
            b"<html><body>Welcome to the server.</body></html>"
        )
        writer.write(response)
        await writer.drain()