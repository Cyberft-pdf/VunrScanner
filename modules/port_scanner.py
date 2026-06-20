import asyncio
import socket
from models import Port
from packet_log import LogCallback

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888,
    27017, 27018,
]

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    27017: "MongoDB", 27018: "MongoDB",
}


async def scan_port(host: str, port: int, timeout: float = 1.0, log_cb: LogCallback | None = None) -> Port | None:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        service = SERVICE_NAMES.get(port, "unknown")
        if log_cb:
            log_cb("TCP", f"{host}:{port}", "OPEN", service, True)
        return Port(number=port, protocol="tcp", state="open", service=service)
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        if log_cb:
            log_cb("TCP", f"{host}:{port}", "closed", "", False)
        return None


async def run(target: str, ports: list[int] | None = None, log_cb: LogCallback | None = None) -> list[Port]:
    host = _resolve(target)
    port_list = ports or COMMON_PORTS
    tasks = [scan_port(host, p, log_cb=log_cb) for p in port_list]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]


def _resolve(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return target
