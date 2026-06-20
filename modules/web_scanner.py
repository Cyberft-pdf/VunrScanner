import ssl
import socket
from datetime import datetime
import aiohttp
from models import WebInfo
from packet_log import LogCallback


async def run(target: str, log_cb: LogCallback | None = None) -> WebInfo:
    info = WebInfo()
    url = _normalize_url(target)

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        try:
            async with session.get(url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                info.status_code = resp.status
                info.headers = dict(resp.headers)
                info.server = resp.headers.get("Server", "")
                info.redirects = [str(h.url) for h in resp.history]
                info.cookies = [c.key for c in resp.cookies.values()]
                if log_cb:
                    log_cb("GET", url, str(resp.status), info.server, resp.status < 400)
        except Exception:
            info.status_code = 0
            if log_cb:
                log_cb("GET", url, "ERR", "connection failed", False)

    if url.startswith("https://"):
        info.ssl_valid, info.ssl_expiry = _check_ssl(target, log_cb)

    return info


def _normalize_url(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"http://{target}"


def _check_ssl(target: str, log_cb: LogCallback | None = None) -> tuple[bool, str]:
    host = target.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(5)
            s.connect((host, 443))
            cert = s.getpeercert()
            expiry_str = cert.get("notAfter", "")
            expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z") if expiry_str else None
            valid = expiry > datetime.utcnow() if expiry else False
            if log_cb:
                log_cb("SSL", host, "valid" if valid else "expired", expiry_str, valid)
            return valid, expiry_str
    except Exception as e:
        if log_cb:
            log_cb("SSL", host, "failed", str(e)[:40], False)
        return False, ""
