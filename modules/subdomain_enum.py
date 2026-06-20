import asyncio
import socket
from dataclasses import dataclass
from packet_log import LogCallback

WORDLIST = [
    "www", "mail", "ftp", "api", "admin", "dev", "staging", "test",
    "blog", "shop", "store", "app", "portal", "cdn", "static", "media",
    "assets", "img", "images", "video", "mobile", "m", "wap",
    "secure", "login", "auth", "sso", "id", "account", "accounts",
    "vpn", "remote", "gateway", "proxy", "ns1", "ns2", "smtp",
    "pop", "imap", "webmail", "mx", "mx1", "mx2",
    "beta", "alpha", "preview", "new", "old", "legacy", "backup",
    "db", "database", "mysql", "redis", "mongo",
    "jenkins", "ci", "jira", "gitlab", "github", "git",
    "docs", "help", "support", "status", "monitor", "grafana",
    "kibana", "elastic", "search",
    "v1", "v2", "v3", "internal", "intranet", "corp", "office",
]


@dataclass
class Subdomain:
    name: str
    ip: str


async def _resolve(subdomain: str, domain: str, log_cb: LogCallback | None = None) -> "Subdomain | None":
    fqdn = f"{subdomain}.{domain}"
    try:
        loop = asyncio.get_event_loop()
        ip = await loop.run_in_executor(None, socket.gethostbyname, fqdn)
        if log_cb:
            log_cb("DNS", fqdn, ip, "", True)
        return Subdomain(name=fqdn, ip=ip)
    except (socket.gaierror, OSError):
        return None


async def run(target: str, log_cb: LogCallback | None = None) -> list[Subdomain]:
    domain = _strip_domain(target)
    tasks = [_resolve(sub, domain, log_cb) for sub in WORDLIST]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]


def _strip_domain(target: str) -> str:
    target = target.replace("https://", "").replace("http://", "").split("/")[0]
    parts = target.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else target
