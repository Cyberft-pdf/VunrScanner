import asyncio
import aiohttp
from dataclasses import dataclass
from packet_log import LogCallback

WORDLIST_QUICK = [
    "admin", "administrator", "admin.php", "admin/login", "wp-admin",
    "login", "signin", "dashboard", "panel", "cpanel", "phpmyadmin",
    ".env", ".git/HEAD", ".gitignore", ".htaccess", "config.php",
    "config.yml", "config.json", "settings.py", "web.config",
    "database.yml", "secrets.yml", ".DS_Store",
    "backup", "backup.zip", "backup.tar.gz", "backup.sql", "db.sql",
    "dump.sql", "old", "bak",
    "api", "api/v1", "api/v2", "api/v3", "swagger.json", "openapi.json",
    "api-docs", "graphql", "graphiql",
    "phpinfo.php", "info.php", "test.php", "debug", "status",
    "health", "healthz", "ping", "version", "robots.txt", "sitemap.xml",
    "wp-login.php", "wp-config.php", "xmlrpc.php",
    "joomla", "drupal", "magento",
    "logs", "log", "error.log", "access.log", "debug.log",
    "uploads", "upload", "files", "media", "static", "assets",
    "dev", "development", "staging", "test", "beta",
    "console", "shell", "terminal",
]

WORDLIST_DEEP = WORDLIST_QUICK + [
    "user", "users", "account", "accounts", "profile", "register",
    "password", "forgot-password", "reset-password",
    "shop", "store", "cart", "checkout", "order", "orders",
    "blog", "posts", "articles", "news", "feed", "rss.xml",
    "search", "contact", "about", "faq", "help", "support",
    "docs", "documentation", "wiki", "kb",
    "metrics", "monitoring", "grafana", "kibana",
    "jenkins", "ci", "cd", "build",
    ".well-known/security.txt", "security.txt", "humans.txt",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "server-status", "server-info",
    "actuator", "actuator/health", "actuator/env", "actuator/beans",
    "trace", "env", "beans", "heapdump", "threaddump",
    "v1/users", "v2/users", "api/users", "api/admin",
]


@dataclass
class FoundPath:
    path: str
    status: int
    size: int = 0
    sensitive: bool = False


SENSITIVE = {
    ".env", ".git", "config", "backup", "sql", "dump", "secret",
    "password", "phpinfo", "phpmyadmin", "debug", "shell", "console",
    "actuator", "heapdump", "threaddump",
}


async def _check(
    session: aiohttp.ClientSession,
    base: str,
    path: str,
    log_cb: LogCallback | None = None,
) -> FoundPath | None:
    url = f"{base.rstrip('/')}/{path.lstrip('/')}"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), allow_redirects=False) as resp:
            sensitive = any(s in path.lower() for s in SENSITIVE)
            hit = resp.status in (200, 201, 301, 302, 403)
            if log_cb:
                detail = "SENSITIVE!" if (sensitive and hit) else ""
                log_cb("DIR", f"/{path}", str(resp.status), detail, hit and resp.status != 404)
            if hit:
                size = int(resp.headers.get("Content-Length", 0))
                return FoundPath(path=path, status=resp.status, size=size, sensitive=sensitive)
    except Exception:
        pass
    return None


async def run(target: str, deep: bool = False, log_cb: LogCallback | None = None) -> list[FoundPath]:
    url = _normalize_url(target)
    wordlist = WORDLIST_DEEP if deep else WORDLIST_QUICK

    connector = aiohttp.TCPConnector(ssl=False, limit=20)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [_check(session, url, path, log_cb) for path in wordlist]
        results = await asyncio.gather(*tasks)

    return [r for r in results if r is not None]


def _normalize_url(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"http://{target}"
