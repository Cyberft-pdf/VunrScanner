import aiohttp
from models import Vuln, Severity, WebInfo
from packet_log import LogCallback

SECURITY_HEADERS = {
    "Strict-Transport-Security": (Severity.HIGH, "Chybí HSTS header — stránka je náchylná na downgrade útoky"),
    "Content-Security-Policy": (Severity.MEDIUM, "Chybí CSP header — zvýšené riziko XSS"),
    "X-Frame-Options": (Severity.MEDIUM, "Chybí X-Frame-Options — možný clickjacking"),
    "X-Content-Type-Options": (Severity.LOW, "Chybí X-Content-Type-Options"),
    "Referrer-Policy": (Severity.LOW, "Chybí Referrer-Policy"),
}

SQLI_PAYLOADS = ["'", "\"", "1' OR '1'='1", "1; DROP TABLE users--"]
XSS_PAYLOADS = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "\"'><svg onload=alert(1)>"]

OPEN_PATHS = [
    "/.git/HEAD", "/.env", "/admin", "/phpinfo.php",
    "/wp-admin", "/config.php", "/.htaccess", "/backup.zip",
    "/api/v1/users", "/swagger.json", "/openapi.json",
]


async def run(target: str, web_info: WebInfo, log_cb: LogCallback | None = None) -> list[Vuln]:
    vulns: list[Vuln] = []
    url = _normalize_url(target)

    if log_cb:
        log_cb("CHK", "Security Headers", "checking...", "", False)
    header_vulns = _check_security_headers(web_info)
    vulns.extend(header_vulns)
    if log_cb:
        log_cb("CHK", "Security Headers", f"{len(header_vulns)} missing", "", len(header_vulns) > 0)

    if log_cb:
        log_cb("CHK", "Exposed Paths", "checking...", "", False)
    path_vulns = await _check_open_paths(url, log_cb)
    vulns.extend(path_vulns)

    if log_cb:
        log_cb("CHK", "SQL Injection", "probing...", "", False)
    sqli_vulns = await _check_sqli(url, log_cb)
    vulns.extend(sqli_vulns)
    if log_cb and not sqli_vulns:
        log_cb("CHK", "SQL Injection", "clean", "", False)

    if log_cb:
        log_cb("CHK", "XSS (Reflected)", "probing...", "", False)
    xss_vulns = await _check_xss(url, log_cb)
    vulns.extend(xss_vulns)
    if log_cb and not xss_vulns:
        log_cb("CHK", "XSS (Reflected)", "clean", "", False)

    cookie_vulns = _check_cookies(web_info)
    vulns.extend(cookie_vulns)
    if log_cb and cookie_vulns:
        log_cb("CHK", "Cookies", f"{len(cookie_vulns)} insecure", "", True)

    return vulns


def _check_security_headers(web_info: WebInfo) -> list[Vuln]:
    vulns = []
    for header, (severity, desc) in SECURITY_HEADERS.items():
        if header not in web_info.headers and header.lower() not in {k.lower() for k in web_info.headers}:
            vulns.append(Vuln(type="Missing Security Header", severity=severity, description=desc, evidence=f"Header '{header}' nenalezen"))
    return vulns


async def _check_open_paths(base_url: str, log_cb: LogCallback | None = None) -> list[Vuln]:
    vulns = []
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        for path in OPEN_PATHS:
            url = base_url.rstrip("/") + path
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), allow_redirects=False) as resp:
                    if log_cb:
                        log_cb("GET", path, str(resp.status), "", resp.status in (200, 301, 302))
                    if resp.status in (200, 301, 302):
                        vuln = Vuln(
                            type="Exposed Path",
                            severity=Severity.HIGH if path in ("/.env", "/.git/HEAD", "/config.php") else Severity.MEDIUM,
                            description=f"Přístupná citlivá cesta: {path}",
                            evidence=f"HTTP {resp.status}",
                            url=url,
                        )
                        vulns.append(vuln)
            except Exception:
                pass
    return vulns


async def _check_sqli(base_url: str, log_cb: LogCallback | None = None) -> list[Vuln]:
    vulns = []
    test_url = base_url.rstrip("/") + "/search?q="
    errors = ["sql syntax", "mysql_fetch", "ORA-", "pg_query", "sqlite3", "syntax error"]
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        for payload in SQLI_PAYLOADS:
            try:
                async with session.get(test_url + payload, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    body = await resp.text()
                    for err in errors:
                        if err.lower() in body.lower():
                            if log_cb:
                                log_cb("CHK", "SQL Injection", "VULNERABLE!", payload[:30], True)
                            vulns.append(Vuln(
                                type="SQL Injection",
                                severity=Severity.CRITICAL,
                                description="Možná SQL Injection zranitelnost — nalezena DB chybová zpráva",
                                evidence=err,
                                url=test_url + payload,
                            ))
                            return vulns
            except Exception:
                pass
    return vulns


async def _check_xss(base_url: str, log_cb: LogCallback | None = None) -> list[Vuln]:
    vulns = []
    test_url = base_url.rstrip("/") + "/search?q="
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        for payload in XSS_PAYLOADS:
            try:
                async with session.get(test_url + payload, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    body = await resp.text()
                    if payload in body:
                        if log_cb:
                            log_cb("CHK", "XSS (Reflected)", "VULNERABLE!", payload[:30], True)
                        vulns.append(Vuln(
                            type="XSS (Reflected)",
                            severity=Severity.HIGH,
                            description="Reflected XSS — payload se vrací neescapovaný v odpovědi",
                            evidence=payload[:60],
                            url=test_url + payload,
                        ))
                        return vulns
            except Exception:
                pass
    return vulns


def _check_cookies(web_info: WebInfo) -> list[Vuln]:
    return [
        Vuln(
            type="Cookie bez Secure/HttpOnly",
            severity=Severity.LOW,
            description=f"Cookie '{cookie}' — ověř, zda má nastaveny Secure a HttpOnly příznaky",
            evidence=cookie,
        )
        for cookie in web_info.cookies
    ]


def _normalize_url(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"http://{target}"
