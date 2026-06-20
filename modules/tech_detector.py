import re
import aiohttp
from dataclasses import dataclass
from packet_log import LogCallback


@dataclass
class Technology:
    name: str
    category: str
    version: str = ""
    confidence: str = "medium"


HEADER_FINGERPRINTS: list[tuple[str, str, str, str]] = [
    ("Server",        r"Apache/([\d.]+)",        "Apache",         "Web Server"),
    ("Server",        r"nginx/([\d.]+)",          "nginx",          "Web Server"),
    ("Server",        r"Microsoft-IIS/([\d.]+)",  "IIS",            "Web Server"),
    ("Server",        r"LiteSpeed",               "LiteSpeed",      "Web Server"),
    ("Server",        r"Caddy",                   "Caddy",          "Web Server"),
    ("X-Powered-By",  r"PHP/([\d.]+)",            "PHP",            "Language"),
    ("X-Powered-By",  r"ASP\.NET",                "ASP.NET",        "Framework"),
    ("X-Powered-By",  r"Express",                 "Express.js",     "Framework"),
    ("X-Powered-By",  r"Next\.js",                "Next.js",        "Framework"),
    ("X-Generator",   r"WordPress ([\d.]+)",      "WordPress",      "CMS"),
    ("X-Generator",   r"Drupal ([\d.]+)",         "Drupal",         "CMS"),
    ("X-Drupal-Cache", r".*",                     "Drupal",         "CMS"),
    ("X-WordPress-Cache", r".*",                  "WordPress",      "CMS"),
]

COOKIE_FINGERPRINTS: list[tuple[str, str, str]] = [
    ("PHPSESSID",        "PHP",           "Language"),
    ("JSESSIONID",       "Java",          "Language"),
    ("django",           "Django",        "Framework"),
    ("laravel_session",  "Laravel",       "Framework"),
    ("csrftoken",        "Django",        "Framework"),
    ("_rails",           "Ruby on Rails", "Framework"),
    ("ASP.NET_SessionId","ASP.NET",       "Framework"),
    ("connect.sid",      "Express.js",    "Framework"),
]

HTML_FINGERPRINTS: list[tuple[str, str, str]] = [
    (r"wp-content/",                        "WordPress",         "CMS"),
    (r"wp-includes/",                       "WordPress",         "CMS"),
    (r"/sites/default/files/",              "Drupal",            "CMS"),
    (r"Joomla!",                            "Joomla",            "CMS"),
    (r'"next":\s*\{',                       "Next.js",           "Framework"),
    (r"__NEXT_DATA__",                      "Next.js",           "Framework"),
    (r"data-reactroot",                     "React",             "JS Framework"),
    (r'id="__nuxt"',                        "Nuxt.js",           "JS Framework"),
    (r"ng-version=",                        "Angular",           "JS Framework"),
    (r"vue\.js|vue\.min\.js",              "Vue.js",            "JS Framework"),
    (r"jquery[.-]([\d.]+)(\.min)?\.js",    "jQuery",            "JS Library"),
    (r"bootstrap[.-]([\d.]+)(\.min)?\.js", "Bootstrap",         "CSS Framework"),
    (r"tailwindcss",                        "Tailwind CSS",      "CSS Framework"),
    (r"<meta[^>]+generator[^>]+WordPress", "WordPress",         "CMS"),
    (r"<meta[^>]+generator[^>]+Drupal",    "Drupal",            "CMS"),
    (r"Shopify\.theme",                     "Shopify",           "E-commerce"),
    (r"cdn\.shopify\.com",                  "Shopify",           "E-commerce"),
    (r"woocommerce",                        "WooCommerce",       "E-commerce"),
    (r"Google Analytics|gtag\(",           "Google Analytics",  "Analytics"),
    (r"googletagmanager\.com",             "Google Tag Manager","Analytics"),
    (r"cdn\.cloudflare\.com|__cf_",       "Cloudflare",        "CDN"),
]


async def run(target: str, log_cb: LogCallback | None = None) -> list[Technology]:
    url = _normalize_url(target)
    techs: list[Technology] = []
    seen: set[str] = set()

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), allow_redirects=True) as resp:
                headers = dict(resp.headers)
                cookies = [c.key for c in resp.cookies.values()]
                body = await resp.text(errors="replace")
                if log_cb:
                    log_cb("GET", url, str(resp.status), "fingerprinting...", True)
        except Exception:
            return techs

    def add(name: str, category: str, version: str = "", confidence: str = "medium") -> None:
        if name not in seen:
            seen.add(name)
            techs.append(Technology(name=name, category=category, version=version, confidence=confidence))
            if log_cb:
                v = f" v{version}" if version else ""
                log_cb("TECH", name + v, category, confidence, True)

    for header, pattern, name, category in HEADER_FINGERPRINTS:
        value = headers.get(header, "") or headers.get(header.lower(), "")
        if value:
            m = re.search(pattern, value, re.IGNORECASE)
            if m:
                add(name, category, m.group(1) if m.lastindex else "", "high")

    for cookie_fragment, name, category in COOKIE_FINGERPRINTS:
        if any(cookie_fragment.lower() in c.lower() for c in cookies):
            add(name, category, confidence="high")

    for pattern, name, category in HTML_FINGERPRINTS:
        m = re.search(pattern, body, re.IGNORECASE)
        if m:
            add(name, category, m.group(1) if m.lastindex and m.lastindex >= 1 else "")

    return techs


def _normalize_url(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"http://{target}"
