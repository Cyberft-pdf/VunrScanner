from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Port:
    number: int
    protocol: str
    state: str
    service: str = ""
    version: str = ""


@dataclass
class WebInfo:
    status_code: int = 0
    server: str = ""
    headers: dict = field(default_factory=dict)
    ssl_valid: bool = False
    ssl_expiry: str = ""
    cookies: list = field(default_factory=list)
    redirects: list = field(default_factory=list)


@dataclass
class Vuln:
    type: str
    severity: Severity
    description: str
    evidence: str = ""
    url: str = ""


@dataclass
class ScanResult:
    target: str
    timestamp: datetime = field(default_factory=datetime.now)
    ports: list[Port] = field(default_factory=list)
    web: WebInfo = field(default_factory=WebInfo)
    vulns: list[Vuln] = field(default_factory=list)
    subdomains: list = field(default_factory=list)
    technologies: list = field(default_factory=list)
    found_paths: list = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
