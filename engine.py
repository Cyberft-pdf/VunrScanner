import asyncio
from typing import Callable
from models import ScanResult
from packet_log import PacketLog, LogCallback
from modules import port_scanner, web_scanner, vuln_checker, subdomain_enum, tech_detector, dir_bruteforce

StepCallback = Callable[[str, str], None]

STEPS = ["ports", "web", "subdomains", "tech", "dirs", "vulns"]


async def scan(
    target: str,
    ports: list[int] | None = None,
    deep: bool = False,
    on_step: StepCallback | None = None,
    log_cb: LogCallback | None = None,
) -> ScanResult:
    result = ScanResult(target=target)

    def notify(step: str, state: str) -> None:
        if on_step:
            on_step(step, state)

    notify("ports", "running")
    notify("web", "running")
    notify("subdomains", "running")
    notify("tech", "running")

    port_task = asyncio.create_task(port_scanner.run(target, ports, log_cb=log_cb))
    web_task = asyncio.create_task(web_scanner.run(target, log_cb=log_cb))
    sub_task = asyncio.create_task(subdomain_enum.run(target, log_cb=log_cb))
    tech_task = asyncio.create_task(tech_detector.run(target, log_cb=log_cb))

    result.ports = await port_task
    notify("ports", "done")

    result.web = await web_task
    notify("web", "done")

    result.subdomains = await sub_task
    notify("subdomains", "done")

    result.technologies = await tech_task
    notify("tech", "done")

    notify("dirs", "running")
    result.found_paths = await dir_bruteforce.run(target, deep=deep, log_cb=log_cb)
    notify("dirs", "done")

    notify("vulns", "running")
    result.vulns = await vuln_checker.run(target, result.web, log_cb=log_cb)
    notify("vulns", "done")

    return result
