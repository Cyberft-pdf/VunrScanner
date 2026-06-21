import argparse
import asyncio
import io
import sys
from datetime import datetime

from rich.console import Console, Group
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from engine import scan, STEPS as ENGINE_STEPS
from packet_log import PacketLog, KIND_STYLE
from reporter import terminal, json_report, html_report

_utf8_stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
console = Console(file=_utf8_stdout, legacy_windows=False)

BANNER = r"""
 __   ___   _  _ _    _  _     ___  ___   _   _  _
 \ \ / / | | || | |  | \| |   / __|/ __| /_\ | \| |
  \ V /| |_| __ | |__| .` |   \__ \ (__ / _ \| .` |
   \_/ |_(_)_||_|____|_|\_|   |___/\___/_/ \_\_|\_|
"""


STEP_LABELS = {
    "ports":      "Port Scanner",
    "web":        "Web Analyzer",
    "subdomains": "Subdomain Enum",
    "tech":       "Tech Detector",
    "dirs":       "Dir Bruteforce",
    "vulns":      "Vuln Checker",
}


def _build_progress_panel(states: dict[str, str], target: str) -> Panel:
    table = Table(box=None, show_header=False, padding=(0, 2))
    table.add_column(width=5)
    table.add_column(width=20)
    table.add_column(width=14)

    icons = {
        "waiting": ("[dim]  ·  [/]",          "dim"),
        "running": ("[[bold cyan] * [/]]",     "cyan"),
        "done":    ("[[bold green] ✓ [/]]",    "green"),
        "error":   ("[[bold red] ✗ [/]]",      "red"),
    }

    for key in ENGINE_STEPS:
        state = states.get(key, "waiting")
        icon, color = icons[state]
        label = f"[{color}]{STEP_LABELS.get(key, key)}[/]"
        suffix = "[dim italic]running...[/]" if state == "running" else "[green]done[/]" if state == "done" else ""
        table.add_row(icon, label, suffix)

    return Panel(
        table,
        title=f"[bold cyan]Target:[/] [white]{target}[/]",
        subtitle=f"[dim]{datetime.now().strftime('%H:%M:%S')}[/]",
        box=box.ROUNDED,
        border_style="cyan",
        padding=(0, 2),
    )


def _build_packet_log_panel(plog: PacketLog) -> Panel:
    table = Table(box=None, show_header=False, padding=(0, 1), expand=True)
    table.add_column(width=6,  no_wrap=True)   # kind badge
    table.add_column(width=2,  no_wrap=True)   # arrow
    table.add_column(min_width=28, no_wrap=True)  # target
    table.add_column(width=7,  no_wrap=True)   # status
    table.add_column(no_wrap=True)             # detail

    entries = plog.entries()
    if not entries:
        table.add_row("", "", "[dim]waiting for packets...[/]", "", "")
    else:
        for e in entries:
            style, label = KIND_STYLE.get(e.kind, ("white", e.kind[:4]))
            badge = Text(f" {label} ", style=f"{style} on grey19")

            if e.positive:
                arrow = Text(" ▶ ", style="bold green")
                target_style = "white"
                status_style = "bold green"
            else:
                arrow = Text(" · ", style="dim")
                target_style = "dim"
                status_style = "dim"

            target_text = Text(e.target[:36], style=target_style, no_wrap=True)
            status_text = Text(e.status[:8], style=status_style, no_wrap=True)

            detail = e.detail[:24] if e.detail else ""
            detail_style = "bold red" if "VULN" in detail or "SENSITIVE" in detail else "dim"
            detail_text = Text(detail, style=detail_style, no_wrap=True)

            table.add_row(badge, arrow, target_text, status_text, detail_text)

    return Panel(
        table,
        title="[bold dim]  live packets  [/]",
        border_style="dim",
        box=box.ROUNDED,
        padding=(0, 1),
    )


def _build_display(states: dict[str, str], target: str, plog: PacketLog):
    return Group(
        _build_progress_panel(states, target),
        _build_packet_log_panel(plog),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="Vulnerability Scanner — webove aplikace a site",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Priklad: py scanner.py example.com --html report.html",
    )
    parser.add_argument("target", help="Cil (domena, IP nebo URL)")
    parser.add_argument("-p", "--ports", help="Porty: 80,443,8080", default=None)
    parser.add_argument("--deep", help="Hlubsi dir bruteforce", action="store_true")
    parser.add_argument("--json", help="JSON report", metavar="SOUBOR", default=None)
    parser.add_argument("--html", help="HTML report", metavar="SOUBOR", default=None)
    return parser.parse_args()


def parse_ports(ports_str: str | None) -> list[int] | None:
    if not ports_str:
        return None
    try:
        return [int(p.strip()) for p in ports_str.split(",")]
    except ValueError:
        console.print(f"[red]Chybny format portu: {ports_str}[/]")
        sys.exit(1)


async def main() -> None:
    args = parse_args()
    ports = parse_ports(args.ports)

    console.print(f"[bold green]{BANNER}[/]", highlight=False)
    console.print(
        Panel(
            "[dim]Pouziti pouze pro autorizovane testovani vlastnich systemu.[/]",
            border_style="dim",
            box=box.SIMPLE,
        )
    )

    states: dict[str, str] = {k: "waiting" for k in ENGINE_STEPS}
    plog = PacketLog()

    result = None
    with Live(
        _build_display(states, args.target, plog),
        console=console,
        refresh_per_second=12,
        transient=False,
    ) as live:
        def step_cb(step: str, state: str) -> None:
            states[step] = state
            live.update(_build_display(states, args.target, plog))

        def log_cb(kind, target, status, detail, positive):
            plog.log(kind, target, status, detail, positive)
            live.update(_build_display(states, args.target, plog))

        result = await scan(args.target, ports, deep=args.deep, on_step=step_cb, log_cb=log_cb)
        live.update(_build_display(states, args.target, plog))

    console.print()
    terminal.print_results(result)

    saved = []
    if args.json:
        json_report.save(result, args.json)
        saved.append(f"[cyan]JSON[/] -> {args.json}")
    if args.html:
        html_report.save(result, args.html)
        saved.append(f"[cyan]HTML[/] -> {args.html}")

    if saved:
        console.print()
        for s in saved:
            console.print(f"  [green]Ulozeno:[/] {s}")

    console.print()


if __name__ == "__main__":
    asyncio.run(main())
