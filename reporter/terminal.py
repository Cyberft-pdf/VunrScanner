import io
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich.rule import Rule
from rich import box
from models import ScanResult, Severity

_utf8_stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
console = Console(file=_utf8_stdout, legacy_windows=False)

SEVERITY_STYLE = {
    Severity.INFO:     ("dim white",   " INFO "),
    Severity.LOW:      ("yellow",      " LOW  "),
    Severity.MEDIUM:   ("orange3",     " MED  "),
    Severity.HIGH:     ("red",         " HIGH "),
    Severity.CRITICAL: ("bold red",    " CRIT "),
}

SEVERITY_ORDER = list(Severity)


def print_results(result: ScanResult) -> None:
    _print_summary(result)
    _print_ports(result)
    _print_web(result)
    _print_technologies(result)
    _print_subdomains(result)
    _print_found_paths(result)
    _print_vulns(result)

    if result.errors:
        console.print(Rule("[red]Chyby[/]", style="red"))
        for err in result.errors:
            console.print(f"  [red]•[/] {err}")
        console.print()


def _print_summary(result: ScanResult) -> None:
    counts = {s: 0 for s in Severity}
    for v in result.vulns:
        counts[v.severity] += 1

    badges = Text()
    for sev in reversed(SEVERITY_ORDER):
        count = counts[sev]
        if count:
            style, label = SEVERITY_STYLE[sev]
            badges.append(f" {label} ", style=f"bold {style} on grey19")
            badges.append(f" {count}  ", style=style)

    grid = Table.grid(padding=(0, 4))
    grid.add_column()
    grid.add_column()
    grid.add_row(
        f"[bold]Cil:[/]          [cyan]{result.target}[/]",
        f"[bold]Cas:[/]  [dim]{result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}[/]",
    )
    grid.add_row(
        f"[bold]Otevrene porty:[/]  [green]{len(result.ports)}[/]",
        f"[bold]Zranitelnosti:[/]  [yellow]{len(result.vulns)}[/]",
    )
    grid.add_row(
        f"[bold]Subdomeny:[/]       [cyan]{len(result.subdomains)}[/]",
        f"[bold]Nalezene cesty:[/]  [orange3]{len(result.found_paths)}[/]",
    )
    grid.add_row(
        f"[bold]Technologie:[/]     [magenta]{len(result.technologies)}[/]",
        "",
    )
    grid.add_row("", "")
    grid.add_row(badges, "")

    console.print(
        Panel(
            grid,
            title="[bold green]Vysledky skenu[/]",
            border_style="green",
            box=box.HEAVY,
            padding=(1, 3),
        )
    )
    console.print()


def _print_ports(result: ScanResult) -> None:
    console.print(Rule("[bold cyan]Otevrene porty[/]", style="cyan"))

    if not result.ports:
        console.print("  [dim]Zadne otevrene porty nenalezeny.[/]\n")
        return

    table = Table(
        box=box.SIMPLE_HEAVY,
        show_edge=True,
        header_style="bold cyan",
        border_style="dim cyan",
        padding=(0, 1),
    )
    table.add_column("PORT", width=7, justify="right")
    table.add_column("PROTOKOL", width=10)
    table.add_column("SLUZBA", width=14)
    table.add_column("STAV", width=8)

    for port in sorted(result.ports, key=lambda p: p.number):
        table.add_row(
            f"[cyan]{port.number}[/]",
            port.protocol.upper(),
            f"[white]{port.service}[/]",
            "[bold green]OPEN[/]",
        )

    console.print(table)
    console.print()


def _print_web(result: ScanResult) -> None:
    web = result.web
    if not web.status_code:
        return

    console.print(Rule("[bold cyan]Web Analyza[/]", style="cyan"))

    status_color = "green" if 200 <= web.status_code < 300 else "yellow" if web.status_code < 400 else "red"
    ssl_text = "[green]Platny[/]" if web.ssl_valid else "[red]Neplatny / HTTP[/]"

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="dim", width=16)
    grid.add_column()

    rows = [
        ("HTTP Status", f"[{status_color}]{web.status_code}[/]"),
        ("Server", f"[white]{web.server or 'neznamy'}[/]"),
        ("SSL / TLS", ssl_text + (f" [dim]{web.ssl_expiry}[/]" if web.ssl_expiry else "")),
        ("Presmerovania", str(len(web.redirects)) + ("" if not web.redirects else f"  [dim]{' -> '.join(web.redirects[:3])}[/]")),
        ("Cookies", f"[yellow]{', '.join(web.cookies)}[/]" if web.cookies else "[dim]zadne[/]"),
    ]

    for label, value in rows:
        grid.add_row(f"[dim]{label}:[/]", value)

    console.print(Panel(grid, border_style="dim cyan", box=box.ROUNDED, padding=(0, 2)))
    console.print()


def _print_technologies(result: ScanResult) -> None:
    console.print(Rule("[bold magenta]Technologie[/]", style="magenta"))

    if not result.technologies:
        console.print("  [dim]Zadne technologie detekovany.[/]\n")
        return

    table = Table(
        box=box.SIMPLE_HEAVY,
        show_edge=True,
        header_style="bold magenta",
        border_style="dim magenta",
        padding=(0, 1),
    )
    table.add_column("TECHNOLOGIE", width=22, no_wrap=True)
    table.add_column("KATEGORIE", width=18, no_wrap=True)
    table.add_column("VERZE", width=12, no_wrap=True)
    table.add_column("JISTOTA", width=10, no_wrap=True)

    confidence_colors = {"high": "green", "medium": "yellow", "low": "dim"}
    for tech in sorted(result.technologies, key=lambda t: t.category):
        color = confidence_colors.get(tech.confidence, "white")
        table.add_row(
            f"[white]{tech.name}[/]",
            f"[dim]{tech.category}[/]",
            f"[cyan]{tech.version}[/]" if tech.version else "[dim]-[/]",
            f"[{color}]{tech.confidence}[/]",
        )

    console.print(table)
    console.print()


def _print_subdomains(result: ScanResult) -> None:
    console.print(Rule("[bold yellow]Subdomeny[/]", style="yellow"))

    if not result.subdomains:
        console.print("  [dim]Zadne subdomeny nalezeny.[/]\n")
        return

    table = Table(
        box=box.SIMPLE_HEAVY,
        show_edge=True,
        header_style="bold yellow",
        border_style="dim yellow",
        padding=(0, 1),
    )
    table.add_column("SUBDOMENA", min_width=30)
    table.add_column("IP ADRESA", width=18, no_wrap=True)

    for sub in sorted(result.subdomains, key=lambda s: s.name):
        table.add_row(f"[cyan]{sub.name}[/]", f"[white]{sub.ip}[/]")

    console.print(table)
    console.print()


def _print_found_paths(result: ScanResult) -> None:
    console.print(Rule("[bold orange3]Nalezene cesty[/]", style="orange3"))

    if not result.found_paths:
        console.print("  [dim]Zadne zajimave cesty nenalezeny.[/]\n")
        return

    table = Table(
        box=box.SIMPLE_HEAVY,
        show_edge=True,
        header_style="bold orange3",
        border_style="dim orange3",
        padding=(0, 1),
    )
    table.add_column("CESTA", min_width=30)
    table.add_column("HTTP", width=6, justify="center", no_wrap=True)
    table.add_column("!", width=4, justify="center", no_wrap=True)

    status_colors = {200: "green", 201: "green", 301: "yellow", 302: "yellow", 403: "orange3"}
    for p in sorted(result.found_paths, key=lambda x: (not x.sensitive, x.status)):
        color = status_colors.get(p.status, "white")
        sensitive_badge = "[bold red]![/]" if p.sensitive else ""
        table.add_row(
            f"[cyan]{p.path}[/]",
            f"[{color}]{p.status}[/]",
            sensitive_badge,
        )

    console.print(table)
    console.print()


def _print_vulns(result: ScanResult) -> None:
    console.print(Rule("[bold red]Zranitelnosti[/]", style="red"))

    if not result.vulns:
        console.print("  [bold green]Zadne zranitelnosti nenalezeny.[/]\n")
        return

    table = Table(
        box=box.SIMPLE_HEAVY,
        show_edge=True,
        header_style="bold red",
        border_style="dim red",
        padding=(0, 1),
    )
    table.add_column("", width=8, justify="center", no_wrap=True)
    table.add_column("TYP", width=24, no_wrap=True)
    table.add_column("POPIS", min_width=30)
    table.add_column("DUKAZ", width=36, no_wrap=True)

    sorted_vulns = sorted(
        result.vulns,
        key=lambda v: SEVERITY_ORDER.index(v.severity),
        reverse=True,
    )

    for vuln in sorted_vulns:
        style, label = SEVERITY_STYLE[vuln.severity]
        badge = Text(label, style=f"bold {style} on grey19")
        table.add_row(
            badge,
            f"[white]{vuln.type}[/]",
            vuln.description,
            f"[dim]{vuln.evidence[:45]}[/]" if vuln.evidence else "",
        )

    console.print(table)
    console.print()
