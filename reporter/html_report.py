from models import ScanResult, Severity

SEVERITY_CSS = {
    Severity.INFO: "#17a2b8",
    Severity.LOW: "#ffc107",
    Severity.MEDIUM: "#fd7e14",
    Severity.HIGH: "#dc3545",
    Severity.CRITICAL: "#6f0000",
}


def save(result: ScanResult, path: str) -> None:
    html = _build(result)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


def _build(r: ScanResult) -> str:
    ports_rows = "".join(
        f"<tr><td>{p.number}</td><td>{p.protocol}</td><td class='open'>{p.state}</td><td>{p.service}</td></tr>"
        for p in sorted(r.ports, key=lambda p: p.number)
    ) or "<tr><td colspan='4'>Žádné otevřené porty</td></tr>"

    def vuln_row(v):
        color = SEVERITY_CSS.get(v.severity, "#fff")
        return (
            f"<tr><td style='color:{color};font-weight:bold'>{v.severity.value}</td>"
            f"<td>{v.type}</td><td>{v.description}</td><td><code>{v.evidence[:80]}</code></td></tr>"
        )

    vuln_rows = "".join(
        vuln_row(v)
        for v in sorted(r.vulns, key=lambda v: list(Severity).index(v.severity), reverse=True)
    ) or "<tr><td colspan='4' style='color:green'>Žádné zranitelnosti nenalezeny</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="cs">
<head>
<meta charset="UTF-8">
<title>Scan Report – {r.target}</title>
<style>
  body {{ font-family: monospace; background: #0d0d0d; color: #ccc; padding: 2rem; }}
  h1, h2 {{ color: #00ff88; }}
  table {{ border-collapse: collapse; width: 100%; margin-bottom: 2rem; }}
  th {{ background: #1a1a2e; color: #00ff88; padding: 8px 12px; text-align: left; }}
  td {{ padding: 6px 12px; border-bottom: 1px solid #222; }}
  tr:hover {{ background: #111; }}
  .open {{ color: #00ff88; }}
  code {{ background: #111; padding: 2px 6px; border-radius: 3px; font-size: 0.85em; }}
  .info {{ background: #1a1a2e; padding: 1rem; border-left: 4px solid #00ff88; margin-bottom: 1.5rem; }}
</style>
</head>
<body>
<h1>Vulnerability Scanner Report</h1>
<div class="info">
  <strong>Cíl:</strong> {r.target}<br>
  <strong>Čas:</strong> {r.timestamp.strftime('%Y-%m-%d %H:%M:%S')}<br>
  <strong>Nalezeno zranitelností:</strong> {len(r.vulns)}<br>
  <strong>Otevřených portů:</strong> {len(r.ports)}
</div>

<h2>Otevřené porty</h2>
<table>
  <tr><th>Port</th><th>Protokol</th><th>Stav</th><th>Služba</th></tr>
  {ports_rows}
</table>

<h2>Web Info</h2>
<div class="info">
  Status: {r.web.status_code} | Server: {r.web.server or "neznámý"} |
  SSL: {"platný ✓" if r.web.ssl_valid else "neplatný"} | Redirecty: {len(r.web.redirects)}
</div>

<h2>Zranitelnosti</h2>
<table>
  <tr><th>Závažnost</th><th>Typ</th><th>Popis</th><th>Důkaz</th></tr>
  {vuln_rows}
</table>
</body>
</html>"""
