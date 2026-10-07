"""
Report generator: JSON + HTML reports
"""
import json
import os
import datetime
from modules.utils import color, Colors, ensure_dir

class Reporter:
    def __init__(self, domain, output_dir="report"):
        self.domain = domain
        self.output_dir = output_dir
        ensure_dir(output_dir)

    def generate(self, results, fmt="both"):
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        if fmt in ("json", "both"):
            self._json_report(results, ts)
        if fmt in ("html", "both"):
            self._html_report(results, ts)

    def _json_report(self, results, ts):
        path = os.path.join(self.output_dir, f"report_{ts}.json")
        with open(path, "w") as f:
            json.dump({"domain": self.domain, "timestamp": ts, "results": results}, f, indent=2, default=str)
        print(color(f"  [+] JSON: {path}", Colors.CYAN))

    def _html_report(self, results, ts):
        subdomains = results.get("subdomains", [])
        fuzz = results.get("fuzz", [])
        secrets = results.get("secrets", [])
        ports = results.get("ports", {})
        scraped = results.get("scraped", [])

        alive_subs = [s for s in subdomains if s.get("alive")]
        critical_secrets = [s for s in secrets if s.get("severity") == "critical"]
        high_secrets = [s for s in secrets if s.get("severity") == "high"]

        sev_badge = lambda s: {
            "critical": '<span class="badge critical">CRITICAL</span>',
            "high":     '<span class="badge high">HIGH</span>',
            "medium":   '<span class="badge medium">MEDIUM</span>',
            "low":      '<span class="badge low">LOW</span>',
        }.get(s, s)

        status_color = lambda c: {200:"green",201:"green",301:"orange",302:"orange",
                                   403:"blue",500:"red"}.get(c,"gray")

        # Build sections
        sub_rows = "".join(
            f'<tr><td><a href="{s["url"]}" target="_blank">{s["host"]}</a></td>'
            f'<td><span class="status-{status_color(s["status"])}">{s["status"] or "-"}</span></td>'
            f'<td>{s.get("ip","")}</td></tr>'
            for s in alive_subs
        )
        fuzz_rows = "".join(
            f'<tr><td><a href="{f["url"]}" target="_blank">{f["url"]}</a></td>'
            f'<td><span class="status-{status_color(f["status"])}">{f["status"]}</span></td>'
            f'<td>{f.get("size","")}</td>'
            f'<td>{f.get("content_type","")}</td></tr>'
            for f in fuzz
        )
        secret_rows = "".join(
            f'<tr>{sev_badge(s["severity"])}<td>{s["pattern"]}</td>'
            f'<td class="mono">{s["match"][:100].replace("<","&lt;")}</td>'
            f'<td>{os.path.basename(s["file"])}:{s["line"]}</td></tr>'
            for s in secrets
        )
        port_rows = ""
        for host, open_ports in ports.items():
            for p in open_ports:
                port_rows += f'<tr><td>{host}</td><td>{p["port"]}</td><td>{p["service"]}</td><td class="mono">{p["banner"][:80]}</td></tr>'

        endpoints = set()
        for item in scraped:
            endpoints.update(item.get("endpoints", []))

        ep_rows = "".join(f'<tr><td class="mono">{e.replace("<","&lt;")}</td></tr>' for e in sorted(endpoints)[:200])

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReconHawk - {self.domain}</title>
<style>
  :root{{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;
    --red:#ff4444;--orange:#f0883e;--green:#3fb950;--blue:#58a6ff;--purple:#bc8cff}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',monospace;font-size:14px}}
  header{{background:linear-gradient(135deg,#1a1f2e,#0d1117);padding:24px 32px;border-bottom:1px solid var(--border)}}
  header h1{{font-size:28px;color:var(--blue)}}
  header p{{color:var(--muted);margin-top:4px}}
  .container{{max-width:1400px;margin:0 auto;padding:24px 32px}}
  .summary{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:32px}}
  .card{{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:20px;text-align:center}}
  .card .num{{font-size:36px;font-weight:700;color:var(--blue)}}
  .card .num.danger{{color:var(--red)}}
  .card .num.warn{{color:var(--orange)}}
  .card .label{{color:var(--muted);font-size:12px;margin-top:4px;text-transform:uppercase;letter-spacing:1px}}
  section{{margin-bottom:40px}}
  section h2{{font-size:18px;color:var(--blue);border-bottom:1px solid var(--border);padding-bottom:8px;margin-bottom:16px}}
  table{{width:100%;border-collapse:collapse}}
  th{{background:var(--surface);color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:1px;padding:10px 12px;text-align:left;border-bottom:1px solid var(--border)}}
  td{{padding:10px 12px;border-bottom:1px solid #21262d;vertical-align:top}}
  tr:hover td{{background:#1c2128}}
  a{{color:var(--blue);text-decoration:none}}
  a:hover{{text-decoration:underline}}
  .mono{{font-family:monospace;font-size:12px;word-break:break-all}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;text-transform:uppercase}}
  .critical{{background:#3d0000;color:#ff4444;border:1px solid #ff4444}}
  .high{{background:#2d1a00;color:#f0883e;border:1px solid #f0883e}}
  .medium{{background:#1a1a00;color:#e3b341;border:1px solid #e3b341}}
  .low{{background:#001a1a;color:#39d353;border:1px solid #39d353}}
  .status-green{{color:var(--green)}}
  .status-orange{{color:var(--orange)}}
  .status-blue{{color:var(--blue)}}
  .status-red{{color:var(--red)}}
  .status-gray{{color:var(--muted)}}
  .tabs{{display:flex;gap:4px;margin-bottom:16px;border-bottom:1px solid var(--border)}}
  .tab{{padding:8px 16px;cursor:pointer;border-radius:6px 6px 0 0;color:var(--muted)}}
  .tab.active{{background:var(--surface);color:var(--text);border:1px solid var(--border);border-bottom:1px solid var(--bg)}}
  .empty{{color:var(--muted);font-style:italic;padding:16px}}
</style>
</head>
<body>
<header>
  <h1>🦅 ReconHawk</h1>
  <p>Target: <strong>{self.domain}</strong> &nbsp;|&nbsp; Scan time: {ts}</p>
</header>
<div class="container">

<div class="summary">
  <div class="card"><div class="num">{len(subdomains)}</div><div class="label">Subdomains</div></div>
  <div class="card"><div class="num">{len(alive_subs)}</div><div class="label">Alive</div></div>
  <div class="card"><div class="num {'danger' if critical_secrets else ''}">{len(critical_secrets)}</div><div class="label">Critical Secrets</div></div>
  <div class="card"><div class="num {'warn' if high_secrets else ''}">{len(high_secrets)}</div><div class="label">High Secrets</div></div>
  <div class="card"><div class="num">{len(fuzz)}</div><div class="label">Paths Found</div></div>
  <div class="card"><div class="num">{len(endpoints)}</div><div class="label">Endpoints</div></div>
</div>

<section>
  <h2>🔐 Secrets & Sensitive Data ({len(secrets)})</h2>
  {'<table><thead><tr><th>Severity</th><th>Type</th><th>Match</th><th>Location</th></tr></thead><tbody>' + secret_rows + '</tbody></table>' if secrets else '<div class="empty">No secrets found</div>'}
</section>

<section>
  <h2>🌐 Live Subdomains ({len(alive_subs)} / {len(subdomains)})</h2>
  {'<table><thead><tr><th>Host</th><th>Status</th><th>IP</th></tr></thead><tbody>' + sub_rows + '</tbody></table>' if alive_subs else '<div class="empty">No live subdomains found</div>'}
</section>

<section>
  <h2>📂 Directory Fuzzing ({len(fuzz)} hits)</h2>
  {'<table><thead><tr><th>URL</th><th>Status</th><th>Size</th><th>Content-Type</th></tr></thead><tbody>' + fuzz_rows + '</tbody></table>' if fuzz else '<div class="empty">No interesting paths found</div>'}
</section>

<section>
  <h2>🔌 Open Ports</h2>
  {'<table><thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Banner</th></tr></thead><tbody>' + port_rows + '</tbody></table>' if port_rows else '<div class="empty">No ports scanned or no open ports found</div>'}
</section>

<section>
  <h2>🔗 Discovered Endpoints ({len(endpoints)})</h2>
  {'<table><thead><tr><th>Endpoint</th></tr></thead><tbody>' + ep_rows + '</tbody></table>' if endpoints else '<div class="empty">No endpoints discovered</div>'}
</section>

</div>
</body>
</html>"""
        path = os.path.join(self.output_dir, f"report_{ts}.html")
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        print(color(f"  [+] HTML: {path}", Colors.CYAN))
