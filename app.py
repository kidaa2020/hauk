"""
ReconHawk Web UI - Flask + SocketIO server
Streams real-time scan output to the browser
"""
import os
import sys
import json
import threading
import datetime
import glob
import io
from contextlib import redirect_stdout

from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit

# Patch print so all module output is captured and streamed
app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24).hex()
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# Active scan state
scan_state = {
    "running": False,
    "domain": None,
    "results": {},
    "log": [],
    "start_time": None,
    "sid": None,  # socket session to emit to
}

# ── Intercept print → emit to browser ────────────────────────────────────────
class WebPrint:
    def __init__(self, sid):
        self.sid = sid
        self.buffer = ""

    def write(self, text):
        if text.strip():
            clean = self._strip_ansi(text.rstrip())
            scan_state["log"].append(clean)
            socketio.emit("log", {"msg": clean}, to=self.sid)

    def flush(self):
        pass

    @staticmethod
    def _strip_ansi(text):
        import re
        return re.sub(r'\033\[[0-9;]*m', '', text)


# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scans")
def list_scans():
    """List past scan reports"""
    reports = []
    for f in sorted(glob.glob("*/report_*.json"), reverse=True)[:30]:
        try:
            with open(f) as fh:
                data = json.load(fh)
            reports.append({
                "file": f,
                "domain": data.get("domain"),
                "timestamp": data.get("timestamp"),
                "subdomains": len(data.get("results", {}).get("subdomains", [])),
                "secrets": len(data.get("results", {}).get("secrets", [])),
            })
        except Exception:
            pass
    return jsonify(reports)

@app.route("/api/scan/<path:filename>")
def get_scan(filename):
    """Return a specific scan JSON"""
    try:
        with open(filename) as f:
            return jsonify(json.load(f))
    except Exception as e:
        return jsonify({"error": str(e)}), 404

@app.route("/api/results")
def current_results():
    return jsonify({
        "running": scan_state["running"],
        "domain": scan_state["domain"],
        "results": scan_state["results"],
        "log": scan_state["log"][-200:],
    })

@app.route("/report/<path:filename>")
def serve_report(filename):
    return send_from_directory(".", filename)


# ── WebSocket events ───────────────────────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    emit("status", {"running": scan_state["running"], "domain": scan_state["domain"]})
    if scan_state["log"]:
        emit("log_history", {"lines": scan_state["log"][-300:]})

@socketio.on("start_scan")
def on_start_scan(data):
    if scan_state["running"]:
        emit("error", {"msg": "A scan is already running"})
        return

    sid = request.sid
    domain = data.get("domain", "").strip()
    if not domain:
        emit("error", {"msg": "Domain required"})
        return

    opts = {
        "output":           data.get("output", f"reports/{domain}"),
        "threads":          int(data.get("threads", 50)),
        "timeout":          int(data.get("timeout", 10)),
        "wordlist":         data.get("wordlist") or None,
        "depth":            int(data.get("depth", 2)),
        "ports":            data.get("ports", "21,22,25,53,80,443,445,3306,3389,5432,6379,8080,8443,8888,9200,27017"),
        "passive":          bool(data.get("passive", False)),
        "format":           data.get("format", "both"),
        "skip_subdomains":  bool(data.get("skip_subdomains", False)),
        "skip_fuzz":        bool(data.get("skip_fuzz", False)),
        "skip_scrape":      bool(data.get("skip_scrape", False)),
        "skip_secrets":     bool(data.get("skip_secrets", False)),
        "skip_ports":       bool(data.get("skip_ports", False)),
    }

    scan_state.update({
        "running": True,
        "domain": domain,
        "results": {},
        "log": [],
        "start_time": datetime.datetime.now().isoformat(),
        "sid": sid,
    })

    socketio.emit("scan_started", {"domain": domain})
    thread = threading.Thread(target=run_scan, args=(domain, opts, sid), daemon=True)
    thread.start()

@socketio.on("stop_scan")
def on_stop_scan():
    scan_state["running"] = False
    emit("log", {"msg": "[!] Scan stop requested"})


# ── Background scan runner ────────────────────────────────────────────────────
def run_scan(domain, opts, sid):
    web_print = WebPrint(sid)
    old_stdout = sys.stdout
    sys.stdout = web_print

    try:
        from modules.subdomains import SubdomainScanner
        from modules.fuzzer import DirectoryFuzzer
        from modules.scraper import SourceScraper
        from modules.secrets import SecretHunter
        from modules.portscan import PortScanner
        from modules.reporter import Reporter

        results = {}
        output = opts["output"]
        os.makedirs(output, exist_ok=True)
        reporter = Reporter(domain, output)

        # 1. Subdomains
        if not opts["skip_subdomains"]:
            print(f"\n[*] Subdomain enumeration → {domain}")
            scanner = SubdomainScanner(domain, threads=opts["threads"],
                                        timeout=opts["timeout"], passive=opts["passive"])
            subdomains = scanner.run()
            results["subdomains"] = subdomains
            _emit_partial("subdomains", subdomains, sid)
            print(f"[+] {len(subdomains)} subdomains found")

        # 2. Port scan
        if not opts["skip_ports"] and not opts["passive"]:
            targets = [domain] + [s["host"] for s in results.get("subdomains", []) if s.get("alive")]
            targets = targets[:20]
            print(f"\n[*] Port scanning {len(targets)} hosts")
            port_scanner = PortScanner(targets, opts["ports"],
                                        threads=opts["threads"], timeout=opts["timeout"])
            results["ports"] = port_scanner.run()
            _emit_partial("ports", results["ports"], sid)

        # 3. Fuzzing
        if not opts["skip_fuzz"]:
            fuzz_targets = [f"https://{domain}", f"http://{domain}"]
            for s in results.get("subdomains", []):
                if s.get("alive"):
                    fuzz_targets.append(s["url"])
            fuzz_targets = list(dict.fromkeys(fuzz_targets))[:10]
            print(f"\n[*] Fuzzing {len(fuzz_targets)} targets")
            fuzzer = DirectoryFuzzer(fuzz_targets, wordlist=opts["wordlist"],
                                      threads=opts["threads"], timeout=opts["timeout"])
            results["fuzz"] = fuzzer.run()
            _emit_partial("fuzz", results["fuzz"], sid)

        # 4. Scraping
        if not opts["skip_scrape"]:
            scrape_targets = [f"https://{domain}"]
            for s in results.get("subdomains", []):
                if s.get("alive"):
                    scrape_targets.append(s["url"])
            scrape_targets = list(dict.fromkeys(scrape_targets))[:15]
            print(f"\n[*] Scraping source from {len(scrape_targets)} targets")
            scraper = SourceScraper(scrape_targets, depth=opts["depth"],
                                     threads=opts["threads"], timeout=opts["timeout"],
                                     output_dir=output)
            results["scraped"] = scraper.run()
            _emit_partial("scraped", results["scraped"], sid)

        # 5. Secrets
        if not opts["skip_secrets"]:
            print(f"\n[*] Hunting secrets in downloaded files")
            hunter = SecretHunter(output)
            results["secrets"] = hunter.run()
            _emit_partial("secrets", results["secrets"], sid)

        # 6. Report
        print(f"\n[*] Generating report...")
        reporter.generate(results, fmt=opts["format"])

        scan_state["results"] = results
        socketio.emit("scan_done", {
            "domain": domain,
            "summary": _build_summary(results),
            "report_dir": output,
        }, to=sid)
        print(f"\n[+] Scan complete!")

    except Exception as e:
        import traceback
        print(f"[!] ERROR: {e}")
        print(traceback.format_exc())
        socketio.emit("scan_error", {"msg": str(e)}, to=sid)
    finally:
        sys.stdout = old_stdout
        scan_state["running"] = False


def _emit_partial(key, data, sid):
    socketio.emit("partial_result", {"key": key, "data": data}, to=sid)


def _build_summary(results):
    subdomains = results.get("subdomains", [])
    secrets = results.get("secrets", [])
    return {
        "subdomains_total": len(subdomains),
        "subdomains_alive": sum(1 for s in subdomains if s.get("alive")),
        "fuzz_hits": len(results.get("fuzz", [])),
        "secrets_total": len(secrets),
        "secrets_critical": sum(1 for s in secrets if s.get("severity") == "critical"),
        "secrets_high": sum(1 for s in secrets if s.get("severity") == "high"),
        "endpoints": sum(len(s.get("endpoints", [])) for s in results.get("scraped", [])),
    }


if __name__ == "__main__":
    print("\n🦅 ReconHawk Web UI")
    print("   http://127.0.0.1:5000\n")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False)
