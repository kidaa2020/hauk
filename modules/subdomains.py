"""
Subdomain enumeration: subfinder (primary) → httpx (probe + classify)
Falls back to passive OSINT + DNS if tools not installed.
"""
import subprocess
import json
import shutil
import re
import concurrent.futures
import socket
import requests
from modules.utils import color, Colors

# ── Type classification ────────────────────────────────────────────────────────
TYPE_RULES = [
    ("Admin",      r"admin|panel|dashboard|control|manager|backoffice|cpanel|whm|plesk|webmin"),
    ("API",        r"api\.|api-|graphql|rest\.|swagger|openapi|gateway|backend"),
    ("Auth",       r"login|signin|auth\.|sso\.|oauth|accounts?\.|id\.|iam\."),
    ("Dev/Stage",  r"dev\.|staging\.|stage\.|test\.|beta\.|alpha\.|qa\.|uat\.|sandbox"),
    ("Git/CI",     r"git\.|gitlab|github|jenkins|ci\.|cd\.|bitbucket|travis|drone|teamcity"),
    ("Monitoring", r"grafana|kibana|prometheus|zabbix|nagios|datadog|newrelic|elastic|splunk"),
    ("Mail",       r"mail\.|smtp\.|imap\.|pop\.|webmail\.|mx\.|email\."),
    ("Database",   r"db\.|mysql\.|mongo\.|redis\.|postgres\.|elastic\.|phpmyadmin|adminer"),
    ("CDN/Media",  r"cdn\.|static\.|assets\.|img\.|images?\.|media\.|files?\.|s3\."),
    ("VPN/Remote", r"vpn\.|remote\.|rdp\.|citrix\.|pulse\.|anyconnect\.|ftp\."),
    ("Shop",       r"shop\.|store\.|cart\.|checkout\.|payment\.|pay\."),
    ("Mobile",     r"m\.|mobile\.|app\.|ios\.|android\."),
    ("Docs",       r"docs?\.|help\.|support\.|wiki\.|kb\.|status\."),
]

def classify_subdomain(host, title="", technologies=None, url=""):
    """Classify a subdomain into a type based on hostname, title and tech."""
    text = f"{host} {title or ''} {url or ''}".lower()
    techs = " ".join(technologies or []).lower()
    for type_name, pattern in TYPE_RULES:
        if re.search(pattern, text) or re.search(pattern, techs):
            return type_name
    return "Web"


def _tool_available(name):
    return shutil.which(name) is not None


class SubdomainScanner:
    PASSIVE_SOURCES = [
        ("crt.sh",       "https://crt.sh/?q=%.{domain}&output=json"),
        ("hackertarget", "https://api.hackertarget.com/hostsearch/?q={domain}"),
        ("alienvault",   "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"),
        ("urlscan",      "https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200"),
    ]

    def __init__(self, domain, threads=50, timeout=10, passive=False):
        self.domain  = domain
        self.threads = threads
        self.timeout = timeout
        self.passive = passive
        self.found   = set()

    def run(self):
        has_subfinder = _tool_available("subfinder")
        has_httpx     = _tool_available("httpx")

        if has_subfinder:
            print(color("  [+] subfinder found — using it for enumeration", Colors.GREEN))
            self._run_subfinder()
        else:
            print(color("  [!] subfinder not found — falling back to passive OSINT", Colors.YELLOW))
            self._passive_enum()
            if not self.passive:
                self._brute_force()

        results = [{"host": h, "url": f"https://{h}", "alive": False,
                    "status": None, "ip": None, "title": "",
                    "technologies": [], "webserver": "", "cdn": False,
                    "type": "Unknown"} for h in sorted(self.found)]

        if has_httpx:
            print(color(f"  [+] httpx found — probing {len(results)} hosts", Colors.GREEN))
            self._run_httpx(results)
        else:
            print(color("  [!] httpx not found — falling back to requests probe", Colors.YELLOW))
            self._probe_requests(results)

        # Classify types
        for r in results:
            r["type"] = classify_subdomain(r["host"], r.get("title",""),
                                           r.get("technologies",[]), r.get("url",""))

        alive = sum(1 for r in results if r["alive"])
        types = {}
        for r in results:
            types[r["type"]] = types.get(r["type"], 0) + 1
        type_str = "  ".join(f"{t}:{n}" for t,n in sorted(types.items()))
        print(color(f"  [-] {len(results)} subdomains | {alive} alive | {type_str}", Colors.YELLOW))
        return results

    # ── subfinder ─────────────────────────────────────────────────────────────
    def _run_subfinder(self):
        try:
            cmd = ["subfinder", "-d", self.domain, "-silent", "-all"]
            if self.passive:
                cmd.append("-passive")
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            for line in proc.stdout.splitlines():
                host = line.strip().lower()
                if host and self.domain in host:
                    self.found.add(host)
            print(color(f"  [+] subfinder: {len(self.found)} subdomains", Colors.GREEN))
        except subprocess.TimeoutExpired:
            print(color("  [!] subfinder timed out", Colors.YELLOW))
        except Exception as e:
            print(color(f"  [!] subfinder error: {e}", Colors.YELLOW))

    # ── httpx ─────────────────────────────────────────────────────────────────
    def _run_httpx(self, results):
        hosts = [r["host"] for r in results]
        if not hosts:
            return
        try:
            cmd = [
                "httpx", "-silent", "-json",
                "-status-code", "-title", "-tech-detect",
                "-web-server", "-cdn", "-follow-redirects",
                "-timeout", str(self.timeout),
                "-threads", str(min(self.threads, 100)),
            ]
            proc = subprocess.run(
                cmd,
                input="\n".join(hosts),
                capture_output=True, text=True, timeout=600
            )
            # Index results by host for O(1) lookup
            result_map = {r["host"]: r for r in results}

            for line in proc.stdout.splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    host = data.get("input", "").strip().lower().lstrip("https://").lstrip("http://").split("/")[0]
                    if not host:
                        # try to get from url
                        from urllib.parse import urlparse
                        host = urlparse(data.get("url","")).netloc.split(":")[0]

                    if host in result_map:
                        entry = result_map[host]
                        entry["alive"]        = True
                        entry["url"]          = data.get("url", entry["url"])
                        entry["status"]       = data.get("status-code") or data.get("status_code")
                        entry["title"]        = data.get("title", "")
                        entry["technologies"] = data.get("tech", []) or data.get("technologies", [])
                        entry["webserver"]    = data.get("webserver", "") or data.get("web-server","")
                        entry["cdn"]          = bool(data.get("cdn", False))
                        # resolve IP
                        try:
                            entry["ip"] = socket.gethostbyname(host)
                        except Exception:
                            pass
                except json.JSONDecodeError:
                    continue
        except subprocess.TimeoutExpired:
            print(color("  [!] httpx timed out", Colors.YELLOW))
        except Exception as e:
            print(color(f"  [!] httpx error: {e} — falling back to requests", Colors.YELLOW))
            self._probe_requests(results)

    # ── Fallback: requests probe ───────────────────────────────────────────────
    def _probe_requests(self, results):
        def probe(entry):
            for scheme in ["https", "http"]:
                try:
                    r = requests.get(f"{scheme}://{entry['host']}", timeout=self.timeout,
                                     allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
                    entry["alive"]  = True
                    entry["url"]    = r.url
                    entry["status"] = r.status_code
                    entry["webserver"] = r.headers.get("Server", "")
                    # Extract title
                    m = re.search(r'<title[^>]*>(.*?)</title>', r.text, re.IGNORECASE | re.DOTALL)
                    if m:
                        entry["title"] = m.group(1).strip()[:100]
                    break
                except Exception:
                    pass
            try:
                entry["ip"] = socket.gethostbyname(entry["host"])
            except Exception:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(probe, results))

    # ── Passive OSINT fallback ─────────────────────────────────────────────────
    def _passive_enum(self):
        for name, url_tmpl in self.PASSIVE_SOURCES:
            try:
                url = url_tmpl.format(domain=self.domain)
                r = requests.get(url, timeout=self.timeout, headers={"User-Agent": "Mozilla/5.0"})
                subs = self._parse_source(name, r)
                for s in subs:
                    if self.domain in s:
                        self.found.add(s.lower().strip())
                print(color(f"  [+] {name}: {len(subs)} entries", Colors.GREEN))
            except Exception as e:
                print(color(f"  [!] {name}: {e}", Colors.YELLOW))

    def _parse_source(self, name, r):
        subs = set()
        try:
            if name == "crt.sh":
                for entry in r.json():
                    for val in entry.get("name_value", "").split("\n"):
                        subs.add(val.strip().lstrip("*."))
            elif name == "hackertarget":
                for line in r.text.splitlines():
                    parts = line.split(",")
                    if parts:
                        subs.add(parts[0].strip())
            elif name == "alienvault":
                for rec in r.json().get("passive_dns", []):
                    subs.add(rec.get("hostname", "").strip())
            elif name == "urlscan":
                for result in r.json().get("results", []):
                    subs.add(result.get("page", {}).get("domain", ""))
        except Exception:
            pass
        return subs

    def _brute_force(self):
        words = ["www","mail","ftp","api","dev","staging","test","admin","portal","vpn",
                 "cdn","static","assets","img","blog","shop","app","mobile","m","beta",
                 "alpha","docs","support","help","status","dashboard","secure","login",
                 "auth","sso","internal","intranet","remote","git","gitlab","jenkins",
                 "jira","confluence","kibana","grafana","prometheus","elastic","backup",
                 "db","mysql","redis","mongo","postgres","smtp","pop","imap","ns1","ns2"]
        try:
            with open("wordlists/subdomains.txt") as f:
                words = [w.strip() for w in f if w.strip()]
        except FileNotFoundError:
            pass

        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3; resolver.lifetime = 3

        def resolve(word):
            host = f"{word}.{self.domain}"
            try:
                resolver.resolve(host, "A")
                self.found.add(host)
            except Exception:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(resolve, words))
        print(color(f"  [+] DNS bruteforce: {len(words)} prefixes checked", Colors.GREEN))
