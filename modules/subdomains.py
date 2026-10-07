"""
Subdomain enumeration: crt.sh, hackertarget, threatcrowd, DNS brute-force
"""
import requests
import dns.resolver
import concurrent.futures
import json
import re
from modules.utils import color, Colors

class SubdomainScanner:
    PASSIVE_SOURCES = [
        ("crt.sh",          "https://crt.sh/?q=%.{domain}&output=json"),
        ("hackertarget",    "https://api.hackertarget.com/hostsearch/?q={domain}"),
        ("alienvault",      "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"),
        ("rapiddns",        "https://rapiddns.io/subdomain/{domain}?full=1"),
        ("urlscan",         "https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200"),
    ]

    def __init__(self, domain, threads=50, timeout=10, passive=False):
        self.domain = domain
        self.threads = threads
        self.timeout = timeout
        self.passive = passive
        self.found = set()

    def run(self):
        self._passive_enum()
        if not self.passive:
            self._brute_force()
        results = []
        for sub in sorted(self.found):
            entry = {"host": sub, "url": f"https://{sub}", "alive": False, "status": None, "ip": None}
            results.append(entry)
        self._check_alive(results)
        alive = sum(1 for r in results if r["alive"])
        print(color(f"  [-] {len(results)} unique subdomains, {alive} alive", Colors.YELLOW))
        return results

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
                data = r.json()
                for entry in data:
                    for val in entry.get("name_value", "").split("\n"):
                        val = val.strip().lstrip("*.")
                        if val:
                            subs.add(val)
            elif name == "hackertarget":
                for line in r.text.splitlines():
                    parts = line.split(",")
                    if parts:
                        subs.add(parts[0].strip())
            elif name == "alienvault":
                data = r.json()
                for rec in data.get("passive_dns", []):
                    subs.add(rec.get("hostname", "").strip())
            elif name == "rapiddns":
                subs.update(re.findall(r'([a-zA-Z0-9._-]+\.' + re.escape(self.domain) + r')', r.text))
            elif name == "urlscan":
                data = r.json()
                for result in data.get("results", []):
                    page = result.get("page", {})
                    subs.add(page.get("domain", ""))
        except Exception:
            pass
        return subs

    def _brute_force(self):
        wordlist_path = "wordlists/subdomains.txt"
        try:
            with open(wordlist_path) as f:
                words = [w.strip() for w in f if w.strip()]
        except FileNotFoundError:
            words = ["www","mail","ftp","api","dev","staging","test","admin","portal","vpn",
                     "cdn","static","assets","img","blog","shop","app","mobile","m","beta",
                     "alpha","docs","support","help","status","dashboard","secure","login",
                     "auth","sso","internal","intranet","remote","git","gitlab","jenkins",
                     "jira","confluence","kibana","grafana","prometheus","elastic","backup",
                     "db","mysql","redis","mongo","postgres","smtp","pop","imap","ns1","ns2"]

        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3

        def resolve(word):
            host = f"{word}.{self.domain}"
            try:
                answers = resolver.resolve(host, "A")
                self.found.add(host)
                return host
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(resolve, words))
        print(color(f"  [+] DNS bruteforce: checked {len(words)} prefixes", Colors.GREEN))

    def _check_alive(self, results):
        def probe(entry):
            for scheme in ["https", "http"]:
                try:
                    r = requests.get(f"{scheme}://{entry['host']}", timeout=self.timeout,
                                     allow_redirects=True, headers={"User-Agent": "Mozilla/5.0"})
                    entry["alive"] = True
                    entry["url"] = r.url
                    entry["status"] = r.status_code
                    break
                except Exception:
                    pass
            try:
                import socket
                entry["ip"] = socket.gethostbyname(entry["host"])
            except Exception:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(probe, results))
