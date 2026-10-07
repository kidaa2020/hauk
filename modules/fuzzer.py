"""
Directory & endpoint fuzzer
- Auto-detects SecLists and combines multiple wordlists
- Tries HTTP + HTTPS automatically
- Smart response filtering
"""
import requests
import concurrent.futures
import os
from modules.utils import color, Colors

# ── SecLists paths (in priority order) ────────────────────────────────────────
SECLISTS_ROOTS = [
    "/usr/share/seclists",
    "/usr/share/SecLists",
    "/opt/seclists",
    "/opt/SecLists",
    os.path.expanduser("~/SecLists"),
    os.path.expanduser("~/seclists"),
]

SECLISTS_WORDLISTS = [
    "Discovery/Web-Content/common.txt",
    "Discovery/Web-Content/raft-medium-directories.txt",
    "Discovery/Web-Content/raft-medium-files.txt",
    "Discovery/Web-Content/directory-list-2.3-small.txt",
    "Discovery/Web-Content/api/api-endpoints.txt",
    "Discovery/Web-Content/quickhits.txt",
]

# ── Fallback built-in wordlist ─────────────────────────────────────────────────
BUILTIN_WORDLIST = [
    # Admin
    "admin","administrator","admin.php","admin/login","wp-admin","phpmyadmin",
    "cpanel","panel","dashboard","manager","controlpanel","backend","superadmin",
    # API
    "api","api/v1","api/v2","api/v3","graphql","rest","swagger","swagger-ui",
    "swagger.json","openapi.json","api-docs","v1","v2","v3",
    # Auth
    "login","logout","signin","signup","register","auth","oauth","callback",
    "sso","forgot-password","reset-password","2fa","verify","token",
    # Config / sensitive
    ".env",".env.local",".env.prod",".env.backup","config.php","config.json",
    "settings.php","configuration.php","web.config","app.config","database.yml",
    "secrets.yml","credentials","credentials.json",
    # Backups
    "backup","backup.zip","backup.tar.gz","backup.sql","dump.sql","database.sql",
    "www.zip","site.zip","files.zip","data.zip","old","archive",
    # Dev
    "test","debug","dev","development","staging","beta","demo","phpinfo.php",
    ".git","/.git/HEAD","/.git/config","/.svn",".DS_Store",
    # Common dirs
    "upload","uploads","files","file","download","downloads","static","assets",
    "images","img","js","css","media","content","storage","include","includes",
    "lib","libs","vendor","src","app","core","data","tmp","temp","cache",
    # Robots / well-known
    "robots.txt","sitemap.xml","security.txt","/.well-known/security.txt",
    "crossdomain.xml","clientaccesspolicy.xml","humans.txt","ads.txt",
    # Server info
    "server-status","server-info",".htaccess",".htpasswd","elmah.axd",
    "trace.axd","info.php","xmlrpc.php","wp-config.php","wp-login.php",
    # Cloud
    ".aws/credentials","/.npmrc","composer.json","package.json",
    "Dockerfile","docker-compose.yml","requirements.txt",
    # Logs / monitoring
    "error_log","error.log","debug.log","access.log","logs","log",
    "health","healthcheck","ping","status","metrics",
    "actuator","actuator/health","actuator/env","actuator/mappings",
    # PHP specifics (vulnweb etc.)
    "index.php","index.html","search.php","cat.php","product.php","listproducts.php",
    "login.php","signup.php","register.php","user.php","users.php","profile.php",
    "admin.php","cart.php","checkout.php","order.php","payment.php",
    "comment.php","comments.php","post.php","news.php","article.php",
    "contact.php","about.php","faq.php","help.php","404.php","error.php",
    "db.php","database.php","connect.php","config.php","conf.php","setup.php",
    "install.php","update.php","upgrade.php","migrate.php","cron.php",
    "ajax.php","api.php","rss.php","feed.php","xml.php","json.php","data.php",
    "upload.php","uploader.php","filemanager.php","editor.php",
    "test.php","phpinfo.php","info.php","debug.php","shell.php","cmd.php",
    # Directories
    "images/","img/","css/","js/","static/","assets/","media/","files/",
    "uploads/","download/","downloads/","backup/","old/","archive/","tmp/",
    "temp/","cache/","data/","db/","sql/","logs/","log/","admin/","user/",
    "users/","api/","v1/","v2/","docs/","doc/","help/","support/",
]


def _find_seclists():
    """Find SecLists root directory."""
    for root in SECLISTS_ROOTS:
        if os.path.isdir(root):
            return root
    return None


def _load_seclists(root):
    """Load and combine all SecLists wordlists, deduped."""
    words = set()
    loaded = []
    for rel_path in SECLISTS_WORDLISTS:
        full_path = os.path.join(root, rel_path)
        if os.path.isfile(full_path):
            try:
                with open(full_path, encoding="utf-8", errors="replace") as f:
                    new = {l.strip() for l in f if l.strip() and not l.startswith("#")}
                    words.update(new)
                    loaded.append(f"{rel_path} ({len(new)})")
            except Exception:
                pass
    return list(words), loaded


class DirectoryFuzzer:
    def __init__(self, targets, wordlist=None, threads=50, timeout=10):
        self.targets = targets
        self.timeout = timeout
        self.threads = threads
        self.words   = self._resolve_wordlist(wordlist)

    def _resolve_wordlist(self, custom_wordlist):
        # 1. Custom wordlist explicitly provided
        if custom_wordlist and os.path.isfile(custom_wordlist):
            with open(custom_wordlist, encoding="utf-8", errors="replace") as f:
                words = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            print(color(f"  [+] Custom wordlist: {len(words)} words from {custom_wordlist}", Colors.GREEN))
            return words

        # 2. Auto-detect SecLists
        seclists_root = _find_seclists()
        if seclists_root:
            words, loaded = _load_seclists(seclists_root)
            if words:
                print(color(f"  [+] SecLists detected at {seclists_root}", Colors.GREEN))
                for l in loaded:
                    print(color(f"      ↳ {l}", Colors.CYAN))
                print(color(f"  [+] Total: {len(words)} unique words", Colors.GREEN))
                return list(words)

        # 3. Fallback built-in
        print(color(f"  [!] SecLists not found — using built-in wordlist ({len(BUILTIN_WORDLIST)} words)", Colors.YELLOW))
        print(color(f"      Install SecLists: sudo apt install seclists", Colors.YELLOW))
        return BUILTIN_WORDLIST

    def run(self):
        all_results = []
        for target in self.targets:
            # Normalize: try to detect if HTTP or HTTPS works
            base = self._normalize_target(target)
            if not base:
                print(color(f"  [!] {target} unreachable — skipping", Colors.YELLOW))
                continue
            results = self._fuzz(base)
            hits = len(results)
            print(color(f"  [+] {base}: {hits} paths found", Colors.GREEN if hits else Colors.YELLOW))
            all_results.extend(results)
        return all_results

    def _normalize_target(self, target):
        """Try HTTPS then HTTP, return whichever responds."""
        candidates = []
        if target.startswith("http"):
            candidates = [target]
            # Also try the opposite scheme
            if target.startswith("https://"):
                candidates.append("http://" + target[8:])
            else:
                candidates.append("https://" + target[7:])
        else:
            candidates = [f"https://{target}", f"http://{target}"]

        for url in candidates:
            try:
                r = requests.get(url, timeout=self.timeout,
                                 headers={"User-Agent": "Mozilla/5.0"},
                                 allow_redirects=True, verify=False)
                return url.rstrip("/")
            except Exception:
                continue
        return None

    def _fuzz(self, base_url):
        results = []
        session = requests.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0"})

        # Get baseline 404 size to filter false positives
        baseline_size = self._get_baseline(session, base_url)

        def check(word):
            word = word.lstrip("/")
            url = f"{base_url}/{word}"
            try:
                r = session.get(url, timeout=self.timeout,
                                allow_redirects=False, verify=False)
                status = r.status_code
                size   = len(r.content)

                # Skip true 404s with similar size to baseline
                if status == 404:
                    if baseline_size is None or abs(size - baseline_size) < 50:
                        return None

                # Always interesting
                if status in (200, 201, 204, 301, 302, 307, 308, 403, 401, 500):
                    # Filter noise: 302 to same path, tiny 403s on non-sensitive paths
                    if status == 302:
                        loc = r.headers.get("Location", "")
                        if loc.rstrip("/") in (url.rstrip("/"), "/"):
                            return None

                    return {
                        "url":          url,
                        "status":       status,
                        "size":         size,
                        "redirect":     r.headers.get("Location", ""),
                        "server":       r.headers.get("Server", ""),
                        "content_type": r.headers.get("Content-Type", "").split(";")[0],
                    }
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            for res in ex.map(check, self.words):
                if res:
                    results.append(res)

        # Sort: 200s first, then 403, then redirects
        results.sort(key=lambda x: (
            0 if x["status"] == 200 else
            1 if x["status"] in (201, 204) else
            2 if x["status"] in (401, 403) else
            3 if x["status"] in (301, 302, 307, 308) else 4
        ))
        return results

    def _get_baseline(self, session, base_url):
        """Request a random path to get the typical 404 response size."""
        try:
            r = session.get(f"{base_url}/reconhawk_nonexistent_path_xyz123",
                            timeout=self.timeout, allow_redirects=False, verify=False)
            if r.status_code == 404:
                return len(r.content)
        except Exception:
            pass
        return None
