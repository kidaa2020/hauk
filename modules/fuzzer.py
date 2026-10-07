"""
Directory & endpoint fuzzer with smart filtering
"""
import requests
import concurrent.futures
from modules.utils import color, Colors, ensure_dir
import os

BUILTIN_WORDLIST = [
    # Admin panels
    "admin","administrator","admin.php","admin/login","wp-admin","phpmyadmin","cpanel",
    "panel","dashboard","manager","management","controlpanel","backend","superadmin",
    # APIs
    "api","api/v1","api/v2","api/v3","graphql","rest","rpc","swagger","swagger-ui",
    "swagger.json","openapi.json","api-docs","api/docs","v1","v2","v3",
    # Auth
    "login","logout","signin","signup","register","auth","oauth","callback","sso",
    "forgot-password","reset-password","2fa","verify","token",
    # Config / sensitive
    ".env",".env.local",".env.prod",".env.backup","config.php","config.json",
    "settings.php","configuration.php","web.config","app.config","database.yml",
    "secrets.yml","credentials","credentials.json","credentials.xml",
    # Backups
    "backup","backup.zip","backup.tar.gz","backup.sql","dump.sql","database.sql",
    "www.zip","site.zip","files.zip","data.zip","old","archive",
    # Dev
    "test","debug","dev","development","staging","beta","demo","phpinfo.php",
    ".git","/.git/HEAD","/.git/config","/.svn",".DS_Store","Thumbs.db",
    # Endpoints
    "upload","uploads","files","file","download","downloads","static","assets",
    "images","img","js","css","media","content","storage",
    # Misc
    "robots.txt","sitemap.xml","sitemap.xml.gz","security.txt","/.well-known",
    "/.well-known/security.txt","crossdomain.xml","clientaccesspolicy.xml",
    "favicon.ico","humans.txt","ads.txt","app-ads.txt","apple-app-site-association",
    # Server info
    "server-status","server-info",".htaccess",".htpasswd","web.config","elmah.axd",
    "trace.axd","info.php","xmlrpc.php","wp-config.php","wp-login.php",
    # Cloud / infra
    ".aws/credentials","/.env.aws","/.boto","/metadata","/.git-credentials",
    "/.npmrc","/.pip/pip.conf","composer.json","package.json","yarn.lock",
    "Gemfile","requirements.txt","Dockerfile","docker-compose.yml",
    # Error / monitoring
    "error_log","error.log","debug.log","access.log","logs","log",
    "monitoring","health","healthcheck","ping","status","metrics","actuator",
    "actuator/health","actuator/env","actuator/mappings","actuator/beans",
]

class DirectoryFuzzer:
    def __init__(self, targets, wordlist=None, threads=50, timeout=10):
        self.targets = targets
        self.timeout = timeout
        self.threads = threads
        if wordlist:
            with open(wordlist) as f:
                self.words = [w.strip() for w in f if w.strip()]
        else:
            self.words = BUILTIN_WORDLIST

    def run(self):
        all_results = []
        for target in self.targets:
            results = self._fuzz(target)
            all_results.extend(results)
            found = [r for r in results if r["status"] not in (404, None)]
            print(color(f"  [+] {target}: {len(found)} interesting paths", Colors.GREEN))
        return all_results

    def _fuzz(self, base_url):
        base_url = base_url.rstrip("/")
        results = []

        def check(word):
            url = f"{base_url}/{word}"
            try:
                r = requests.get(url, timeout=self.timeout, allow_redirects=False,
                                  headers={"User-Agent": "Mozilla/5.0"})
                status = r.status_code
                if status not in (404, 400, 403) or word.startswith("."):
                    # 403 on sensitive paths is also interesting
                    interesting = status not in (404, 400) or (status == 403 and any(
                        k in word for k in [".env","config","admin","backup","secret",".git"]))
                    if interesting:
                        return {
                            "url": url,
                            "status": status,
                            "size": len(r.content),
                            "redirect": r.headers.get("Location", ""),
                            "server": r.headers.get("Server", ""),
                            "content_type": r.headers.get("Content-Type", ""),
                        }
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            for res in ex.map(check, self.words):
                if res:
                    results.append(res)
        return results
