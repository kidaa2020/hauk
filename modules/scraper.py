"""
Source code scraper: downloads HTML, JS, CSS, extracts endpoints, forms, comments
"""
import requests
import re
import os
import hashlib
import concurrent.futures
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from modules.utils import color, Colors, ensure_dir, save_file

class SourceScraper:
    JS_PATTERNS = [
        r'["\'`](/[a-zA-Z0-9_\-/\.?=&%#@:]+)["\' `]',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
        r'url\s*[:=]\s*["\']([^"\']+)["\']',
        r'endpoint\s*[:=]\s*["\']([^"\']+)["\']',
        r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
        r'api_?[Uu]rl\s*[:=]\s*["\']([^"\']+)["\']',
        r'(?:href|action|src|data-url|data-src)\s*=\s*["\']([^"\'#\s]+)["\']',
    ]

    def __init__(self, targets, depth=2, threads=30, timeout=10, output_dir="report"):
        self.targets = targets
        self.depth = depth
        self.threads = threads
        self.timeout = timeout
        self.output_dir = output_dir
        self.visited = set()
        self.scraped_data = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0"})

    def run(self):
        for target in self.targets:
            self._crawl(target, 0)
        return self.scraped_data

    def _crawl(self, url, depth):
        if depth > self.depth or url in self.visited:
            return
        self.visited.add(url)
        try:
            r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            ct = r.headers.get("Content-Type", "")
            if "html" in ct:
                self._process_html(url, r.text, depth)
            elif "javascript" in ct or url.endswith(".js"):
                self._process_js(url, r.text)
        except Exception:
            pass

    def _process_html(self, url, html, depth):
        soup = BeautifulSoup(html, "html.parser")
        domain = urlparse(url).netloc
        base_dir = ensure_dir(os.path.join(self.output_dir, "scraped", domain.replace(":", "_")))

        # Save HTML
        fname = hashlib.md5(url.encode()).hexdigest()[:8] + ".html"
        save_file(os.path.join(base_dir, fname), html)

        # Extract JS files
        js_urls = []
        for tag in soup.find_all("script", src=True):
            js_url = urljoin(url, tag["src"])
            js_urls.append(js_url)

        # Download JS concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            ex.map(lambda u: self._download_js(u, base_dir), js_urls)

        # Extract endpoints from inline scripts
        endpoints = set()
        forms = []
        comments = []

        for script in soup.find_all("script"):
            if script.string:
                endpoints.update(self._extract_endpoints(script.string))

        for form in soup.find_all("form"):
            forms.append({
                "action": form.get("action", ""),
                "method": form.get("method", "GET"),
                "inputs": [{"name": i.get("name"), "type": i.get("type")}
                           for i in form.find_all("input")]
            })

        for comment in soup.find_all(string=lambda t: isinstance(t, str) and "<!--" in str(t)):
            text = str(comment).strip()
            if len(text) > 5:
                comments.append(text)

        # Also collect HTML comments via regex
        html_comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        comments.extend([c.strip() for c in html_comments if len(c.strip()) > 5])

        entry = {
            "url": url,
            "type": "html",
            "local": os.path.join(base_dir, fname),
            "js_files": js_urls,
            "endpoints": list(endpoints),
            "forms": forms,
            "comments": list(set(comments))[:20],
        }
        self.scraped_data.append(entry)

        # Crawl same-domain links
        if depth < self.depth:
            links = [urljoin(url, a["href"]) for a in soup.find_all("a", href=True)
                     if domain in urljoin(url, a["href"])]
            for link in links[:20]:
                self._crawl(link, depth + 1)

    def _download_js(self, url, base_dir):
        if url in self.visited:
            return
        self.visited.add(url)
        try:
            r = self.session.get(url, timeout=self.timeout)
            fname = hashlib.md5(url.encode()).hexdigest()[:8] + "_" + os.path.basename(url.split("?")[0])[-50:]
            fpath = os.path.join(base_dir, fname)
            save_file(fpath, r.text)
            endpoints = self._extract_endpoints(r.text)
            entry = {
                "url": url,
                "type": "js",
                "local": fpath,
                "endpoints": list(endpoints),
            }
            self.scraped_data.append(entry)
        except Exception:
            pass

    def _process_js(self, url, content):
        domain = urlparse(url).netloc
        base_dir = ensure_dir(os.path.join(self.output_dir, "scraped", domain.replace(":", "_")))
        self._download_js(url, base_dir)

    def _extract_endpoints(self, content):
        endpoints = set()
        for pattern in self.JS_PATTERNS:
            for match in re.finditer(pattern, content):
                ep = match.group(1)
                if len(ep) > 2 and not ep.startswith("//comments"):
                    endpoints.add(ep)
        return endpoints
