"""
Secret Hunter: scans downloaded files for hardcoded credentials, tokens, keys
"""
import re
import os
import json
from modules.utils import color, Colors

PATTERNS = [
    # AWS
    {"name": "AWS Access Key",       "severity": "critical", "regex": r'AKIA[0-9A-Z]{16}'},
    {"name": "AWS Secret Key",       "severity": "critical", "regex": r'(?i)aws.{0,20}["\']([A-Za-z0-9/+=]{40})["\']'},
    {"name": "AWS Session Token",    "severity": "critical", "regex": r'(?i)aws.session.token.{0,10}["\']([A-Za-z0-9/+=]{100,})["\']'},
    # Google
    {"name": "Google API Key",       "severity": "critical", "regex": r'AIza[0-9A-Za-z\-_]{35}'},
    {"name": "GCP Service Account",  "severity": "critical", "regex": r'"type"\s*:\s*"service_account"'},
    # Azure
    {"name": "Azure Storage Key",    "severity": "critical", "regex": r'AccountKey=[A-Za-z0-9+/=]{88}'},
    {"name": "Azure SAS Token",      "severity": "high",     "regex": r'sv=\d{4}-\d{2}-\d{2}&s[a-z]='},
    # GitHub / Git
    {"name": "GitHub Token",         "severity": "critical", "regex": r'gh[pousr]_[A-Za-z0-9_]{36,}'},
    {"name": "GitHub Classic Token", "severity": "critical", "regex": r'ghp_[A-Za-z0-9]{36}'},
    {"name": "GitLab Token",         "severity": "critical", "regex": r'glpat-[A-Za-z0-9\-_]{20}'},
    # Stripe / Payment
    {"name": "Stripe Live Key",      "severity": "critical", "regex": r'sk_live_[A-Za-z0-9]{24,}'},
    {"name": "Stripe Test Key",      "severity": "medium",   "regex": r'sk_test_[A-Za-z0-9]{24,}'},
    {"name": "Stripe Public Key",    "severity": "low",      "regex": r'pk_live_[A-Za-z0-9]{24,}'},
    # Twilio / SendGrid
    {"name": "Twilio API Key",       "severity": "high",     "regex": r'SK[a-z0-9]{32}'},
    {"name": "SendGrid Key",         "severity": "high",     "regex": r'SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}'},
    # Slack
    {"name": "Slack Token",          "severity": "high",     "regex": r'xox[baprs]-[A-Za-z0-9\-]{10,}'},
    {"name": "Slack Webhook",        "severity": "high",     "regex": r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'},
    # JWT
    {"name": "JWT Token",            "severity": "medium",   "regex": r'eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*'},
    # Private Keys
    {"name": "RSA Private Key",      "severity": "critical", "regex": r'-----BEGIN RSA PRIVATE KEY-----'},
    {"name": "EC Private Key",       "severity": "critical", "regex": r'-----BEGIN EC PRIVATE KEY-----'},
    {"name": "OpenSSH Key",          "severity": "critical", "regex": r'-----BEGIN OPENSSH PRIVATE KEY-----'},
    {"name": "PGP Private Key",      "severity": "critical", "regex": r'-----BEGIN PGP PRIVATE KEY BLOCK-----'},
    # Passwords
    {"name": "Password in URL",      "severity": "high",     "regex": r'[a-zA-Z]+://[^:@\s]+:([^:@\s@]{8,})@[a-zA-Z0-9.-]+'},
    {"name": "Basic Auth Header",    "severity": "high",     "regex": r'(?i)authorization:\s*basic\s+[A-Za-z0-9+/=]{10,}'},
    {"name": "Hardcoded Password",   "severity": "high",     "regex": r'(?i)(?:password|passwd|pwd|pass)\s*[=:]\s*["\']([^"\']{8,})["\']'},
    {"name": "Hardcoded Secret",     "severity": "high",     "regex": r'(?i)(?:secret|api_?secret|client_?secret)\s*[=:]\s*["\']([^"\']{8,})["\']'},
    {"name": "Hardcoded Token",      "severity": "high",     "regex": r'(?i)(?:token|access_?token|auth_?token|bearer)\s*[=:]\s*["\']([^"\']{16,})["\']'},
    {"name": "Database URL",         "severity": "high",     "regex": r'(?i)(?:mysql|postgres|mongodb|redis|mssql)://[^\s"\'<>]+'},
    # API Keys generic
    {"name": "Generic API Key",      "severity": "medium",   "regex": r'(?i)api[_-]?key\s*[=:]\s*["\']([A-Za-z0-9\-_]{16,})["\']'},
    {"name": "Generic Access Key",   "severity": "medium",   "regex": r'(?i)access[_-]?key\s*[=:]\s*["\']([A-Za-z0-9\-_]{16,})["\']'},
    # Firebase
    {"name": "Firebase URL",         "severity": "medium",   "regex": r'https://[a-z0-9-]+\.firebaseio\.com'},
    # Mailchimp
    {"name": "Mailchimp API Key",    "severity": "high",     "regex": r'[0-9a-f]{32}-us[0-9]{1,2}'},
    # NPM tokens
    {"name": "NPM Token",            "severity": "high",     "regex": r'npm_[A-Za-z0-9]{36}'},
    # Heroku
    {"name": "Heroku API Key",       "severity": "high",     "regex": r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'},
    # Internal IPs / Hostnames
    {"name": "Internal IP",          "severity": "low",      "regex": r'(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}'},
    # S3 Buckets
    {"name": "S3 Bucket URL",        "severity": "medium",   "regex": r'https?://([a-z0-9\-\.]+)\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com'},
]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

class SecretHunter:
    def __init__(self, output_dir="report"):
        self.output_dir = output_dir
        self.scraped_dir = os.path.join(output_dir, "scraped")

    def run(self):
        findings = []
        files = self._collect_files()
        for fpath in files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                for pattern in PATTERNS:
                    for match in re.finditer(pattern["regex"], content):
                        line_no = content[:match.start()].count("\n") + 1
                        finding = {
                            "file": fpath,
                            "pattern": pattern["name"],
                            "severity": pattern["severity"],
                            "match": match.group(0)[:200],
                            "line": line_no,
                        }
                        findings.append(finding)
                        sev_color = {"critical": Colors.RED, "high": Colors.RED,
                                     "medium": Colors.YELLOW, "low": Colors.CYAN}.get(pattern["severity"], Colors.RESET)
                        print(color(f"  [{pattern['severity'].upper()}] {pattern['name']} in {os.path.basename(fpath)}:{line_no}", sev_color))
            except Exception:
                pass

        # Deduplicate
        seen = set()
        deduped = []
        for f in findings:
            key = (f["pattern"], f["match"][:50])
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        deduped.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
        return deduped

    def _collect_files(self):
        files = []
        if not os.path.isdir(self.scraped_dir):
            return files
        for root, dirs, filenames in os.walk(self.scraped_dir):
            for fname in filenames:
                if fname.endswith((".html", ".js", ".json", ".txt", ".xml", ".yml", ".yaml", ".env", ".config")):
                    files.append(os.path.join(root, fname))
        return files
