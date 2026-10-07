# 🦅 ReconHawk

Advanced pentesting & bug bounty automation tool for Linux.

## Features

| Module | Description |
|--------|-------------|
| **Subdomains** | Passive OSINT (crt.sh, HackerTarget, AlienVault, URLScan) + DNS brute-force |
| **Port Scanner** | Socket-based scanner with banner grabbing (no nmap needed) |
| **Dir Fuzzer** | 150+ built-in sensitive paths + custom wordlist support |
| **Source Scraper** | Crawls HTML, downloads all JS files, extracts endpoints & forms |
| **Secret Hunter** | 35+ regex patterns: AWS, GCP, Azure, GitHub, Stripe, JWT, RSA keys, passwords... |
| **Reporter** | Dark-themed HTML report + JSON output |

## Install

```bash
git clone <repo>
cd recon-tool
chmod +x install.sh
./install.sh
source venv/bin/activate
```

## Usage

```bash
# Full scan
python3 recon.py example.com

# Passive only (no active probing)
python3 recon.py example.com --passive

# Custom output dir + threads
python3 recon.py example.com -o results --threads 100

# Skip specific modules
python3 recon.py example.com --skip-ports --skip-fuzz

# Custom wordlist
python3 recon.py example.com --wordlist /usr/share/wordlists/dirb/common.txt

# Only HTML report
python3 recon.py example.com --format html
```

## Options

```
positional:
  domain              Target domain (e.g. example.com)

optional:
  -o, --output        Output directory (default: report)
  --threads N         Number of threads (default: 50)
  --timeout N         Request timeout seconds (default: 10)
  --wordlist FILE     Custom wordlist for directory fuzzing
  --depth N           Scraping crawl depth (default: 2)
  --ports LIST        Comma-separated ports to scan
  --passive           Passive mode only (no active probing)
  --format            Report format: json | html | both (default: both)
  --skip-subdomains   Skip subdomain enumeration
  --skip-fuzz         Skip directory fuzzing
  --skip-scrape       Skip source code scraping
  --skip-secrets      Skip secret hunting
  --skip-ports        Skip port scanning
```

## Output Structure

```
report/
├── report_YYYYMMDD_HHMMSS.html   # Visual HTML report
├── report_YYYYMMDD_HHMMSS.json   # Machine-readable JSON
└── scraped/
    └── <domain>/
        ├── <hash>.html            # Downloaded HTML pages
        └── <hash>_<name>.js      # Downloaded JS files
```

## Secret Patterns Detected

- AWS Access/Secret Keys, Session Tokens
- Google API Keys, GCP Service Accounts
- Azure Storage Keys, SAS Tokens
- GitHub/GitLab Tokens
- Stripe, Twilio, SendGrid API Keys
- Slack Tokens & Webhooks
- JWT Tokens
- RSA/EC/OpenSSH/PGP Private Keys
- Hardcoded passwords, secrets, tokens
- Database connection strings
- S3 Bucket URLs, Firebase URLs
- NPM, Heroku, Mailchimp tokens
- Internal IP addresses

## Passive OSINT Sources

- [crt.sh](https://crt.sh) — Certificate transparency logs
- [HackerTarget](https://hackertarget.com) — Host search API
- [AlienVault OTX](https://otx.alienvault.com) — Threat intelligence
- [RapidDNS](https://rapiddns.io) — DNS lookup
- [URLScan.io](https://urlscan.io) — URL scanning database

## Requirements

- Python 3.8+
- Linux/macOS
