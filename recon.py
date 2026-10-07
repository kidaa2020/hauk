#!/usr/bin/env python3
"""
ReconHawk - Advanced Pentesting & Bug Bounty Automation Tool
Author: ReconHawk
"""

import argparse
import sys
from modules.subdomains import SubdomainScanner
from modules.fuzzer import DirectoryFuzzer
from modules.scraper import SourceScraper
from modules.secrets import SecretHunter
from modules.portscan import PortScanner
from modules.reporter import Reporter
from modules.utils import banner, color, Colors

def main():
    banner()
    parser = argparse.ArgumentParser(
        description="ReconHawk - Pentesting & Bug Bounty Automation",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument("-o", "--output", default="report", help="Output directory (default: report)")
    parser.add_argument("--threads", type=int, default=50, help="Number of threads (default: 50)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--wordlist", help="Custom wordlist for fuzzing")
    parser.add_argument("--skip-subdomains", action="store_true", help="Skip subdomain enumeration")
    parser.add_argument("--skip-fuzz", action="store_true", help="Skip directory fuzzing")
    parser.add_argument("--skip-scrape", action="store_true", help="Skip source code scraping")
    parser.add_argument("--skip-secrets", action="store_true", help="Skip secret hunting")
    parser.add_argument("--skip-ports", action="store_true", help="Skip port scanning")
    parser.add_argument("--ports", default="21,22,25,53,80,443,445,3306,3389,5432,6379,8080,8443,8888,9200,27017",
                        help="Ports to scan (comma-separated)")
    parser.add_argument("--depth", type=int, default=2, help="Scraping depth (default: 2)")
    parser.add_argument("--passive", action="store_true", help="Passive mode only (no active probing)")
    parser.add_argument("--format", choices=["json","html","both"], default="both", help="Report format")

    args = parser.parse_args()

    reporter = Reporter(args.domain, args.output)
    results = {}

    # 1. Subdomain Enumeration
    if not args.skip_subdomains:
        print(color(f"\n[*] Starting subdomain enumeration for {args.domain}", Colors.CYAN))
        scanner = SubdomainScanner(args.domain, threads=args.threads, timeout=args.timeout, passive=args.passive)
        subdomains = scanner.run()
        results["subdomains"] = subdomains
        print(color(f"[+] Found {len(subdomains)} subdomains", Colors.GREEN))

    # 2. Port Scanning
    if not args.skip_ports and not args.passive:
        targets = [args.domain] + [s["host"] for s in results.get("subdomains", []) if s.get("alive")]
        print(color(f"\n[*] Port scanning {len(targets)} hosts", Colors.CYAN))
        port_scanner = PortScanner(targets[:20], args.ports, threads=args.threads, timeout=args.timeout)
        results["ports"] = port_scanner.run()

    # 3. Directory Fuzzing
    if not args.skip_fuzz:
        targets_to_fuzz = [f"https://{args.domain}", f"http://{args.domain}"]
        if results.get("subdomains"):
            for s in results["subdomains"]:
                if s.get("alive"):
                    targets_to_fuzz.append(s["url"])
        targets_to_fuzz = list(dict.fromkeys(targets_to_fuzz))[:10]
        print(color(f"\n[*] Fuzzing {len(targets_to_fuzz)} targets", Colors.CYAN))
        fuzzer = DirectoryFuzzer(targets_to_fuzz, wordlist=args.wordlist,
                                  threads=args.threads, timeout=args.timeout)
        results["fuzz"] = fuzzer.run()

    # 4. Source Code Scraping
    if not args.skip_scrape:
        scrape_targets = [f"https://{args.domain}"]
        if results.get("subdomains"):
            for s in results["subdomains"]:
                if s.get("alive"):
                    scrape_targets.append(s["url"])
        scrape_targets = list(dict.fromkeys(scrape_targets))[:15]
        print(color(f"\n[*] Scraping source from {len(scrape_targets)} targets", Colors.CYAN))
        scraper = SourceScraper(scrape_targets, depth=args.depth,
                                threads=args.threads, timeout=args.timeout,
                                output_dir=args.output)
        results["scraped"] = scraper.run()

    # 5. Secret Hunting
    if not args.skip_secrets:
        print(color(f"\n[*] Hunting for hardcoded secrets", Colors.CYAN))
        hunter = SecretHunter(args.output)
        results["secrets"] = hunter.run()
        critical = sum(1 for s in results["secrets"] if s.get("severity") == "critical")
        high = sum(1 for s in results["secrets"] if s.get("severity") == "high")
        print(color(f"[+] Found {len(results['secrets'])} secrets ({critical} critical, {high} high)", Colors.RED if results["secrets"] else Colors.GREEN))

    # 6. Generate Report
    print(color(f"\n[*] Generating report...", Colors.CYAN))
    reporter.generate(results, fmt=args.format)
    print(color(f"[+] Report saved to: {args.output}/", Colors.GREEN))

if __name__ == "__main__":
    main()
