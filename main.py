#!/usr/bin/env python3
"""
Web Vulnerability Scanner + AI Report
Usage: python main.py -u <URL> [options]
"""

import argparse
import asyncio
import json
import logging
import os
import sys

from scanner.crawler import AsyncCrawler
from scanner.ai_reporter import generate_ai_report

# Для экспорта в HTML можно использовать markdown
try:
    import markdown
except ImportError:
    markdown = None


def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%H:%M:%S',
        level=level
    )


def save_results_json(vulns, ai_report, output_base: str):
    data = {
        "vulnerabilities": [v.to_dict() for v in vulns],
        "ai_report": ai_report
    }
    filename = f"{output_base}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"[+] JSON report saved to {filename}")


def save_results_md(vulns, ai_report, output_base: str):
    lines = ["# Web Vulnerability Scan Report", ""]
    lines.append("## Vulnerabilities Found")
    for v in vulns:
        lines.append(f"### {v.vuln_type}")
        lines.append(f"- **URL**: {v.url}")
        lines.append(f"- **Detail**: {v.detail}")
        if v.evidence:
            lines.append(f"- **Evidence**: {v.evidence[:200]}...")
        lines.append("")
    lines.append("## AI Generated Report")
    lines.append(ai_report)
    lines.append("")
    filename = f"{output_base}.md"
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"[+] Markdown report saved to {filename}")


def save_results_html(vulns, ai_report, output_base: str):
    if markdown is None:
        print("[!] Markdown library not installed, skipping HTML report")
        return
    md_content = []
    md_content.append("# Web Vulnerability Scan Report\n")
    md_content.append("## Vulnerabilities Found\n")
    for v in vulns:
        md_content.append(f"### {v.vuln_type}\n")
        md_content.append(f"- **URL**: {v.url}\n")
        md_content.append(f"- **Detail**: {v.detail}\n")
        if v.evidence:
            md_content.append(f"- **Evidence**: {v.evidence[:200]}...\n")
        md_content.append("\n")
    md_content.append("## AI Generated Report\n")
    md_content.append(ai_report)
    html_body = markdown.markdown("\n".join(md_content), extensions=['extra'])
    full_html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Security Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 40px; }}
h1 {{ color: #d32f2f; }}
h2 {{ color: #1976d2; }}
pre {{ background: #f5f5f5; padding: 10px; }}
</style>
</head>
<body>{html_body}</body>
</html>"""
    filename = f"{output_base}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(full_html)
    print(f"[+] HTML report saved to {filename}")


def main():
    parser = argparse.ArgumentParser(description='Web Vulnerability Scanner + AI Report')
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g. http://testphp.vulnweb.com)')
    parser.add_argument('--depth', type=int, default=20, help='Max pages to crawl (default: 20)')
    parser.add_argument('--concurrency', type=int, default=5, help='Number of concurrent requests (default: 5)')
    parser.add_argument('--timeout', type=int, default=10, help='HTTP timeout in seconds (default: 10)')
    parser.add_argument('--output', default='report', help='Base name for output files (default: report)')
    parser.add_argument('--formats', nargs='+', choices=['md', 'json', 'html'], default=['md', 'json'],
                        help='Report formats (default: md and json)')
    parser.add_argument('--no-ai', action='store_true', help='Skip AI report generation')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output (debug)')
    args = parser.parse_args()

    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)

    print(f"[*] Starting scan of {args.url}")
    scanner = AsyncCrawler(
        base_url=args.url,
        max_pages=args.depth,
        concurrency=args.concurrency,
        timeout=args.timeout
    )

    try:
        vulns = asyncio.run(scanner.run())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(1)

    print(f"\n[=== Scanning completed ===]")
    print(f"Pages visited: {len(scanner.visited)}")
    print(f"Vulnerabilities found: {len(vulns)}")
    for v in vulns:
        print(f" - [{v.vuln_type}] {v.url} -> {v.detail[:80]}...")

    # AI report
    ai_report = ""
    if not args.no_ai:
        print("\n[*] Generating AI report via DeepSeek...")
        ai_report = generate_ai_report(vulns, args.url)
        print("\n" + ai_report + "\n")
    else:
        ai_report = "AI report skipped."

    # Save reports
    for fmt in args.formats:
        if fmt == 'json':
            save_results_json(vulns, ai_report, args.output)
        elif fmt == 'md':
            save_results_md(vulns, ai_report, args.output)
        elif fmt == 'html':
            save_results_html(vulns, ai_report, args.output)

    print("[*] All tasks completed.")


if __name__ == "__main__":
    main()
