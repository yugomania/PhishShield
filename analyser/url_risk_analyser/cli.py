"""Command-line interface: paste a URL, get an explained risk report."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import threat_intel
from .analyser import analyse

_COLOURS = {"high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "none": "\033[32m",
            "confirmed_malicious": "\033[1;41;97m", "bold": "\033[1m", "dim": "\033[2m", "reset": "\033[0m"}


def _c(text: str, key: str, enabled: bool) -> str:
    return f"{_COLOURS[key]}{text}{_COLOURS['reset']}" if enabled else text


def format_report(r: dict, colour: bool = False) -> str:
    v, ti, h = r["verdict"], r["threat_intelligence"], r["heuristics"]
    out = [
        f"URL:    {r['analysed_url']}",
        f"Host:   {r['host_display']}" + (f"  ({r['host']})" if r["host_display"] != r["host"] else ""),
        f"Owner domain: {r['registrable_domain']}" if r["registrable_domain"] else "",
        "",
    ]
    verdict_key = "confirmed_malicious" if v["category"] == "confirmed_malicious" else h["risk_level"]
    out += [_c(f" VERDICT: {v['label'].upper()} ", verdict_key, colour), f"  {v['summary']}", ""]

    out.append(_c("1) Threat intelligence: confirmed malicious destinations", "bold", colour))
    checked = ", ".join(ti["sources_checked"]) or "none"
    if ti["matches"]:
        for m in ti["matches"]:
            out.append(_c(f"   MATCH  {m['source']}: {m['detail']} [{m['matched']}]", "high", colour))
    else:
        out.append(f"   No match (checked: {checked})")
    for err in ti["errors"]:
        out.append(_c(f"   ! could not check {err}", "dim", colour))
    out += [f"   {ti['meaning']}", ""]

    out.append(_c("2) Heuristic risk indicators: warning signs, NOT confirmation", "bold", colour))
    out.append(f"   Risk score: {h['risk_score']}/100 ({_c(h['risk_level'].upper(), h['risk_level'], colour)})")
    if not h["findings"]:
        out.append("   No suspicious characteristics found.")
    for f in h["findings"]:
        out.append(f"   [{_c(f['severity'].upper(), f['severity'], colour)}] {f['title']}")
        out.append(f"       Why it matters: {f['explanation']}")
        out.append(_c(f"       Evidence: {f['evidence']}", "dim", colour))
    out.append(_c(f"   {h['disclaimer']}", "dim", colour))

    for note in r["notes"]:
        out.append(_c(f"\nNote: {note}", "dim", colour))
    return "\n".join(line for i, line in enumerate(out) if line or i)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="url-risk", description="Check a URL for phishing risk.")
    ap.add_argument("urls", nargs="*", help="URL(s) to analyse. If omitted, you'll be prompted.")
    ap.add_argument("--json", action="store_true", help="print machine-readable JSON")
    ap.add_argument("--blocklist", help="path to a custom blocklist file")
    ap.add_argument("--update-feed", action="store_true", help="download the latest OpenPhish feed and exit")
    ap.add_argument("--serve", action="store_true", help="run the local HTTP API for the browser extension")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args(argv)

    if args.update_feed:
        try:
            n = threat_intel.update_feed()
        except Exception as exc:
            print(f"Feed update failed: {exc}", file=sys.stderr)
            return 1
        print(f"Saved {n} URLs to {threat_intel.DEFAULT_FEED}")
        return 0

    sources = threat_intel.default_sources(args.blocklist)

    if args.serve:
        from .server import serve
        serve(port=args.port, sources=sources)
        return 0

    urls = args.urls
    if not urls:
        try:
            urls = [input("Paste a URL to check: ")]
        except (EOFError, KeyboardInterrupt):
            return 1

    colour = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    status = 0
    reports = []
    for url in urls:
        try:
            report = analyse(url, sources)
        except ValueError as exc:
            print(f"Cannot analyse {url!r}: {exc}", file=sys.stderr)
            status = 2
            continue
        reports.append(report)
        if not args.json:
            print(format_report(report, colour))
            print("-" * 72 if len(urls) > 1 else "")
    if args.json:
        print(json.dumps(reports[0] if len(reports) == 1 else reports, indent=2, ensure_ascii=False))
    return status


if __name__ == "__main__":
    sys.exit(main())
