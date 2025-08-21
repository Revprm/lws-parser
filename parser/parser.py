#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from typing import Iterator, List

from .enrichment import GeoIPEnricher
from .report import print_human, write_csv, write_json
from .rules import Alert, RuleEngine
from .utils import LogEvent, parse_line


def iter_events(files: List[Path], fmt: str) -> Iterator[LogEvent]:
    for fp in files:
        with fp.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                ev = parse_line(line, fmt=fmt)
                if ev:
                    yield ev


def apply_enrichment(alerts: List[Alert], enricher: GeoIPEnricher):
    if not alerts:
        return
    for a in alerts:
        info = enricher.lookup(a.ip) if enricher else {}
        a.details.update(info)


def main():
    ap = argparse.ArgumentParser(
        description="Custom Log Parser for Blue-Team detections (Apache/Nginx)."
    )
    ap.add_argument(
        "--log", "-l", nargs="+", required=True, help="Path(s) to log files"
    )
    ap.add_argument(
        "--format",
        choices=["auto", "apache", "nginx"],
        default="auto",
        help="Log format",
    )
    ap.add_argument(
        "--out-json", default="outputs/alerts.json", help="Alerts JSON output path"
    )
    ap.add_argument("--out-csv", default="", help="Optional CSV output path")
    ap.add_argument(
        "--geoip-db", default="", help="Path to MaxMind GeoLite2-City.mmdb (optional)"
    )
    ap.add_argument(
        "--bf-threshold",
        type=int,
        default=10,
        help="Brute force threshold within window",
    )
    ap.add_argument(
        "--bf-window", type=int, default=60, help="Brute force window seconds"
    )
    ap.add_argument(
        "--burst5xx", type=int, default=30, help="5xx burst threshold within window"
    )
    ap.add_argument(
        "--burst5xx-window", type=int, default=60, help="5xx burst window seconds"
    )
    ap.add_argument("--print", action="store_true", help="Print human summary")
    args = ap.parse_args()

    files = [Path(p) for p in args.log]
    engine = RuleEngine(
        brute_force_threshold=args.bf_threshold,
        brute_force_window_sec=args.bf_window,
        burst_5xx_threshold=args.burst5xx,
        burst_5xx_window_sec=args.burst5xx_window,
    )
    events = iter_events(files, fmt=args.format)
    alerts = engine.run(events)

    enricher = GeoIPEnricher(args.geoip_db) if args.geoip_db else None
    if enricher:
        apply_enrichment(alerts, enricher)
        enricher.close()

    write_json(alerts, Path(args.out_json))
    if args.out_csv:
        write_csv(alerts, Path(args.out_csv))
    if args.print:
        print_human(alerts)
    else:
        print(
            f"[+] {len(alerts)} alerts written to {args.out_json}"
            + (f" and {args.out_csv}" if args.out_csv else "")
        )


if __name__ == "__main__":
    main()
