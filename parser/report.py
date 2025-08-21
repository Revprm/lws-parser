import csv
import json
from pathlib import Path
from typing import List, Dict
from .rules import Alert


def write_json(alerts: List[Alert], path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump([a.__dict__ for a in alerts], f, indent=2)


def write_csv(alerts: List[Alert], path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["type", "severity", "ts", "ip", "details"]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for a in alerts:
            w.writerow(
                {
                    "type": a.type,
                    "severity": a.severity,
                    "ts": a.ts,
                    "ip": a.ip,
                    "details": json.dumps(a.details, ensure_ascii=False),
                }
            )


def summarize(alerts: List[Alert]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for a in alerts:
        counts[a.type] = counts.get(a.type, 0) + 1
    return counts


def print_human(alerts: List[Alert]):
    if not alerts:
        print("No alerts generated.")
        return
    print(f"Generated {len(alerts)} alerts:")
    by_type = summarize(alerts)
    for t, c in sorted(by_type.items(), key=lambda x: (-x[1], x[0])):
        print(f"  - {t}: {c}")
