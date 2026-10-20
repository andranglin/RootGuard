#!/usr/bin/env python3
"""Check schema, timestamps, identifiers and source coverage for RootGuard case-study CSVs."""
from collections import Counter
from datetime import datetime
from pathlib import Path
import csv
import sys

ROOT = Path(__file__).parent
FILES = [
    ROOT / "cs-01-phishing" / "extended-evidence.csv",
    ROOT / "cs-02-lateral-movement" / "extended-evidence.csv",
]
COLUMNS = [
    "event_id", "time_utc", "source", "asset", "identity", "source_ip",
    "target", "activity", "outcome", "correlation_id", "detail", "reliability",
]

def check(path):
    errors = []
    with path.open(newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        if reader.fieldnames != COLUMNS:
            errors.append("schema mismatch")
        rows = list(reader)
    ids = [r["event_id"] for r in rows]
    if len(ids) != len(set(ids)):
        errors.append("duplicate event IDs")
    times = []
    for row in rows:
        try:
            times.append(datetime.fromisoformat(row["time_utc"].replace("Z", "+00:00")))
        except ValueError:
            errors.append(f"invalid UTC timestamp: {row['event_id']}")
        if any(not row.get(k) for k in ("source", "asset", "activity", "detail")):
            errors.append(f"missing required value: {row['event_id']}")
    if times != sorted(times):
        errors.append("out-of-order timestamps")
    sources = Counter(r["source"] for r in rows)
    print(f"{path.relative_to(ROOT)}: {len(rows)} events; sources={dict(sources)}")
    return errors

def main():
    problems = []
    for path in FILES:
        if not path.exists():
            problems.append(f"{path.name} missing")
        else:
            problems += [f"{path}: {msg}" for msg in check(path)]
    if problems:
        for problem in problems:
            print("ERROR:", problem, file=sys.stderr)
        return 1
    print("Dataset integrity checks passed. This does NOT validate forensic realism.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
