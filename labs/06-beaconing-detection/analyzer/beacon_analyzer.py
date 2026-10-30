#!/usr/bin/env python3
"""Time-based beaconing analyzer.

Groups connections by (src_ip, dst_ip, dst_port), then scores how regular the gaps
between connections are. Command-and-control implants usually call home on a timer
(sometimes with jitter), so their inter-arrival times have low dispersion compared
with human-driven traffic.

Input CSV columns (header required): timestamp,src_ip,dst_ip,dst_port[,bytes]
  timestamp: epoch seconds or ISO 8601 (e.g. 2026-03-03T10:00:00)
Export this from Zeek conn.log, Splunk, Elastic, or a firewall log.

Standard library only. Author: Steven Drew. License: MIT.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import statistics
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

Key = Tuple[str, str, str]


@dataclass
class BeaconScore:
    src_ip: str
    dst_ip: str
    dst_port: str
    connections: int
    mean_interval: float
    median_interval: float
    stdev_interval: float
    cv: float              # coefficient of variation = stdev / mean (0 = perfectly regular)
    jitter_pct: float      # median absolute deviation as % of the median interval
    bytes_cv: Optional[float]  # dispersion of payload sizes; implants often send fixed-size check-ins
    score: float           # 0..1, higher = more beacon-like
    beacon: bool


def parse_ts(value: str) -> float:
    value = value.strip()
    try:
        return float(value)
    except ValueError:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def load_csv(rows: Iterable[Dict[str, str]]) -> Dict[Key, List[Tuple[float, Optional[int]]]]:
    flows: Dict[Key, List[Tuple[float, Optional[int]]]] = defaultdict(list)
    for row in rows:
        try:
            ts = parse_ts(row["timestamp"])
            src = str(ipaddress.ip_address(row["src_ip"].strip()))
            dst = str(ipaddress.ip_address(row["dst_ip"].strip()))
        except (KeyError, ValueError):
            continue
        size = row.get("bytes")
        flows[(src, dst, str(row.get("dst_port", "")).strip())].append(
            (ts, int(size) if size and size.strip().isdigit() else None)
        )
    return flows


def _cv(values: Sequence[float]) -> float:
    mean = statistics.fmean(values)
    return statistics.pstdev(values) / mean if mean > 0 else float("inf")


def score_flow(key: Key, events: List[Tuple[float, Optional[int]]], min_connections: int = 10,
               max_cv: float = 0.25, min_interval: float = 5.0) -> Optional[BeaconScore]:
    """Return a BeaconScore, or None if there is too little data to judge."""
    events = sorted(events)
    if len(events) < min_connections:
        return None
    times = [t for t, _ in events]
    gaps = [b - a for a, b in zip(times, times[1:]) if b - a > 0]
    if len(gaps) < min_connections - 1:
        return None
    mean = statistics.fmean(gaps)
    median = statistics.median(gaps)
    stdev = statistics.pstdev(gaps)
    cv = stdev / mean if mean > 0 else float("inf")
    mad = statistics.median([abs(g - median) for g in gaps])
    jitter = 100.0 * mad / median if median > 0 else float("inf")
    sizes = [s for _, s in events if s is not None]
    bytes_cv = _cv(sizes) if len(sizes) >= min_connections else None

    # Interval regularity dominates; consistent payload size and more samples add confidence.
    regularity = max(0.0, 1.0 - cv / (2 * max_cv))
    size_term = 1.0 if bytes_cv is None else max(0.0, 1.0 - min(bytes_cv, 1.0))
    volume = min(1.0, len(gaps) / 50.0)
    score = round(0.7 * regularity + 0.15 * size_term + 0.15 * volume, 3)
    beacon = cv <= max_cv and mean >= min_interval
    return BeaconScore(key[0], key[1], key[2], len(events), round(mean, 2), round(median, 2),
                       round(stdev, 2), round(cv, 3), round(jitter, 1),
                       None if bytes_cv is None else round(bytes_cv, 3), score, beacon)


def analyze(flows: Dict[Key, List[Tuple[float, Optional[int]]]], allow: Iterable[str] = (),
            **kwargs) -> List[BeaconScore]:
    nets = [ipaddress.ip_network(a, strict=False) for a in allow]
    out = []
    for key, events in flows.items():
        if any(ipaddress.ip_address(key[1]) in n for n in nets):
            continue
        s = score_flow(key, events, **kwargs)
        if s:
            out.append(s)
    return sorted(out, key=lambda s: (-s.beacon, -s.score))


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Score connection regularity to find beaconing.")
    p.add_argument("csv", help="connection CSV (or - for stdin)")
    p.add_argument("--min-connections", type=int, default=10)
    p.add_argument("--max-cv", type=float, default=0.25,
                   help="max coefficient of variation of intervals to flag (default 0.25)")
    p.add_argument("--min-interval", type=float, default=5.0,
                   help="ignore flows whose mean gap is below this many seconds")
    p.add_argument("--allow", action="append", default=[], help="destination IP/CIDR to skip")
    p.add_argument("--all", action="store_true", help="show non-beacon flows too")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)

    fh = sys.stdin if a.csv == "-" else open(a.csv, newline="", encoding="utf-8")
    with fh:
        rows = (r for r in csv.DictReader(line for line in fh if not line.startswith("#")))
        results = analyze(load_csv(rows), a.allow, min_connections=a.min_connections,
                          max_cv=a.max_cv, min_interval=a.min_interval)
    shown = [r for r in results if a.all or r.beacon]
    if a.json:
        for r in shown:
            print(json.dumps(asdict(r)))
    else:
        print(f"{'BEACON':6} {'SRC':15} {'DST':15} {'PORT':5} {'N':>4} {'MEAN_S':>8} {'CV':>6} {'JIT%':>6} {'SCORE':>5}")
        for r in shown:
            print(f"{'yes' if r.beacon else 'no':6} {r.src_ip:15} {r.dst_ip:15} {r.dst_port:5} {r.connections:>4} "
                  f"{r.mean_interval:>8} {r.cv:>6} {r.jitter_pct:>6} {r.score:>5}")
    return 1 if any(r.beacon for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
