"""Regenerate samples/connections.csv. SYNTHETIC data, documentation IP ranges only, fixed seed."""

import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

rng = random.Random(1337)
start = datetime(2026, 3, 3, 10, 0, 0)
rows = []


def add(t, src, dst, port, size):
    rows.append((t.strftime("%Y-%m-%dT%H:%M:%S"), src, dst, port, size))


# 1) Simulated implant: 60 s sleep with +/-10% jitter, fixed-ish check-in size.
t = start
while t < start + timedelta(hours=2):
    add(t, "192.0.2.50", "203.0.113.80", 443, 310 + rng.randint(-8, 8))
    t += timedelta(seconds=60 * (1 + rng.uniform(-0.10, 0.10)))

# 2) Simulated slow beacon: 300 s, almost no jitter, plain HTTP.
t = start + timedelta(seconds=17)
while t < start + timedelta(hours=2):
    add(t, "192.0.2.51", "198.51.100.200", 80, 512)
    t += timedelta(seconds=300 + rng.uniform(-3, 3))

# 3) Benign but periodic: time sync every 64 s (expected false positive -> allowlist).
t = start + timedelta(seconds=5)
while t < start + timedelta(hours=2):
    add(t, "192.0.2.20", "192.0.2.1", 123, 90)
    t += timedelta(seconds=64)

# 4) Human browsing: bursts of requests with long, irregular pauses.
t = start
while t < start + timedelta(hours=2):
    for _ in range(rng.randint(3, 12)):
        add(t, "192.0.2.30", "198.51.100.10", 443, rng.randint(400, 90000))
        t += timedelta(seconds=rng.uniform(0.2, 4))
    t += timedelta(seconds=rng.expovariate(1 / 240))

# 5) Too few connections to judge.
for i in range(4):
    add(start + timedelta(minutes=13 * i), "192.0.2.31", "198.51.100.11", 22, 2000)

rows.sort()
out = Path(__file__).with_name("connections.csv")
with out.open("w", newline="") as fh:
    fh.write("# SYNTHETIC SAMPLE DATA - documentation IP ranges, created for testing\n")
    w = csv.writer(fh)
    w.writerow(["timestamp", "src_ip", "dst_ip", "dst_port", "bytes"])
    w.writerows(rows)
print(f"wrote {len(rows)} rows to {out.name}")
