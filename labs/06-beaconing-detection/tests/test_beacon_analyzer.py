"""Tests against the SYNTHETIC samples/connections.csv."""

import csv
import subprocess
import sys
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB / "analyzer"))

import beacon_analyzer as ba  # noqa: E402

CSV = LAB / "samples" / "connections.csv"


def results(**kw):
    with CSV.open(newline="") as fh:
        rows = csv.DictReader(l for l in fh if not l.startswith("#"))
        return {(r.src_ip, r.dst_ip): r for r in ba.analyze(ba.load_csv(rows), **kw)}


def test_jittered_beacon_flagged():
    r = results()[("192.0.2.50", "203.0.113.80")]
    assert r.beacon and 55 <= r.mean_interval <= 65 and r.cv < 0.1


def test_slow_beacon_flagged():
    assert results()[("192.0.2.51", "198.51.100.200")].beacon


def test_periodic_benign_is_flagged_until_allowlisted():
    assert results()[("192.0.2.20", "192.0.2.1")].beacon
    assert ("192.0.2.20", "192.0.2.1") not in results(allow=["192.0.2.1/32"])


def test_human_browsing_not_flagged():
    assert not results()[("192.0.2.30", "198.51.100.10")].beacon


def test_too_few_connections_skipped():
    assert ("192.0.2.31", "198.51.100.11") not in results()


def test_strict_cv_drops_jittered_beacon():
    assert not results(max_cv=0.01)[("192.0.2.50", "203.0.113.80")].beacon


def test_perfect_timer_scores_high():
    flows = {("192.0.2.9", "203.0.113.9", "443"): [(i * 30.0, 200) for i in range(40)]}
    r = ba.analyze(flows)[0]
    assert r.beacon and r.cv == 0 and r.score > 0.9


def test_parse_ts_formats():
    assert ba.parse_ts("0") == 0.0
    assert ba.parse_ts("1970-01-01T00:00:10Z") == 10.0


def test_cli_exit_code():
    res = subprocess.run([sys.executable, str(LAB / "analyzer" / "beacon_analyzer.py"), str(CSV)],
                         capture_output=True, text=True)
    assert res.returncode == 1 and "203.0.113.80" in res.stdout and "198.51.100.10" not in res.stdout
