"""Check the Lab 08 classification regexes (same patterns as web_attacks.spl) against the
SYNTHETIC DVWA access log."""

import re
from collections import Counter
from pathlib import Path
from urllib.parse import unquote_plus

LOG = Path(__file__).resolve().parents[1] / "labs" / "08-web-attack-detection" / "samples" / "access.log"

PATTERNS = [
    ("sqli", r"union\s+(all\s+)?select|'\s*or\s*'?1'?\s*=\s*'?1|information_schema|sleep\(|@@version|'\s*--"),
    ("xss", r"<script|javascript:|onerror\s*=|onload\s*=|alert\(|document\.cookie"),
    ("cmd_injection", r"(;|\||&&|`|\$\()\s*(id|whoami|uname|cat\s+/etc/passwd|ls)\b"),
]
LINE = re.compile(r'^(\S+) .*?"GET (\S+) HTTP')


def classify(uri):
    q = unquote_plus(uri).lower()
    for name, rx in PATTERNS:
        if re.search(rx, q):
            return name
    return None


def results():
    out = Counter()
    for line in LOG.read_text().splitlines():
        m = LINE.match(line)
        if m:
            out[(m.group(1), classify(m.group(2)))] += 1
    return out


def test_attacker_requests_classified():
    r = results()
    assert r[("198.51.100.66", "sqli")] == 3
    assert r[("198.51.100.66", "xss")] == 2
    assert r[("198.51.100.66", "cmd_injection")] == 2


def test_normal_dvwa_use_not_flagged():
    r = results()
    for ip in ("192.0.2.40", "192.0.2.41"):
        assert all(cls is None for (src, cls) in r if src == ip)
