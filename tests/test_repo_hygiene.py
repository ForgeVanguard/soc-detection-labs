"""Repository checks: sample data is labelled SYNTHETIC and every IPv4 address in the repo
is a documentation (RFC 5737), loopback, or well-known placeholder address."""

import ipaddress
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEXT = {".md", ".yml", ".spl", ".kql", ".eql", ".esql", ".txt", ".csv", ".log", ".xml", ".py", ".sh", ".json"}
ALLOWED = [ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",  # RFC 5737 documentation ranges
    "127.0.0.0/8", "0.0.0.0/32", "255.255.255.255/32",
)]
IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")


def files():
    for p in ROOT.rglob("*"):
        if p.is_file() and p.suffix in TEXT and ".git" not in p.parts and ".pytest_cache" not in p.parts:
            yield p


def test_only_documentation_ips():
    bad = []
    for p in files():
        for m in IPV4.finditer(p.read_text(encoding="utf-8", errors="ignore")):
            try:
                ip = ipaddress.ip_address(m.group(1))
            except ValueError:
                continue  # not a valid address (for example 999.1.1.1)
            if not any(ip in n for n in ALLOWED):
                bad.append(f"{p.relative_to(ROOT)}: {ip}")
    assert not bad, "non-documentation IPs found:\n" + "\n".join(bad)


def test_samples_are_labelled_synthetic():
    unlabelled = [str(p.relative_to(ROOT)) for p in ROOT.glob("labs/*/samples/*")
                  if p.is_file() and p.suffix != ".py" and "SYNTHETIC" not in p.read_text(encoding="utf-8")[:300]]
    assert not unlabelled, unlabelled


def test_every_lab_readme_has_required_sections():
    required = ["## Objective", "## Lab setup", "## Attack simulation", "## Log sources required",
                "## Detection logic", "## MITRE ATT&CK mapping", "## Tuning notes", "## Response steps", "## Results"]
    for readme in sorted(ROOT.glob("labs/*/README.md")):
        text = readme.read_text(encoding="utf-8")
        missing = [s for s in required if s not in text]
        assert not missing, f"{readme.parent.name} missing {missing}"
