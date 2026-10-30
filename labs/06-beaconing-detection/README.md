# Lab 06 - Beaconing Detection (Time-Based)

## Objective

Detect command-and-control beaconing by how *regular* a host's connections to one destination are, rather than by signatures. Includes a working Python analyzer with tests, run against a SYNTHETIC connection CSV.

## Lab setup

| Host | Role | Address |
|---|---|---|
| `attacker` | Kali Linux | 192.0.2.10 |
| `lab-target01` | Linux or Windows target that will run a simulated beacon | 192.0.2.20 |
| `sensor` | Zeek on the lab segment | 192.0.2.4 |

The analyzer needs only Python 3.8+. Tests: `pytest labs/06-beaconing-detection/tests`.

## Attack simulation

> **Authorized use only.** Run these steps only in an isolated lab that you own, against the lab VMs described in [docs/lab-environment.md](../../docs/lab-environment.md). The attack-side commands are standard, publicly documented tool usage for generating telemetry; they are not meant for any other system.

Simulate a beacon with a harmless loop, with no implant or payload: a periodic HTTP request with jitter to a lab web server on the attacker VM.

```bash
# Attacker: simple web server to receive the requests
python3 -m http.server 8080

# Target: request every 60 s +/- 10 % (Ctrl+C to stop; run for 1-2 hours)
while true; do curl -s -o /dev/null http://192.0.2.10:8080/check; sleep $((54 + RANDOM % 13)); done
```

If you also run an adversary-emulation framework in your lab, use its sleep/jitter settings and compare the results.

## Log sources required

| Source | Fields |
|---|---|
| Zeek `conn.log` (best) | `ts`, `id.orig_h`, `id.resp_h`, `id.resp_p`, `orig_bytes` |
| Firewall / proxy logs | time, src, dest, dest port, bytes |

Export to CSV with `timestamp,src_ip,dst_ip,dst_port,bytes` for the analyzer. `samples/connections.csv` is **SYNTHETIC** (`samples/generate_connections.py`, fixed seed) and has: a 60 s ±10 % beacon, a 300 s beacon, periodic NTP (a benign periodic flow), human browsing, and a flow with too few connections.

## Detection logic

For each `(src, dst, port)` flow with ≥ 10 connections:

- **Inter-arrival gaps** between consecutive connections.
- **Coefficient of variation (CV)** = stdev / mean of gaps. A timer gives CV near 0, and humans give CV > 1. Flag at **CV ≤ 0.25** and mean gap ≥ 5 s.
- **Jitter %** = median absolute deviation / median gap. It is robust to a few missed check-ins.
- **Payload size CV.** Implants often send same-size check-ins.
- **Score** (0-1) combines the three for ranking; the `beacon` flag uses CV only.

```bash
python3 labs/06-beaconing-detection/analyzer/beacon_analyzer.py --all labs/06-beaconing-detection/samples/connections.csv
python3 labs/06-beaconing-detection/analyzer/beacon_analyzer.py --allow 192.0.2.1/32 --json conn.csv
```

The SPL and KQL versions compute the same CV with `streamstats` and `prev()`.

### Detection files

| File | Format |
|---|---|
| [`detections/beaconing.kql`](detections/beaconing.kql) | KQL (Microsoft Sentinel / Defender) |
| [`detections/beaconing.spl`](detections/beaconing.spl) | Splunk SPL |

## MITRE ATT&CK mapping

| Tactic | Technique | ID |
|---|---|---|
| Command and Control | Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) |
| Command and Control | Non-Application Layer Protocol | [T1095](https://attack.mitre.org/techniques/T1095/) |
| Exfiltration | Scheduled Transfer | [T1029](https://attack.mitre.org/techniques/T1029/) |

## Tuning notes

- **Expected FPs:** NTP, update checks, telemetry agents, monitoring, mail polling, and cloud sync. These are periodic by design (the sample includes NTP to show this). Allowlist by destination with a documented reason.
- **Heavy jitter** (50 %+) pushes CV above 0.25. Try `--max-cv 0.5` together with the size-CV and long-duration signals, at the cost of more noise.
- **Sleep longer than your data window** (for example a 6-hour sleep) needs days of data and a lower `--min-connections`.
- Run per destination *domain* (from DNS/proxy logs) as well as per IP, because C2 behind a CDN rotates IPs.

## Response steps

1. Identify the process making the connections on the source host (Sysmon 3 / `ss -tnp` / EDR).
2. Look up the destination's reputation, registration age, and whether other internal hosts talk to it.
3. If the traffic is malicious: isolate the host, block the destination, collect memory and disk triage, and hunt the destination across all hosts.

## Results

> **Not filled in yet.** This section is a template. Complete it after running the lab in your own environment. Record only what you actually observed.

| Item | Value |
|---|---|
| Date run | _fill in_ |
| SIEM / version | _fill in_ |
| Attack runs executed | _fill in_ |
| Alerts fired (true positives) | _fill in_ |
| Missed attack runs (false negatives) | _fill in_ |
| False positives before tuning | _fill in_ |
| False positives after tuning | _fill in_ |
| Mean time from attack to alert | _fill in_ |
| Analyzer output on your capture (CV, jitter) | _fill in_ |

**Evidence:** _add sanitized screenshots or exported results here (documentation IPs only, no real hostnames)._

**What I would change next time:** _fill in_
