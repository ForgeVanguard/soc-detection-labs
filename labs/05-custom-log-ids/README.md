# Lab 05 - Custom Log IDS (Python and Bash)

## Objective

Build a small host-based intrusion detector that reads `auth.log` without a SIEM, then show the same logic as SIEM detections. The tool lives in its own repository: **[log-brute-force-detector](https://github.com/ForgeVanguard/log-brute-force-detector)**.

## Lab setup

Same hosts as Lab 01. The tool needs only Python 3.8+ (standard library) or bash + awk on the target or an analysis box.

```bash
git clone https://github.com/ForgeVanguard/log-brute-force-detector
cd log-brute-force-detector
pytest -q                                   # tests use the SYNTHETIC samples
python3 -m lbfd --year 2026 samples/auth.log
bash/ssh-bruteforce-detect.sh samples/auth.log
```

## Attack simulation

> **Authorized use only.** Run these steps only in an isolated lab that you own, against the lab VMs described in [docs/lab-environment.md](../../docs/lab-environment.md). The attack-side commands are standard, publicly documented tool usage for generating telemetry; they are not meant for any other system.

Reuse the Lab 01 Hydra run, plus a spray (one password across many accounts):

```bash
hydra -L lab-users.txt -p 'Winter2026!' -t 2 ssh://192.0.2.20
```

Then run the detector on the target's real log: `sudo python3 -m lbfd /var/log/auth.log`.

## Log sources required

`/var/log/auth.log` or `/var/log/secure`, read locally. JSON output (`--json`) can be forwarded to the SIEM (`lbfd_alerts_ingest.spl`).

## Detection logic

| Rule | Logic | ATT&CK |
|---|---|---|
| `BRUTE_FORCE` | ≥ 5 failures from one IP in a 60 s sliding window | T1110.001 |
| `PASSWORD_SPRAY` | ≥ 5 distinct usernames failing from one IP in 60 s | T1110.003 |
| `SUCCESS_AFTER_FAILURES` | login accepted from an IP flagged above | T1110 → T1021.004 |

The Python version uses a per-IP deque (a true sliding window) and merges a continuous attack into one alert. The shell version is a single awk pass. Both have tests and agree on the sample data. The SIEM versions here use 1-minute buckets.

### Detection files

| File | Format |
|---|---|
| [`detections/lbfd_alerts_ingest.spl`](detections/lbfd_alerts_ingest.spl) | Splunk SPL |
| [`detections/sigma/ssh_password_spray_correlation.yml`](detections/sigma/ssh_password_spray_correlation.yml) | Sigma |
| [`detections/ssh_password_spray.esql`](detections/ssh_password_spray.esql) | Elastic ES|QL |
| [`detections/ssh_password_spray.kql`](detections/ssh_password_spray.kql) | KQL (Microsoft Sentinel / Defender) |
| [`detections/ssh_password_spray.spl`](detections/ssh_password_spray.spl) | Splunk SPL |
| [`detections/sigma-converted/`](detections/sigma-converted/) | Sigma → SPL / Lucene, produced by `scripts/convert-sigma.sh` |

## MITRE ATT&CK mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force: Password Guessing | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |
| Credential Access | Brute Force: Password Spraying | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) |
| Lateral Movement | Remote Services: SSH | [T1021.004](https://attack.mitre.org/techniques/T1021/004/) |

## Tuning notes

- Thresholds are flags (`-t`, `-w`, `-u`), so record what you change and why in Lab 10's tuning log.
- Use the allowlist (`-a 192.0.2.0/28`) for scanners and bastions.
- A sliding window catches bursts that straddle bucket edges, which the SIEM `bin` version can miss. That is a useful comparison to write up.

## Response steps

Same as Lab 01. In addition, the exit code (1 = alerts) lets you run the tool from cron and act on the result, for example by sending the alert to a webhook.

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
| Python vs Bash vs SIEM agreement on your log | _fill in_ |

**Evidence:** _add sanitized screenshots or exported results here (documentation IPs only, no real hostnames)._

**What I would change next time:** _fill in_
