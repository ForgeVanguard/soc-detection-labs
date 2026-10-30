# Lab 09 - Network Baseline vs Attack

## Objective

Record a week of normal lab traffic, build a baseline of which hosts talk to which ports and how much, then run the attacks from earlier labs and detect them as **deviations** from the baseline rather than with signatures.

## Lab setup

| Host | Role | Address |
|---|---|---|
| `attacker` | Kali Linux | 192.0.2.10 |
| `lab-target01`, `web01`, `win-target` | normal lab activity (updates, browsing, admin SSH) | 192.0.2.20-40 |
| `sensor` | Zeek on the lab segment | 192.0.2.4 |

You need **at least 7 days** of quiet, normal traffic before the attack window. Write down what normal activity you created (update schedules, scripted browsing) so the baseline is explainable.

## Attack simulation

> **Authorized use only.** Run these steps only in an isolated lab that you own, against the lab VMs described in [docs/lab-environment.md](../../docs/lab-environment.md). The attack-side commands are standard, publicly documented tool usage for generating telemetry; they are not meant for any other system.

Week 1: baseline only. Week 2: repeat a subset of earlier labs at recorded times:

```bash
nmap -sS --top-ports 1000 192.0.2.20                      # Lab 02
hydra -l labuser -P small-wordlist.txt ssh://192.0.2.20    # Lab 01
# Lab 06 beacon loop for 2 hours
# Lab 07 exploit (opens a new port)
```

## Log sources required

Zeek `conn.log` (or firewall logs mapped to CIM `Network_Traffic` / ECS) for both weeks.

## Detection logic

- `baseline_build.spl` saves per `(source host, dest port, proto)`: average daily connections, bytes out, and peer count to `network_baseline.csv`.
- `baseline_deviation.spl` flags three kinds of deviation in the last 24 h: **new port for host**, **connection spike** (> 3× daily average), and **egress volume spike** (> 3× bytes).
- The KQL version uses a `leftanti` join to find host/port pairs never seen in the baseline window.
- Expected: scans and brute force appear as connection spikes or new ports, the beacon appears as a new host/port pair, and the exploit backdoor appears as a new listening port.

### Detection files

| File | Format |
|---|---|
| [`detections/baseline_build.spl`](detections/baseline_build.spl) | Splunk SPL |
| [`detections/baseline_deviation.kql`](detections/baseline_deviation.kql) | KQL (Microsoft Sentinel / Defender) |
| [`detections/baseline_deviation.spl`](detections/baseline_deviation.spl) | Splunk SPL |

## MITRE ATT&CK mapping

| Tactic | Technique | ID |
|---|---|---|
| Discovery | Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) |
| Command and Control | Application Layer Protocol | [T1071](https://attack.mitre.org/techniques/T1071/) |
| Exfiltration | Exfiltration Over C2 Channel | [T1041](https://attack.mitre.org/techniques/T1041/) |

## Tuning notes

- Baselines go stale. Rebuild them on a schedule, and **never include an attack window** in the baseline.
- A 3× multiplier is a starting point, not a rule. Record the distribution (p95/p99) of your own week 1 and pick a threshold from it.
- New software installs and patch days look like new ports or spikes, so annotate those dates.

## Response steps

1. For each deviation, find the process or user behind it on the source host.
2. Classify each deviation as expected change (update the baseline), misconfiguration, or attack (escalate using the matching lab's response steps).

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
| Deviations in week 1 (noise floor) | _fill in_ |
| Attacks visible as deviations in week 2 | _fill in_ |

**Evidence:** _add sanitized screenshots or exported results here (documentation IPs only, no real hostnames)._

**What I would change next time:** _fill in_
