# Lab 10 - Detection Rule Tuning

## Objective

Take a noisy rule from Lab 01, measure its alert volume against normal activity, tune it step by step, and document every change with its reason and its effect. This lab produces a **tuning log**, which is the evidence that a detection is maintained.

## Lab setup

Run the Lab 01 search (`ssh_brute_force_v1.spl`) as a scheduled saved search for a week of normal activity plus a few repeats of the Lab 01 attack. Then do the same with `ssh_brute_force_v2.spl`. Create the lookup from `detections/ssh_allowlist.csv` (Settings > Lookups).

## Attack simulation

> **Authorized use only.** Run these steps only in an isolated lab that you own, against the lab VMs described in [docs/lab-environment.md](../../docs/lab-environment.md). The attack-side commands are standard, publicly documented tool usage for generating telemetry; they are not meant for any other system.

Re-run the Lab 01 Hydra attack 3-5 times during the measurement window so you can confirm the tuned rule still catches it (true-positive retention).

## Log sources required

Same as Lab 01, plus Splunk's `_audit` index for fired-alert counts (`alert_volume_compare.spl`).

## Detection logic

| Version | Change | Why |
|---|---|---|
| v1 | ≥ 5 failures / 1 min / src | Lab 01 baseline rule |
| v2 | allowlist lookup (scanner, bastion) | known benign sources with an owner and review date |
| v2 | 5-minute window, ≥ 10 failures | catches slower guessing, merges split bursts |
| v2 | severity: success = high, ≥ 5 users = medium | the analyst sees the important alert first |

The Sigma pair (`ssh_brute_force_tuned_correlation.yml`) is the vendor-neutral v2: a filter on known sources, and an `event_count` ≥ 10 in 5 m.

**Tuning log template:** copy this table into `tuning-log.md` and add a row per change.

| Date | Rule | Change | Reason | Alerts/week before | Alerts/week after | TPs retained? |
|---|---|---|---|---|---|---|
| _fill in_ | | | | | | |

### Detection files

| File | Format |
|---|---|
| [`detections/alert_volume_compare.spl`](detections/alert_volume_compare.spl) | Splunk SPL |
| [`detections/sigma/ssh_brute_force_tuned_correlation.yml`](detections/sigma/ssh_brute_force_tuned_correlation.yml) | Sigma |
| [`detections/ssh_allowlist.csv`](detections/ssh_allowlist.csv) | Lookup (allowlist) |
| [`detections/ssh_brute_force_v1.spl`](detections/ssh_brute_force_v1.spl) | Splunk SPL |
| [`detections/ssh_brute_force_v2.spl`](detections/ssh_brute_force_v2.spl) | Splunk SPL |
| [`detections/sigma-converted/`](detections/sigma-converted/) | Sigma → SPL / Lucene, produced by `scripts/convert-sigma.sh` |

## MITRE ATT&CK mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force: Password Guessing | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |
| — | Applies to all labs (method) | [T1110](https://attack.mitre.org/techniques/T1110/) |

## Tuning notes

Principles used here:
- **Tune with data**, not guesses: measure volume before and after each change, one change at a time.
- **Allowlist narrowly** (exact IPs, with an owner and an expiry), and never allowlist a whole subnet to silence noise.
- **Re-test the attack after every change.** A quiet rule that misses the attack is worse than a noisy one.
- Prefer **severity tiers** to raising thresholds until real attacks disappear.

## Response steps

1. When a new false-positive source appears, investigate it first, then decide: allowlist (with a reason), adjust logic, or accept the noise.
2. Review the allowlist on its `review_by` date, and remove entries that are no longer needed.

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
| v1 alerts in measurement window | _fill in_ |
| v2 alerts in measurement window | _fill in_ |
| Attack repeats caught by v1 / v2 | _fill in_ |

**Evidence:** _add sanitized screenshots or exported results here (documentation IPs only, no real hostnames)._

**What I would change next time:** _fill in_
