# Lab 01 - SSH Brute Force Detection

## Objective

Generate an SSH password-guessing attack against a Linux target, collect the sshd authentication logs in a SIEM, and build detections for (1) many failures from one source, and (2) a successful login from a source that was just failing, which is the case that matters most.

## Lab setup

| Host | Role | Address |
|---|---|---|
| `attacker` | Kali Linux | 192.0.2.10 |
| `lab-target01` | Ubuntu Server with OpenSSH, Splunk Universal Forwarder or Elastic Agent | 192.0.2.20 |
| `siem` | Splunk Free or Elastic (see docs) | 192.0.2.5 |

1. On the target, create a throwaway account with a weak password (for example `labuser` / a word from a small list). Delete it when the lab is done.
2. Forward `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL) to the SIEM. In Splunk use the Splunk Add-on for Unix and Linux, `sourcetype=linux_secure`, `index=linux`.
3. Confirm ingestion: `index=linux sourcetype=linux_secure sshd | head 5`.

## Attack simulation

> **Authorized use only.** Run these steps only in an isolated lab that you own, against the lab VMs described in [docs/lab-environment.md](../../docs/lab-environment.md). The attack-side commands are standard, publicly documented tool usage for generating telemetry; they are not meant for any other system.

```bash
# 1. Confirm SSH is exposed on the target
nmap -sV -p 22 192.0.2.20

# 2. Password guessing with a short wordlist against one lab account
hydra -l labuser -P small-wordlist.txt -t 4 ssh://192.0.2.20

# 3. Same thing from Metasploit
msfconsole -q -x "use auxiliary/scanner/ssh/ssh_login; set RHOSTS 192.0.2.20; set USERNAME labuser; set PASS_FILE small-wordlist.txt; set STOP_ON_SUCCESS true; run; exit"

# 4. Log in with the recovered password to generate the 'success after failures' event
ssh labuser@192.0.2.20
```

Keep the wordlist small (20-50 entries) and make sure it contains the lab password, so the run ends in a success.

## Log sources required

| Source | Where | Needed for |
|---|---|---|
| sshd auth log | `/var/log/auth.log` or `/var/log/secure` (`linux_secure`) | all rules |
| (optional) journald | `journalctl -u ssh` | systems without rsyslog |

See `samples/auth.log` for a **SYNTHETIC** example of the expected lines.

## Detection logic

- **Brute force:** count `Failed password|publickey|keyboard-interactive` per `src_ip` per 1-minute bucket, and alert at **≥ 5**.
- **Success after failures:** an `Accepted` event from a `src_ip` that had **≥ 5** failures in the previous 30 minutes (`streamstats time_window=30m`). This is the high-severity alert.
- The `Invalid user X from IP` line is not counted, because sshd also logs a matching `Failed password for invalid user X` line and counting both would double-count the attempt.
- The Sigma correlation rule (`event_count`, group-by `src_ip`, 1m, ≥ 5) is the vendor-neutral version. Note that the Splunk conversion uses fixed `bin` buckets, so a burst that straddles a minute boundary can split. The tuned version in Lab 10 widens the window.
- Dashboard: `dashboards/ssh_brute_force_dashboard.xml` (Splunk Simple XML) has failure/success trends, brute-force sources, top usernames, and success-after-failures.

### Detection files

| File | Format |
|---|---|
| [`detections/sigma/ssh_accepted_login.yml`](detections/sigma/ssh_accepted_login.yml) | Sigma |
| [`detections/sigma/ssh_brute_force_correlation.yml`](detections/sigma/ssh_brute_force_correlation.yml) | Sigma |
| [`detections/ssh_brute_force.esql`](detections/ssh_brute_force.esql) | Elastic ES|QL |
| [`detections/ssh_brute_force.kql`](detections/ssh_brute_force.kql) | KQL (Microsoft Sentinel / Defender) |
| [`detections/ssh_brute_force.spl`](detections/ssh_brute_force.spl) | Splunk SPL |
| [`detections/ssh_success_after_failures.spl`](detections/ssh_success_after_failures.spl) | Splunk SPL |
| [`detections/sigma-converted/`](detections/sigma-converted/) | Sigma → SPL / Lucene, produced by `scripts/convert-sigma.sh` |

## MITRE ATT&CK mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force: Password Guessing | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |
| Lateral Movement | Remote Services: SSH | [T1021.004](https://attack.mitre.org/techniques/T1021/004/) |
| Initial Access / Persistence | Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) |

## Tuning notes

- **False positives you should expect:** a user mistyping their password a few times (stays under 5/min); scripts or Ansible runs that use a stale key or password (high volume, one user, from an internal IP); credentialed vulnerability scans.
- Allowlist known scanners and bastions with a lookup, not by editing the search (see Lab 10).
- Internet-facing SSH gets constant background brute force. On such hosts alert only on **success after failures** and send the volume alerts to a report.
- Low-and-slow guessing (1 attempt per few minutes) evades a 1-minute window, so add a daily `stats count by src_ip` report with a higher threshold.

## Response steps

1. Check whether any `Accepted` event came from the source IP. If one did, treat it as a compromised account.
2. Contain: block the source at the host firewall (`ufw deny from <IP>`) or perimeter, and lock or reset the targeted account.
3. Scope: look for the account's sessions (`last`, `who`, `journalctl _COMM=sshd`), new keys in `~/.ssh/authorized_keys`, new cron jobs, and sudo use.
4. Harden: disable password authentication (`PasswordAuthentication no`), disallow root login, and consider fail2ban or rate-limiting.
5. Document the timeline and close with the root cause (weak password, exposed service).

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
| Hydra run: time to first alert | _fill in_ |
| Success-after-failures alert fired? | _fill in_ |

**Evidence:** _add sanitized screenshots or exported results here (documentation IPs only, no real hostnames)._

**What I would change next time:** _fill in_
