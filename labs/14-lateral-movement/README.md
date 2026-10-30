# Lab 14 - Lateral Movement (PsExec / WMI) - Optional

## Objective

Move from one lab Windows host to another with PsExec and WMI using a lab admin account, and detect it on the *destination* host from 4624 type 3, 5140/5145 share access, 7045 service installs, and WmiPrvSE child processes.

## Lab setup

| Host | Role | Address |
|---|---|---|
| `attacker` | Kali Linux | 192.0.2.10 |
| `dc01` | Windows Server domain controller (lab domain) | 192.0.2.50 |
| `win-target` | Windows 10/11, domain-joined, Sysmon + Universal Forwarder or Elastic Agent | 192.0.2.60 |
| `siem` | Splunk or Elastic | 192.0.2.5 |
| `win-target2` | second domain-joined Windows host | 192.0.2.61 |

Enable **Audit File Share** and **Audit Detailed File Share** (5140/5145) on the destination. These are noisy, so enable them for the lab and evaluate the volume.

## Attack simulation

> **Authorized use only.** Run these steps only in an isolated lab that you own, against the lab VMs described in [docs/lab-environment.md](../../docs/lab-environment.md). The attack-side commands are standard, publicly documented tool usage for generating telemetry; they are not meant for any other system.

```powershell
# From win-target (192.0.2.60) as a lab admin account, against win-target2 (192.0.2.61)

# PsExec (Sysinternals): creates PSEXESVC service via ADMIN$
psexec.exe \\192.0.2.61 -accepteula cmd /c "hostname & whoami"

# WMI remote process creation
wmic /node:192.0.2.61 process call create "cmd.exe /c hostname > C:\Windows\Temp\lab.txt"
Invoke-CimMethod -ComputerName 192.0.2.61 -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine='cmd.exe /c whoami'}
```

From Kali, the Impacket equivalents (`impacket-psexec`, `impacket-wmiexec`) produce similar events with different service names. Comparing them is a good extension.

## Log sources required

| Event | Channel (destination) | Signal |
|---|---|---|
| 4624 LogonType 3 | Security | network logon by the admin account |
| 4672 | Security | special privileges assigned to that logon |
| 5140 / 5145 | Security | `\\*\ADMIN$`, `\\*\IPC$`, pipes `PSEXESVC-*-stdin/stdout/stderr`, `svcctl` |
| 7045 | System | `PSEXESVC` service installed |
| Sysmon 1 | Sysmon | `WmiPrvSE.exe` → `cmd.exe` / `powershell.exe` |

## Detection logic

- **PsExec chain** (`psexec_chain.spl`): network logon + admin share access + PSEXESVC service install on one host within 2 minutes.
- **Admin share + service pipes** (Sigma `win_admin_share_psexec_pipe`): 5145 on `ADMIN$`/`IPC$` with PsExec-style pipe names or `svcctl`.
- **WMI exec** (Sigma `win_wmi_remote_exec`, EQL): `WmiPrvSE.exe` parent starting a shell.
- **Fan-out** (`network_logon_fanout.spl`): one account making type 3 logons to ≥ 3 hosts in 15 minutes.

### Detection files

| File | Format |
|---|---|
| [`detections/lateral_movement.kql`](detections/lateral_movement.kql) | KQL (Microsoft Sentinel / Defender) |
| [`detections/network_logon_fanout.spl`](detections/network_logon_fanout.spl) | Splunk SPL |
| [`detections/psexec_chain.spl`](detections/psexec_chain.spl) | Splunk SPL |
| [`detections/sigma/win_admin_share_psexec_pipe.yml`](detections/sigma/win_admin_share_psexec_pipe.yml) | Sigma |
| [`detections/sigma/win_psexec_service.yml`](detections/sigma/win_psexec_service.yml) | Sigma |
| [`detections/sigma/win_wmi_remote_exec.yml`](detections/sigma/win_wmi_remote_exec.yml) | Sigma |
| [`detections/wmi_exec.eql`](detections/wmi_exec.eql) | Elastic EQL |
| [`detections/wmi_exec.spl`](detections/wmi_exec.spl) | Splunk SPL |
| [`detections/sigma-converted/`](detections/sigma-converted/) | Sigma → SPL / Lucene, produced by `scripts/convert-sigma.sh` |

## MITRE ATT&CK mapping

| Tactic | Technique | ID |
|---|---|---|
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) |
| Execution | System Services: Service Execution | [T1569.002](https://attack.mitre.org/techniques/T1569/002/) |
| Execution | Windows Management Instrumentation | [T1047](https://attack.mitre.org/techniques/T1047/) |
| Defense Evasion / Lateral Movement | Valid Accounts: Domain Accounts | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) |

## Tuning notes

- **FPs:** IT staff using PsExec, SCCM/Intune, backup agents, and monitoring that uses WMI. Allowlist by source admin workstation and account, and require that admin activity come from known jump hosts.
- Renamed PsExec (`-r` flag) changes the service name, so the pipe-name and ADMIN$ signals still apply.
- 5145 is high volume on file servers. Scope it to `ADMIN$`/`IPC$` and to workstations only.

## Response steps

1. Identify the source host and account. Was this an admin doing their job?
2. If not, treat both hosts as compromised. Look at what ran on the destination (child processes of `PSEXESVC.exe` or `WmiPrvSE.exe`).
3. Disable or reset the account and look for where its credentials were stolen (Lab 12 on the source host).
4. Restrict admin logons with tiering, LAPS for local admin passwords, and host firewall rules for SMB/WMI between workstations.

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
