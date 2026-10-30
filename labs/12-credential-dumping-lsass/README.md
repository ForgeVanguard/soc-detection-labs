# Lab 12 - Credential Dumping (LSASS Access)

## Objective

Detect attempts to read LSASS memory, the most common way to steal Windows credentials, using Sysmon process-access (10), process-create (1) and file-create (11) events.

## Lab setup

| Host | Role | Address |
|---|---|---|
| `attacker` | Kali Linux | 192.0.2.10 |
| `dc01` | Windows Server domain controller (lab domain) | 192.0.2.50 |
| `win-target` | Windows 10/11, domain-joined, Sysmon + Universal Forwarder or Elastic Agent | 192.0.2.60 |
| `siem` | Splunk or Elastic | 192.0.2.5 |

The Sysmon config must log **ProcessAccess for `lsass.exe`** (SwiftOnSecurity and sysmon-modular both include it). Test on a **lab VM snapshot**: Defender will block or flag most of these actions. Leave it on and record what it does; that is useful data. Use only lab accounts.

## Attack simulation

> **Authorized use only.** Run these steps only in an isolated lab that you own, against the lab VMs described in [docs/lab-environment.md](../../docs/lab-environment.md). The attack-side commands are standard, publicly documented tool usage for generating telemetry; they are not meant for any other system.

Use only built-in or Microsoft-signed tooling to create the telemetry. No credential-extraction tools are needed, because the detection is on the *access*, not on the parsing.

```powershell
# Elevated PowerShell on win-target (lab VM only). Writes a dump file; delete it afterward.

# 1. ProcDump (Sysinternals, Microsoft-signed)
procdump64.exe -accepteula -ma lsass.exe C:\LabTemp\lsass.dmp

# 2. Built-in comsvcs.dll MiniDump (a living-off-the-land technique)
$id = (Get-Process lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $id C:\LabTemp\l.dmp full

# 3. Task Manager > Details > lsass.exe > Create dump file (GUI path, for comparison)

Remove-Item C:\LabTemp\*.dmp
```

## Log sources required

| Event | Source | Use |
|---|---|---|
| Sysmon 10 | ProcessAccess | handle to `lsass.exe` with `GrantedAccess` |
| Sysmon 1 | ProcessCreate | `procdump -ma lsass`, `comsvcs.dll MiniDump` |
| Sysmon 11 | FileCreate | `.dmp` written |
| Defender 1116/1117 | Microsoft-Windows-Windows Defender/Operational | AV detection of the dump |

`samples/sysmon10_lsass_access.xml` is a **SYNTHETIC** illustration of the event layout.

## Detection logic

- **Sysmon 10:** `TargetImage` ends with `\lsass.exe` and `GrantedAccess` is one of `0x1010`, `0x1410`, `0x1438`, `0x143a`, `0x1fffff` (masks that combine `PROCESS_VM_READ` with query rights), excluding `C:\Windows\System32\*`, Defender paths and `WerFault.exe`.
- **Sysmon 1:** `comsvcs` + `MiniDump` on the command line, or ProcDump (by image or `OriginalFileName`) with `-ma`/`-mm` and `lsass`.
- **Sysmon 11:** `.dmp` created by anything other than WER.
- High fidelity comes from combining them: an access event plus a dump file from the same process within a minute.

### Detection files

| File | Format |
|---|---|
| [`detections/lsass_access.kql`](detections/lsass_access.kql) | KQL (Microsoft Sentinel / Defender) |
| [`detections/lsass_access.spl`](detections/lsass_access.spl) | Splunk SPL |
| [`detections/lsass_dump.eql`](detections/lsass_dump.eql) | Elastic EQL |
| [`detections/lsass_dump_cmdline.spl`](detections/lsass_dump_cmdline.spl) | Splunk SPL |
| [`detections/lsass_dump_file.spl`](detections/lsass_dump_file.spl) | Splunk SPL |
| [`detections/sigma/lsass_access_suspicious.yml`](detections/sigma/lsass_access_suspicious.yml) | Sigma |
| [`detections/sigma/lsass_dump_cmdline.yml`](detections/sigma/lsass_dump_cmdline.yml) | Sigma |
| [`detections/sigma-converted/`](detections/sigma-converted/) | Sigma → SPL / Lucene, produced by `scripts/convert-sigma.sh` |

## MITRE ATT&CK mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | OS Credential Dumping: LSASS Memory | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) |

## Tuning notes

- **FPs:** EDR/AV, backup, and monitoring agents open LSASS legitimately. Allowlist them by **full signed path**, never by file name alone.
- The `System32` exclusion is broad. If you see `rundll32.exe` (which lives in System32) doing comsvcs MiniDump, the **process-create** rule catches it. That is why both rules exist.
- Other masks exist (for example `0x1400`, `0x1000`), but they are mostly benign query-only access. Avoid adding them without data.
- Consider enabling **LSA Protection (RunAsPPL)** and **Credential Guard**, then record how they change what the test produces.

## Response steps

1. Treat as **critical**: assume every credential cached on that host is exposed.
2. Isolate the host. Collect the Sysmon events, the dump file (if it is still present), and the parent process chain.
3. Reset the passwords of every account that has logged on to that host since the last reboot, starting with privileged accounts. For a domain compromise, plan a double `krbtgt` reset.
4. Hunt for the same `SourceImage` or command line across all hosts.

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
