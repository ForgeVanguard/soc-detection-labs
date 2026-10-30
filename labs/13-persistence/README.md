# Lab 13 - Persistence (Scheduled Tasks, Run Keys, Services)

## Objective

Create the three most common Windows persistence mechanisms with built-in commands and harmless payloads, and detect each from Security 4698, System 7045 and Sysmon 13.

## Lab setup

| Host | Role | Address |
|---|---|---|
| `attacker` | Kali Linux | 192.0.2.10 |
| `dc01` | Windows Server domain controller (lab domain) | 192.0.2.50 |
| `win-target` | Windows 10/11, domain-joined, Sysmon + Universal Forwarder or Elastic Agent | 192.0.2.60 |
| `siem` | Splunk or Elastic | 192.0.2.5 |

Enable **Audit Other Object Access Events** (for 4698). Sysmon config must log registry events for `CurrentVersion\Run` (the community configs do).

## Attack simulation

> **Authorized use only.** Run these steps only in an isolated lab that you own, against the lab VMs described in [docs/lab-environment.md](../../docs/lab-environment.md). The attack-side commands are standard, publicly documented tool usage for generating telemetry; they are not meant for any other system.

All payloads below just start Notepad or write a text file. Clean up after each step.

```powershell
# 1. Scheduled task (4698)
schtasks /create /tn "LabUpdater" /tr "C:\Windows\System32\notepad.exe" /sc onlogon /f
schtasks /delete /tn "LabUpdater" /f

# 2. Run key (Sysmon 13)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v LabRun /t REG_SZ /d "C:\Windows\System32\notepad.exe" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v LabRun /f

# 3. Service with a suspicious path (7045). Copy a benign binary to a user-writable folder first.
New-Item -ItemType Directory C:\Users\Public\lab -Force | Out-Null
Copy-Item C:\Windows\System32\notepad.exe C:\Users\Public\lab\labsvc.exe
sc.exe create LabSvc binPath= "C:\Users\Public\lab\labsvc.exe" start= demand
sc.exe delete LabSvc
Remove-Item C:\Users\Public\lab -Recurse
```

## Log sources required

| Event | Channel | Mechanism |
|---|---|---|
| 4698 | Security | scheduled task created (`TaskContent` has the XML with the command) |
| 4702 | Security | scheduled task updated |
| 7045 | System | service installed (`ImagePath`) |
| Sysmon 13 | Sysmon | registry value set (`TargetObject`, `Details`) |
| Sysmon 1 | Sysmon | `schtasks.exe` / `reg.exe` / `sc.exe` command lines |

## Detection logic

- **4698** outside `\Microsoft\` with the `<Command>` and `<Arguments>` extracted from the task XML.
- **Sysmon 13** on `...\CurrentVersion\Run\` and `RunOnce\` (HKLM, HKCU and WOW6432Node).
- **7045** where `ImagePath` is in a user-writable path (`AppData`, `Temp`, `Users\Public`, `ProgramData`) or uses an interpreter (`powershell`, `cmd /c`, `mshta`, `rundll32`).
- The KQL hunt unions all three into one timeline per host.

### Detection files

| File | Format |
|---|---|
| [`detections/new_service_7045.spl`](detections/new_service_7045.spl) | Splunk SPL |
| [`detections/persistence.kql`](detections/persistence.kql) | KQL (Microsoft Sentinel / Defender) |
| [`detections/run_key.eql`](detections/run_key.eql) | Elastic EQL |
| [`detections/run_key_sysmon13.spl`](detections/run_key_sysmon13.spl) | Splunk SPL |
| [`detections/scheduled_task_4698.spl`](detections/scheduled_task_4698.spl) | Splunk SPL |
| [`detections/sigma/registry_run_key_set.yml`](detections/sigma/registry_run_key_set.yml) | Sigma |
| [`detections/sigma/win_scheduled_task_created.yml`](detections/sigma/win_scheduled_task_created.yml) | Sigma |
| [`detections/sigma/win_service_install_suspicious.yml`](detections/sigma/win_service_install_suspicious.yml) | Sigma |
| [`detections/sigma-converted/`](detections/sigma-converted/) | Sigma → SPL / Lucene, produced by `scripts/convert-sigma.sh` |

## MITRE ATT&CK mapping

| Tactic | Technique | ID |
|---|---|---|
| Persistence / Execution | Scheduled Task/Job: Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) |
| Persistence | Create or Modify System Process: Windows Service | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) |

## Tuning notes

- **FPs:** installers and updaters (browsers, drivers, collaboration tools) create tasks, Run keys and services constantly. Build an allowlist of `(name, path, signer)` from a week of normal activity.
- Prioritize entries whose command points at user-writable paths or script interpreters, or that were created by an Office app, a browser, or a script host.
- Expect `ProgramData` to be noisy for 7045. Drop it from the list if your software inventory justifies that, and say so in the tuning log.

## Response steps

1. Get the full command the persistence runs, and hash and examine that file.
2. Find what created it (Sysmon 1 parent chain around the event time).
3. Remove the persistence **after** collecting evidence, then check for other mechanisms on the same host. Attackers usually add more than one.

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
