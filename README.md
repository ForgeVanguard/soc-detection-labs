# SOC Detection Labs

Hands-on detection engineering and threat hunting labs. Each lab follows the same loop:

```
  simulate  ──►  collect  ──►  detect  ──►  tune
  (attack in an     (logs into     (SPL / KQL /    (measure FPs,
   isolated lab)     a SIEM)        EQL / Sigma)     document changes)
      ▲                                                  │
      └──────────────────────────────────────────────────┘
```

Every lab ships its **detections as code** (Splunk SPL, Microsoft Sentinel/Defender KQL, Elastic EQL/ES|QL, and Sigma), an **ATT&CK mapping**, **tuning notes with expected false positives**, **response steps**, and a **Results template** that I fill in only with what I actually observed.

> **Status:** detection content is written and validated offline (Sigma checked and converted with sigma-cli; Python analyzers tested with pytest; scripts pass shellcheck). The **Results** sections are intentionally blank templates until each lab is run end-to-end in my lab, so this repo contains no claimed detection rates or metrics.

## Architecture

All addresses are RFC 5737 documentation ranges and hostnames are generic. See [docs/lab-environment.md](docs/lab-environment.md) for setup.

```
                       isolated lab network 192.0.2.0/24 (host-only)
 ┌──────────────┐        ┌──────────────────┐      ┌──────────────────────────┐
 │ attacker     │ ─────► │ lab-target01     │      │ dc01 192.0.2.50          │
 │ Kali         │        │ Linux: SSH, DVWA │      │ win-target 192.0.2.60    │
 │ 192.0.2.10   │ ─────► │ 192.0.2.20       │      │ win-target2 192.0.2.61   │
 └──────────────┘   │    ├──────────────────┤      │ Sysmon + audit policy    │
                    └──► │ vuln-target      │      └────────────┬─────────────┘
                         │ Metasploitable 2 │                   │
                         │ 192.0.2.30       │                   │
                         └────────┬─────────┘                   │
             span / tap           │ syslog, Sysmon, agents      │ forwarders / Elastic Agent
          ┌───────────────┐       ▼                             ▼
          │ sensor (Zeek) │ ──► ┌──────────────────────────────────────┐
          │ 192.0.2.4     │     │ siem: Splunk Free or Elastic         │
          └───────────────┘     │ 192.0.2.5  dashboards, alerts        │
                                └──────────────────────────────────────┘
```

## Lab index

| # | Lab | Focus | ATT&CK | Tools |
|---|---|---|---|---|
| 01 | [SSH brute force](labs/01-ssh-brute-force) | password guessing, success-after-failures, dashboard | T1110.001, T1021.004, T1078 | Kali, Hydra, Metasploit, Nmap, Splunk |
| 02 | [Port scan detection](labs/02-port-scan-detection) | distinct-port counting per source | T1046, T1595.001 | Nmap, Zeek, Splunk/ELK |
| 03 | [Reverse shell](labs/03-reverse-shell-detection) | command-line + network + packet views | T1059.004, T1095 | Netcat, Wireshark, Sysmon for Linux |
| 04 | [SOC attack chain](labs/04-soc-attack-chain-simulation) | scan → exploit → shell → C2, incident timeline | T1046, T1190, T1059.004, T1071, T1095 | Nmap, DVWA, Netcat, Zeek, Splunk |
| 05 | [Custom log IDS](labs/05-custom-log-ids) | Python + Bash detector, SIEM parity | T1110.001, T1110.003, T1021.004 | [log-brute-force-detector](https://github.com/ForgeVanguard/log-brute-force-detector) |
| 06 | [Beaconing](labs/06-beaconing-detection) | interval regularity (CV, jitter) analyzer | T1071.001, T1095, T1029 | Python, Zeek, Splunk/KQL |
| 07 | [Exploitation visibility](labs/07-exploitation-visibility) | raw logs vs SIEM comparison | T1190, T1210, T1059.004 | Metasploit, Metasploitable 2, Zeek |
| 08 | [Web attacks (DVWA)](labs/08-web-attack-detection) | SQLi, XSS, command injection | T1190, T1059.004, T1189 | DVWA, Apache logs, ModSecurity |
| 09 | [Baseline vs attack](labs/09-network-baseline-vs-attack) | deviation from a known-good week | T1046, T1071, T1041 | Zeek, Splunk lookups, KQL |
| 10 | [Rule tuning](labs/10-detection-rule-tuning) | v1 → v2 with a tuning log | T1110.001 (method for all) | Splunk, Sigma |
| 11 | [Windows password spraying](labs/11-windows-password-spraying) | 4625 / 4776 / 4771 spray vs brute force | T1110.003, T1110.001 | CrackMapExec/NetExec, Kerbrute, Hydra |
| 12 | [Credential dumping (LSASS)](labs/12-credential-dumping-lsass) | Sysmon 10 access masks, Sysmon 1/11 | T1003.001 | ProcDump, comsvcs.dll, Sysmon |
| 13 | [Persistence](labs/13-persistence) | scheduled tasks, Run keys, services | T1053.005, T1547.001, T1543.003 | schtasks, reg, sc, Sysmon |
| 14 | [Lateral movement](labs/14-lateral-movement) *(optional)* | PsExec, WMI, admin shares | T1021.002, T1569.002, T1047, T1078.002 | PsExec, WMI, Impacket |

## ATT&CK coverage matrix

| Tactic | Technique | Labs | Primary data source |
|---|---|---|---|
| Reconnaissance | T1595.001 Active Scanning: IP Blocks | 02 | Zeek conn / firewall |
| Initial Access | T1190 Exploit Public-Facing Application | 04, 07, 08 | web logs, process creation |
| Initial Access | T1189 Drive-by Compromise (XSS delivery) | 08 | web logs |
| Initial Access / Persistence | T1078 / T1078.002 Valid Accounts | 01, 14 | auth logs, 4624 |
| Execution | T1059.004 Unix Shell | 03, 04, 07, 08 | process creation |
| Execution | T1047 WMI | 14 | Sysmon 1 |
| Execution | T1569.002 Service Execution | 14 | System 7045 |
| Persistence | T1053.005 Scheduled Task | 13 | Security 4698 |
| Persistence | T1547.001 Registry Run Keys | 13 | Sysmon 13 |
| Persistence | T1543.003 Windows Service | 13 | System 7045 |
| Credential Access | T1110.001 Password Guessing | 01, 05, 10, 11 | auth logs, 4625 |
| Credential Access | T1110.003 Password Spraying | 05, 11 | auth logs, 4625/4776/4771 |
| Credential Access | T1003.001 LSASS Memory | 12 | Sysmon 10/1/11 |
| Discovery | T1046 Network Service Discovery | 02, 04, 09 | Zeek conn / firewall |
| Lateral Movement | T1021.004 SSH | 01, 05 | auth logs |
| Lateral Movement | T1021.002 SMB/Admin Shares | 14 | 4624 type 3, 5140/5145 |
| Lateral Movement | T1210 Exploitation of Remote Services | 07 | Zeek, process creation |
| Command and Control | T1071 / T1071.001 Application Layer Protocol | 04, 06, 09 | Zeek conn, proxy |
| Command and Control | T1095 Non-Application Layer Protocol | 03, 04, 06 | Sysmon 3, Zeek |
| Exfiltration | T1041 Exfiltration Over C2 Channel | 09 | Zeek conn (bytes out) |
| Exfiltration | T1029 Scheduled Transfer | 06 | Zeek conn |

## Repository layout

```
labs/NN-name/
  README.md                 objective, setup, attack, logs, logic, ATT&CK, tuning, response, results
  detections/
    *.spl  *.kql  *.eql  *.esql     hand-written queries per platform
    sigma/*.yml                     Sigma rules (correlations in the same file as their base rule)
    sigma-converted/                sigma-cli output (Splunk SPL, Elastic Lucene)
  samples/                          SYNTHETIC logs, documentation IPs only
  dashboards/                       Splunk Simple XML (Lab 01)
  analyzer/ tests/                  code + tests where the lab has a tool (Lab 06)
docs/lab-environment.md             Splunk/ELK, Sysmon, Kali, DVWA, Metasploitable, audit policy
docs/lab-template.md                template every lab follows
scripts/convert-sigma.sh            validate + convert all Sigma rules
tests/                              repo hygiene, Lab 08 pattern tests
```

## Per-lab template

Every lab README has the same sections (enforced by `tests/test_repo_hygiene.py`):

1. **Objective** 2. **Lab setup** 3. **Attack simulation** (isolated, owned lab only) 4. **Log sources required** 5. **Detection logic** 6. **MITRE ATT&CK mapping** 7. **Tuning notes** (expected false positives) 8. **Response steps** 9. **Results** (fill-in template: detection rate, FP count before/after tuning, time to alert)

See [docs/lab-template.md](docs/lab-template.md).

## Validation

| Check | How |
|---|---|
| Sigma syntax and conventions | `sigma check labs` (sigma-cli / pySigma) |
| Sigma converts to real queries | `scripts/convert-sigma.sh`: Splunk (sysmon + Windows log-source pipelines) and Elastic Lucene (ECS); correlations to Splunk |
| Python analyzers | `pytest -q` (Lab 06 beacon analyzer, Lab 08 web patterns, repo hygiene) |
| Shell scripts | `shellcheck` |
| Sample data | hygiene test: every sample labelled SYNTHETIC; every IPv4 in the repo is a documentation address |

CI runs all of this on every push (`.github/workflows/ci.yml`).

## Related repositories

- [log-brute-force-detector](https://github.com/ForgeVanguard/log-brute-force-detector): the Lab 05 tool (Python + Bash, tested)
- [vmware-security-homelab](https://github.com/ForgeVanguard/vmware-security-homelab): the virtual lab these exercises run in
- [windows-hardening-kit](https://github.com/ForgeVanguard/windows-hardening-kit): the defensive side of Labs 11-14
- [dfir-osint-toolkit](https://github.com/ForgeVanguard/dfir-osint-toolkit): triage and investigation tooling

## Disclaimer

See [DISCLAIMER.md](DISCLAIMER.md). Everything here is for education and for authorized testing in an isolated lab you own.

## License

MIT © 2026 Steven Drew
