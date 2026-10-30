# Lab 11 - Windows Failed Logons and Password Spraying

## Objective

Detect password spraying and brute force against Windows accounts from Security log events 4625, 4776 and 4771, and tell the two patterns apart.

## Lab setup

| Host | Role | Address |
|---|---|---|
| `attacker` | Kali Linux | 192.0.2.10 |
| `dc01` | Windows Server domain controller (lab domain) | 192.0.2.50 |
| `win-target` | Windows 10/11, domain-joined, Sysmon + Universal Forwarder or Elastic Agent | 192.0.2.60 |
| `siem` | Splunk or Elastic | 192.0.2.5 |

Enable auditing (GPO > Advanced Audit Policy): **Logon** (Success/Failure), **Credential Validation** (Success/Failure), **Kerberos Authentication Service** (Failure). Install Sysmon with a community config (see docs). Forward Security, System and Sysmon channels.

Create 10-15 throwaway lab accounts in a dedicated OU. **Set the lab domain's account lockout threshold high** (or disable it in the lab only) so spraying does not lock accounts mid-test, and note this setting in your results.

## Attack simulation

> **Authorized use only.** Run these steps only in an isolated lab that you own, against the lab VMs described in [docs/lab-environment.md](../../docs/lab-environment.md). The attack-side commands are standard, publicly documented tool usage for generating telemetry; they are not meant for any other system.

```bash
# SMB spray: one password, many lab accounts (generates 4625 on the target, 4776 on the DC)
crackmapexec smb 192.0.2.60 -u lab-users.txt -p 'Spring2026!' --continue-on-success
# (netexec is the maintained fork: nxc smb ... same arguments)

# Kerberos pre-auth spray (generates 4771 on the DC)
kerbrute passwordspray -d lab.local --dc 192.0.2.50 lab-users.txt 'Spring2026!'

# Brute force: many passwords, one account
hydra -l labuser01 -P small-wordlist.txt smb://192.0.2.60
```

## Log sources required

| Event | Channel | Where | Meaning |
|---|---|---|---|
| 4625 | Security | target host | failed logon (SubStatus `0xC000006A` bad password, `0xC0000064` no such user) |
| 4776 | Security | DC | NTLM credential validation (Error Code as above) |
| 4771 | Security | DC | Kerberos pre-auth failed (`0x18` = bad password) |
| 4624 | Security | target | the successful logon that may follow |

`samples/4625_spray.csv` is a **SYNTHETIC** event list showing the spray shape.

## Detection logic

- **Spray:** one source, **≥ 10 distinct accounts** failing in 10 minutes (4625 by `IpAddress`, 4776 by workstation, 4771 by client address).
- **Brute force:** one account, **≥ 20 failures** in 10 minutes.
- The split matters for response: a spray means many accounts may be at risk, while brute force targets one account and risks a lockout.
- Sigma: one file, `win_failed_logon_correlations.yml`, has the base 4625 rule plus two correlations (value_count users by IP, event_count by user). Separate rules cover 4776 and 4771.

### Detection files

| File | Format |
|---|---|
| [`detections/kerberos_spray_4771.spl`](detections/kerberos_spray_4771.spl) | Splunk SPL |
| [`detections/ntlm_spray_4776.spl`](detections/ntlm_spray_4776.spl) | Splunk SPL |
| [`detections/password_spray.esql`](detections/password_spray.esql) | Elastic ES|QL |
| [`detections/password_spray.kql`](detections/password_spray.kql) | KQL (Microsoft Sentinel / Defender) |
| [`detections/password_spray_4625.spl`](detections/password_spray_4625.spl) | Splunk SPL |
| [`detections/sigma/win_failed_logon_correlations.yml`](detections/sigma/win_failed_logon_correlations.yml) | Sigma |
| [`detections/sigma/win_kerberos_preauth_failure.yml`](detections/sigma/win_kerberos_preauth_failure.yml) | Sigma |
| [`detections/sigma/win_ntlm_validation_failure.yml`](detections/sigma/win_ntlm_validation_failure.yml) | Sigma |
| [`detections/sigma-converted/`](detections/sigma-converted/) | Sigma → SPL / Lucene, produced by `scripts/convert-sigma.sh` |

## MITRE ATT&CK mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force: Password Spraying | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) |
| Credential Access | Brute Force: Password Guessing | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |

## Tuning notes

- **FPs:** a user with an old password on a phone or mapped drive (one account, many failures, from one host); VDI/RDS gateways where many users fail from one IP; apps with stale service-account credentials.
- Check `LogonType`: 3 = network (SMB/spraying), 10 = RDP, 2 = interactive.
- Slow sprays (one attempt per account per hour) need a 24-hour window with `dc(account)`.
- 4625 events from an IP of `-` usually mean local logons; handle them separately.

## Response steps

1. Look for any **4624 success** from the spraying source for the targeted accounts. Those accounts are compromised.
2. Reset passwords for accounts that succeeded, and check them for MFA enrollment changes, new mailbox rules, and group changes.
3. Block the source and check whether it is internal (a compromised host doing the spraying).
4. Review the password policy and add a banned-password list for seasonal patterns.

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
