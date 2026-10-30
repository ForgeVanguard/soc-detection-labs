# Lab 02 - Port Scan Detection

## Objective

Run common Nmap scan types against a lab host and detect them from firewall or Zeek connection logs by counting distinct destination ports per source. Compare how visible each scan type is.

## Lab setup

| Host | Role | Address |
|---|---|---|
| `attacker` | Kali Linux | 192.0.2.10 |
| `lab-target01` | Linux target with host firewall logging (`ufw logging on` / iptables LOG) or Zeek on a SPAN/bridge | 192.0.2.20 |
| `siem` | Splunk or Elastic | 192.0.2.5 |

The most reliable source is **Zeek `conn.log`** from a sensor that sees the lab segment (Security Onion works well). A host firewall that logs drops works too. Map it to the CIM `Network_Traffic` data model in Splunk or to ECS in Elastic.

## Attack simulation

> **Authorized use only.** Run these steps only in an isolated lab that you own, against the lab VMs described in [docs/lab-environment.md](../../docs/lab-environment.md). The attack-side commands are standard, publicly documented tool usage for generating telemetry; they are not meant for any other system.

```bash
nmap -sS -T4 --top-ports 1000 192.0.2.20      # SYN scan (needs root)
nmap -sT -p 1-1024 192.0.2.20                  # full connect scan
nmap -sU --top-ports 50 192.0.2.20             # UDP scan
nmap -sS -T1 -p 1-200 192.0.2.20               # slow scan (to test the window)
nmap -sn 192.0.2.0/24                          # host discovery sweep
```

Run each separately and note the start and end time of each, so you can line the scans up with the alerts.

## Log sources required

| Source | Fields used |
|---|---|
| Zeek `conn.log` | `id.orig_h`, `id.resp_h`, `id.resp_p`, `conn_state` |
| Firewall (pfSense/OPNsense, ufw/iptables) | src, dest, dest_port, action |
| CIM `Network_Traffic` or ECS `event.category: network` | normalized versions of the above |

`samples/conn.log` is a **SYNTHETIC** Zeek extract showing a SYN-scan pattern (many `REJ` states from one source).

## Detection logic

- **Vertical scan:** one `src` → one `dest`, **≥ 20 distinct destination ports in 5 minutes**.
- Zeek variant: count only `conn_state` values that mean no or refused handshake (`S0`, `REJ`, `RSTOS0`, `RSTR`, `SH`), which strips normal sessions out.
- Horizontal sweep (`-sn` or one port across many hosts): change the group-by to `src, dest_port` and count `dc(dest)` instead.
- Sigma: a `value_count` correlation on `dst_port` grouped by `src_ip` and `dst_ip`.

### Detection files

| File | Format |
|---|---|
| [`detections/port_scan.esql`](detections/port_scan.esql) | Elastic ES|QL |
| [`detections/port_scan.kql`](detections/port_scan.kql) | KQL (Microsoft Sentinel / Defender) |
| [`detections/port_scan.spl`](detections/port_scan.spl) | Splunk SPL |
| [`detections/port_scan_zeek.spl`](detections/port_scan_zeek.spl) | Splunk SPL |
| [`detections/sigma/port_scan_correlation.yml`](detections/sigma/port_scan_correlation.yml) | Sigma |
| [`detections/sigma-converted/`](detections/sigma-converted/) | Sigma → SPL / Lucene, produced by `scripts/convert-sigma.sh` |

## MITRE ATT&CK mapping

| Tactic | Technique | ID |
|---|---|---|
| Discovery | Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) |
| Reconnaissance | Active Scanning: Scanning IP Blocks | [T1595.001](https://attack.mitre.org/techniques/T1595/001/) |

## Tuning notes

- **Expected FPs:** authorized vulnerability scanners, monitoring (Nagios/Zabbix checks many ports), and asset discovery tools. Allowlist them by source IP with an owner and review date.
- **Slow scans (`-T1`, `-T0`)** spread ports over hours and will not hit 20 in 5 minutes. Add a daily `dc(dest_port) by src` report.
- Host-firewall logs only show **blocked** ports. A host with many open services shows fewer events, which is why Zeek is the better source.
- UDP scans produce few log lines on many firewalls, so note the visibility gap in the results.

## Response steps

1. Identify the source: is it an internal asset, a known scanner, or something unknown?
2. Check whether the scan was followed by connections to the open ports it found (pivot on the src in web, SSH and SMB logs; see Lab 04).
3. If the source is internal and unexpected, isolate it and triage it as a possibly compromised host.
4. If it is external, block it at the perimeter and confirm that no unneeded services are exposed.

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
| Visibility per scan type (SYN / connect / UDP / slow) | _fill in_ |

**Evidence:** _add sanitized screenshots or exported results here (documentation IPs only, no real hostnames)._

**What I would change next time:** _fill in_
