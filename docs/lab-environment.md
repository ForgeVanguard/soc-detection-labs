# Lab environment setup

Everything in these labs runs in an **isolated environment that you own**. Use a host-only or internal virtual network so none of the attack traffic can leave it. Snapshot every VM before you start so you can revert.

Related: these labs assume the kind of virtualized lab described in [vmware-security-homelab](https://github.com/ForgeVanguard/vmware-security-homelab). Use that repo for the hypervisor and network isolation; use this doc for the SOC tooling on top.

> All addresses in this repository are from the RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and all hostnames are generic placeholders. Replace them with your own.

## Network layout

| Host | Role | Example address |
|---|---|---|
| attacker | Kali Linux | 192.0.2.10 |
| lab-target01 | Linux target (SSH, DVWA, services) | 192.0.2.20 |
| vuln-target | Metasploitable 2 (host-only, never bridged) | 192.0.2.30 |
| dc01 | Windows Server domain controller | 192.0.2.50 |
| win-target / win-target2 | Windows 10/11, domain-joined | 192.0.2.60-61 |
| sensor | Zeek / Security Onion | 192.0.2.4 |
| siem | Splunk Free or Elastic | 192.0.2.5 |

You do not need every host for every lab. The Linux labs (01-10) need attacker + lab-target01 + siem. The Windows labs (11-14) need the Windows hosts.

## SIEM option A: Splunk Free

Splunk Free indexes up to 500 MB/day with no account, which is plenty for a lab.

```bash
docker run -d --name splunk -p 8000:8000 -p 8089:8089 -p 9997:9997 \
  -e SPLUNK_START_ARGS=--accept-license \
  -e SPLUNK_PASSWORD='<choose-a-strong-password>' \
  splunk/splunk:latest
# Web UI: http://<docker-host>:8000  (user: admin)
```

Add-ons to install (Settings > Apps): **Splunk Add-on for Unix and Linux** (`linux_secure`), **Splunk Add-on for Microsoft Windows**, and the **Sysmon TA**. Create indexes `linux`, `web`, `wineventlog`, `zeek`, `ids`. Point Universal Forwarders at port 9997.

## SIEM option B: Elastic (docker-compose)

A single-node Elasticsearch + Kibana is enough for the lab. Use Elastic's official `docker-compose` from the "Install Elastic Stack with Docker Compose" guide, then add the **System**, **Apache**, **Nginx** and **Windows** integrations in Fleet, plus **Elastic Defend** on the endpoints. The ES|QL, EQL, KQL and Lucene queries in each lab target these ECS field names.

> Do not commit the `.env` file from Elastic's compose bundle; it contains passwords. A `.gitignore` entry is included in this repo.

## Sysmon (Windows and Linux telemetry)

Install Sysmon with a maintained community configuration rather than the defaults:

- **SwiftOnSecurity/sysmon-config** - a good, well-commented starting point.
- **olafhartong/sysmon-modular** - modular, ATT&CK-tagged; generate a merged config from the modules you want.

```powershell
sysmon64.exe -accepteula -i sysmonconfig.xml     # install
sysmon64.exe -c sysmonconfig.xml                 # update config
```

Make sure the config logs, at minimum: Event 1 (ProcessCreate), 3 (NetworkConnect), 10 (ProcessAccess for `lsass.exe`), 11 (FileCreate) and 13 (RegistryValueSet). The labs call out which events they need.

For Linux targets, install **Sysmon for Linux** (events 1 and 3) or enable auditd `execve` logging.

## Windows audit policy

Set these via GPO (Advanced Audit Policy Configuration), then run `gpupdate /force`:

| Subcategory | Setting | Labs |
|---|---|---|
| Logon | Success + Failure | 11, 14 |
| Credential Validation | Success + Failure | 11 |
| Kerberos Authentication Service | Failure | 11 |
| Other Object Access Events | Success | 13 (4698) |
| File Share / Detailed File Share | Success | 14 (5140/5145) |

## Targets

- **DVWA** (Lab 08): `docker run -d -p 80:80 vulnerables/web-dvwa`, then set the security level in the DVWA UI. Isolated network only.
- **Metasploitable 2** (Lab 07): import the VM on a **host-only** network. It is intentionally vulnerable and must never touch a real network.
- **Kali Linux** (attacker): has nmap, hydra, metasploit, netcat, crackmapexec/netexec, kerbrute, sqlmap, Wireshark.

## Validating the detections offline

You do not need the full lab to check that the detection content is correct:

```bash
pip install sigma-cli
sigma plugin install splunk elasticsearch sysmon windows
./scripts/convert-sigma.sh          # validates and converts every Sigma rule

pip install pytest
pytest -q                           # repo hygiene + the Python analyzers' own tests
shellcheck labs/07-exploitation-visibility/detections/raw_log_hunt.sh scripts/*.sh
```
