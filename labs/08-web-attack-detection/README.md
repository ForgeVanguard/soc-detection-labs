# Lab 08 - Web Attack Detection (DVWA)

## Objective

Attack DVWA with SQL injection, reflected XSS, and command injection, then detect each class from web server logs. Learn what access logs can and cannot show.

## Lab setup

| Host | Role | Address |
|---|---|---|
| `attacker` | Kali Linux | 192.0.2.10 |
| `web01` | DVWA in Docker (`docker run -d -p 80:80 vulnerables/web-dvwa`) on an isolated network, Apache access log forwarded | 192.0.2.20 |
| `siem` | Splunk (`sourcetype=access_combined`) or Elastic (Apache/nginx integration) | 192.0.2.5 |

Set DVWA **Security Level = low** for the first run, then medium, and compare. Optional: put ModSecurity (OWASP CRS) in front to log request bodies.

## Attack simulation

> **Authorized use only.** Run these steps only in an isolated lab that you own, against the lab VMs described in [docs/lab-environment.md](../../docs/lab-environment.md). The attack-side commands are standard, publicly documented tool usage for generating telemetry; they are not meant for any other system.

Use the DVWA pages in a browser on the attacker VM:

| Module | Example input (lab only) |
|---|---|
| SQL Injection (`/vulnerabilities/sqli/`, GET `id`) | `1' or '1'='1` and `1' union select user,password from users-- ` |
| XSS reflected (`/vulnerabilities/xss_r/`, GET `name`) | `<script>alert(1)</script>` |
| Command Injection (`/vulnerabilities/exec/`, POST `ip`) | `127.0.0.1; id` |

Optional, for volume: `sqlmap -u "http://192.0.2.20/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="<DVWA session cookie>" --batch --level 1`.

## Log sources required

| Source | Fields | Notes |
|---|---|---|
| Apache/nginx access log | client IP, method, URI + query, status, UA | GET payloads only |
| ModSecurity audit log | full request incl. body, rule IDs | needed for POST (command injection) |

`samples/access.log` is **SYNTHETIC** and contains benign DVWA browsing plus the encoded payloads above.

## Detection logic

- **URL-decode first** (`urldecode()` in SPL, `url_decode()` in KQL). Attack tools encode payloads, and matching the raw `%27` forms alone is brittle.
- One search classifies `sqli` / `xss` / `cmd_injection` by regex and summarizes by client IP. `tests/test_web_patterns.py` checks the same regexes against the synthetic log (7 attack lines classified, 0 benign).
- Three Sigma rules (`category: webserver`, `cs-uri-query|contains`) for portable versions; they contain both raw and encoded variants.
- `web_attacks_post.spl` covers POST bodies from the ModSecurity audit log.
- Severity hint: a 200 response to an attack pattern is worth more attention than a 403 from the WAF.

### Detection files

| File | Format |
|---|---|
| [`detections/sigma/web_cmd_injection.yml`](detections/sigma/web_cmd_injection.yml) | Sigma |
| [`detections/sigma/web_sqli.yml`](detections/sigma/web_sqli.yml) | Sigma |
| [`detections/sigma/web_xss.yml`](detections/sigma/web_xss.yml) | Sigma |
| [`detections/web_attacks.esql`](detections/web_attacks.esql) | Elastic ES|QL |
| [`detections/web_attacks.kql`](detections/web_attacks.kql) | KQL (Microsoft Sentinel / Defender) |
| [`detections/web_attacks.spl`](detections/web_attacks.spl) | Splunk SPL |
| [`detections/web_attacks_post.spl`](detections/web_attacks_post.spl) | Splunk SPL |
| [`detections/sigma-converted/`](detections/sigma-converted/) | Sigma → SPL / Lucene, produced by `scripts/convert-sigma.sh` |

## MITRE ATT&CK mapping

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Exploit Public-Facing Application | [T1190](https://attack.mitre.org/techniques/T1190/) |
| Execution | Command and Scripting Interpreter: Unix Shell | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) |
| Initial Access | Drive-by Compromise (stored/reflected XSS delivery) | [T1189](https://attack.mitre.org/techniques/T1189/) |

## Tuning notes

- **FPs:** search boxes and forums where users type words like "select" or "script"; developer tools; security scanners. Scope the search to sensitive paths, and allowlist scanners.
- Double-encoding (`%2527`) and comment tricks (`UN/**/ION`) evade simple regexes. Note any evasion you try in the Results.
- Access logs do not include POST bodies, so command injection via DVWA's form is **invisible** there. Record this as a visibility gap.

## Response steps

1. Check the response status and size. A 200 with a large body on SQLi may mean data was returned.
2. Pull every request from that client IP and build a timeline.
3. Check for follow-on activity: new files in the web root, shells spawned by the web server (Lab 04).
4. Block the IP at the WAF/reverse proxy, then fix the input handling (parameterized queries, output encoding, no shell calls with user input).

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
| Detected at security level low / medium / high | _fill in_ |

**Evidence:** _add sanitized screenshots or exported results here (documentation IPs only, no real hostnames)._

**What I would change next time:** _fill in_
