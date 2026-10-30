# Lab template

Copy this when adding a new lab. Keep every heading; reviewers and the repo hygiene test expect them.

```markdown
# Lab NN - <Title>

## Objective
What the lab teaches and the detection you will end up with.

## Lab setup
Hosts, roles, addresses (documentation IPs only), and prerequisites.

## Attack simulation
> Authorized use only. Isolated lab you own.
Standard, publicly documented tool commands that generate the telemetry.

## Log sources required
Table of source, location/sourcetype, and which rule needs it.

## Detection logic
Plain-English logic, then a table of the detection files.

## MITRE ATT&CK mapping
Tactic / Technique / ID table with links.

## Tuning notes
Expected false positives and how to handle them (allowlists, windows, thresholds).

## Response steps
What an analyst does when the alert fires.

## Results
A clearly-marked template. Fill in only what you actually observed. No invented metrics.
```

## Rules for detection content

- **No invented results.** Leave metrics as a template until you have run the lab.
- **Validate Sigma** with `./scripts/convert-sigma.sh` before committing.
- **Python** must pass `pytest`; **Bash** must pass `shellcheck`.
- **Sample logs** must be clearly labelled `SYNTHETIC` and use documentation IPs only.
- Keep attack commands educational and lab-scoped: standard tool usage, no weaponized payloads.
