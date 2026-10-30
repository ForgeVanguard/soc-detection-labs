#!/usr/bin/env bash
# convert-sigma.sh - validate every Sigma rule and convert it to Splunk SPL and Elastic Lucene.
#
# Requires sigma-cli with the splunk, elasticsearch, sysmon and windows plugins:
#   pip install sigma-cli
#   sigma plugin install splunk elasticsearch sysmon windows
#
# Output goes to labs/<lab>/detections/sigma-converted/<rule>.{splunk.spl,lucene.txt}
# Windows rules use the sysmon + Windows log-source pipelines (Splunk) and ECS/Winlogbeat (Elastic).
# Linux, firewall and web rules are converted without a field-mapping pipeline: map the field
# names to your own sourcetype or index (see each lab README).
# Correlation rules (thresholds) are converted for Splunk only; Lucene has no aggregation, so
# those labs include a hand-written ES|QL query.

set -euo pipefail

SIGMA="${SIGMA:-sigma}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

"$SIGMA" check labs

status=0
while IFS= read -r rule; do
    lab_dir="$(dirname "$(dirname "$rule")")"
    out="$lab_dir/sigma-converted"
    mkdir -p "$out"
    name="$(basename "$rule" .yml)"
    if grep -q '^    product: windows' "$rule"; then
        splunk_p=(-p sysmon -p windows-logsources)
        elastic_p=(-p sysmon -p ecs_windows)
    else
        splunk_p=(--without-pipeline)
        elastic_p=(--without-pipeline)
    fi
    if ! "$SIGMA" convert -t splunk "${splunk_p[@]}" "$rule" -o "$out/$name.splunk.spl"; then
        echo "FAILED splunk: $rule" >&2; status=1
    fi
    if grep -q '^correlation:' "$rule"; then
        # Lucene cannot express aggregations; the lab ships a hand-written ES|QL version instead.
        echo "note: $rule is a correlation rule - Elastic version is in detections/*.esql" >&2
        continue
    fi
    if ! "$SIGMA" convert -t lucene "${elastic_p[@]}" "$rule" -o "$out/$name.lucene.txt"; then
        echo "FAILED lucene: $rule" >&2; status=1
    fi
done < <(find labs -path '*/detections/sigma/*.yml' | sort)

exit "$status"
