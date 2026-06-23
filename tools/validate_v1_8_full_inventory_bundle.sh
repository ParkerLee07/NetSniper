#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RUN_DIR_ARG="${1:-}"

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

pass() {
    echo "[PASS] $*"
}

if [ -n "$RUN_DIR_ARG" ]; then
    run="$RUN_DIR_ARG"
else
    run="$(ls -td runs/* 2>/dev/null | head -1)"
fi

[ -n "$run" ] || fail "No run directory found"
[ -d "$run" ] || fail "Run directory does not exist: $run"

for file in hosts.txt analysis.json analysis.enriched.json classification_quality.json manifest.json; do
    [ -s "$run/$file" ] || fail "Missing or empty $run/$file"
done

hosts_count="$(wc -l < "$run/hosts.txt" | tr -d ' ')"

analysis_count="$(jq 'length' "$run/analysis.json")"
enriched_count="$(jq 'if has("hosts") then (.hosts | length) elif type == "array" then length else 0 end' "$run/analysis.enriched.json")"

[ "$hosts_count" = "$analysis_count" ] \
    || fail "hosts.txt count ($hosts_count) does not match analysis.json count ($analysis_count)"

[ "$hosts_count" = "$enriched_count" ] \
    || fail "hosts.txt count ($hosts_count) does not match analysis.enriched.json count ($enriched_count)"

missing_analysis="$(
    comm -23 \
        <(LC_ALL=C sort "$run/hosts.txt") \
        <(jq -r '.[] | .host // .ip // .ip_address // .host_id // empty' "$run/analysis.json" | LC_ALL=C sort)
)"

[ -z "$missing_analysis" ] \
    || fail "Hosts missing from analysis.json: $missing_analysis"

missing_enriched="$(
    comm -23 \
        <(LC_ALL=C sort "$run/hosts.txt") \
        <(jq -r 'if has("hosts") then .hosts else . end | .[] | .host // .ip // .ip_address // .host_id // empty' "$run/analysis.enriched.json" | LC_ALL=C sort)
)"

[ -z "$missing_enriched" ] \
    || fail "Hosts missing from analysis.enriched.json: $missing_enriched"

bad_unknowns="$(
    jq -r '
      .[]?
      | select((.classification.method // "") == "full_inventory_preservation")
      | select(
          (.device_type // "") != "Unknown"
          or (.severity // "") != "INFO"
          or ((.score // 0) != 0)
          or ((.classification.primary_type // "") != "Unknown / Ambiguous")
          or ((.classification.confidence // 0) != 0)
          or ((.classification.siem_action // "") != "no_action")
          or (((.findings // []) | length) != 0)
        )
      | .host // .ip // .ip_address // .host_id
    ' "$run/analysis.json"
)"

[ -z "$bad_unknowns" ] \
    || fail "Discovery-only hosts were not preserved conservatively: $bad_unknowns"

false_confidence="$(jq -r '.false_confidence_candidate_count // 0' "$run/classification_quality.json")"
[ "$false_confidence" = "0" ] \
    || fail "False-confidence candidates detected: $false_confidence"

pass "NetSniper v1.8 full inventory bundle validation passed for $run"
pass "Hosts preserved: $hosts_count"
