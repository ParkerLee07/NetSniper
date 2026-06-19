#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENHANCER="$ROOT_DIR/tools/enhance_v1_7_analysis.py"
FIXTURE="$ROOT_DIR/tests/fixtures/analysis_v1_7/sample_analysis.json"

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

pass() {
  echo "[PASS] $*"
}

command -v jq >/dev/null 2>&1 || fail "jq is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"

[[ -x "$ENHANCER" ]] || fail "Missing executable enhancer: tools/enhance_v1_7_analysis.py"
[[ -f "$FIXTURE" ]] || fail "Missing sample analysis fixture"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

output="$tmp_dir/sample_analysis.enriched.json"

before_hash="$(sha256sum "$FIXTURE" | awk '{print $1}')"

python3 "$ENHANCER" \
  --analysis "$FIXTURE" \
  --output "$output" \
  > "$tmp_dir/summary.json"

after_hash="$(sha256sum "$FIXTURE" | awk '{print $1}')"

[[ "$before_hash" == "$after_hash" ]] \
  || fail "Enhancer modified the input fixture"

jq empty "$output" || fail "Enhanced analysis output is invalid JSON"
jq empty "$tmp_dir/summary.json" || fail "Enhancer summary output is invalid JSON"

host_count="$(jq '.hosts | length' "$output")"
[[ "$host_count" -eq 4 ]] || fail "Expected 4 enriched hosts, found $host_count"

summary_host_count="$(jq '.netsniper_v1_7_enrichment.host_count' "$output")"
[[ "$summary_host_count" -eq 4 ]] || fail "Expected summary host_count 4, found $summary_host_count"

printer_type="$(jq -r '.hosts[] | select(.ip == "192.168.4.60") | .classification.primary_type' "$output")"
[[ "$printer_type" == "Network Printer / MFP" ]] \
  || fail "Printer fixture classified as '$printer_type'"

container_type="$(jq -r '.hosts[] | select(.ip == "192.168.4.50") | .classification.primary_type' "$output")"
[[ "$container_type" == "Container Infrastructure" ]] \
  || fail "Container fixture classified as '$container_type'"

web_type="$(jq -r '.hosts[] | select(.ip == "192.168.4.80") | .classification.primary_type' "$output")"
[[ "$web_type" == "Web Server / Web Application Host" ]] \
  || fail "Generic web fixture classified as '$web_type'"

web_decision="$(jq -r '.hosts[] | select(.ip == "192.168.4.80") | .classification.decision' "$output")"
[[ "$web_decision" == "possible" ]] \
  || fail "Generic web fixture should stay possible, got '$web_decision'"

web_confidence="$(jq -r '.hosts[] | select(.ip == "192.168.4.80") | .classification.confidence' "$output")"
[[ "$web_confidence" -lt 70 ]] \
  || fail "Generic web fixture violated false-confidence guard with confidence $web_confidence"

camera_host_id="$(jq -r '.hosts[] | select(.target_ip == "192.168.4.70" or .host_id == "192.168.4.70") | .host_id' "$output")"
[[ "$camera_host_id" == "192.168.4.70" ]] \
  || fail "Expected target_ip host identity to be preserved as host_id, got '$camera_host_id'"

camera_ip="$(jq -r '.hosts[] | select(.host_id == "192.168.4.70") | .ip' "$output")"
[[ "$camera_ip" == "192.168.4.70" ]] \
  || fail "Expected target_ip host identity to be promoted to ip, got '$camera_ip'"

camera_type="$(jq -r '.hosts[] | select(.host_id == "192.168.4.70") | .classification.primary_type' "$output")"
[[ "$camera_type" == "IP Camera / NVR" ]] \
  || fail "Expected legacy camera fixture to classify as IP Camera / NVR, got '$camera_type'"

missing_host_id_count="$(
  jq '
    [
      .hosts[]
      | select((.host_id // "") == "")
    ]
    | length
  ' "$output"
)"
[[ "$missing_host_id_count" -eq 0 ]] \
  || fail "Expected all enriched hosts to have host_id, missing on $missing_host_id_count host(s)"

previous_classification_count="$(
  jq '
    [
      .hosts[]
      | select(.classification_previous != null)
    ]
    | length
  ' "$output"
)"
[[ "$previous_classification_count" -ge 1 ]] \
  || fail "Expected previous classification to be preserved on at least one host"

for field in \
  schema_version \
  primary_type \
  confidence \
  confidence_band \
  decision \
  siem_action \
  evidence \
  contradictions \
  secondary_candidates
do
  missing_count="$(
    jq --arg field "$field" '
      [
        .hosts[]
        | select(.classification[$field] == null)
      ]
      | length
    ' "$output"
  )"

  [[ "$missing_count" -eq 0 ]] \
    || fail "Missing classification field '$field' on $missing_count host(s)"
done

classified_count="$(jq '.netsniper_v1_7_enrichment.classified_count' "$output")"
possible_count="$(jq '.netsniper_v1_7_enrichment.possible_or_review_count' "$output")"

[[ "$classified_count" -ge 2 ]] \
  || fail "Expected at least 2 classified hosts, found $classified_count"

[[ "$possible_count" -ge 1 ]] \
  || fail "Expected at least 1 possible/review host, found $possible_count"

pass "NetSniper v1.7 analysis enhancer enriched sample analysis safely"
pass "Enhanced hosts: $host_count"
pass "Classified hosts: $classified_count"
pass "Possible/review hosts: $possible_count"
