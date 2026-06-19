#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE_DIR="$ROOT_DIR/tests/fixtures/classification_v1_7"
HOST_CLASSIFIER="$ROOT_DIR/tools/classify_v1_7_host.py"
PROFILES_FILE="$ROOT_DIR/classification/evidence_profiles.json"

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

pass() {
  echo "[PASS] $*"
}

command -v jq >/dev/null 2>&1 || fail "jq is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"

[[ -d "$FIXTURE_DIR" ]] || fail "Missing fixture directory"
[[ -x "$HOST_CLASSIFIER" ]] || fail "Missing executable host classifier: tools/classify_v1_7_host.py"
[[ -f "$PROFILES_FILE" ]] || fail "Missing evidence profiles file"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

fixture_count=0

for fixture in "$FIXTURE_DIR"/*.json; do
  fixture_count=$((fixture_count + 1))
  fixture_name="$(basename "$fixture")"

  host_record="$tmp_dir/${fixture_name%.json}.host.json"
  output_file="$tmp_dir/${fixture_name%.json}.host.result.json"

  jq '
    {
      host_id: .fixture_id,
      observed: .observed
    }
  ' "$fixture" > "$host_record"

  python3 "$HOST_CLASSIFIER" \
    --host-record "$host_record" \
    --profiles "$PROFILES_FILE" \
    > "$output_file"

  jq empty "$output_file" || fail "Host classifier produced invalid JSON for $fixture_name"

  expected_type="$(jq -r '.expected.primary_type' "$fixture")"
  expected_decision="$(jq -r '.expected.decision' "$fixture")"
  expected_siem_action="$(jq -r '.expected.siem_action' "$fixture")"
  minimum_confidence="$(jq -r '.expected.minimum_confidence' "$fixture")"
  expected_contradiction_review="$(jq -r '.expected.expected_contradiction_review' "$fixture")"
  false_confidence_guard="$(jq -r '.expected.false_confidence_guard // false' "$fixture")"

  actual_type="$(jq -r '.primary_type' "$output_file")"
  actual_decision="$(jq -r '.decision' "$output_file")"
  actual_siem_action="$(jq -r '.siem_action' "$output_file")"
  actual_confidence="$(jq -r '.confidence' "$output_file")"
  actual_band="$(jq -r '.confidence_band' "$output_file")"
  actual_host_id="$(jq -r '.host_id' "$output_file")"
  contradiction_count="$(jq '.contradictions | length' "$output_file")"

  [[ -n "$actual_host_id" && "$actual_host_id" != "null" ]] \
    || fail "$fixture_name missing host_id"

  [[ "$actual_type" == "$expected_type" ]] \
    || fail "$fixture_name expected primary_type '$expected_type' but got '$actual_type'"

  [[ "$actual_decision" == "$expected_decision" ]] \
    || fail "$fixture_name expected decision '$expected_decision' but got '$actual_decision'"

  [[ "$actual_siem_action" == "$expected_siem_action" ]] \
    || fail "$fixture_name expected siem_action '$expected_siem_action' but got '$actual_siem_action'"

  [[ "$actual_confidence" -ge "$minimum_confidence" ]] \
    || fail "$fixture_name expected confidence >= $minimum_confidence but got $actual_confidence"

  jq -e --arg band "$actual_band" '
    .expected.allowed_confidence_bands | index($band)
  ' "$fixture" >/dev/null \
    || fail "$fixture_name confidence band '$actual_band' was not allowed"

  if [[ "$expected_contradiction_review" == "true" ]]; then
    [[ "$contradiction_count" -ge 1 ]] \
      || fail "$fixture_name expected at least one contradiction"
  fi

  if [[ "$false_confidence_guard" == "true" ]]; then
    [[ "$actual_confidence" -lt 70 || "$actual_decision" != "classified" ]] \
      || fail "$fixture_name violated false-confidence guard"
  fi
done

[[ "$fixture_count" -ge 8 ]] || fail "Expected at least 8 fixtures, found $fixture_count"

pass "NetSniper v1.7 reusable host classifier matched expected outputs"
pass "Validated host records: $fixture_count"
