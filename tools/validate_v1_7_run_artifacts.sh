#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GENERATOR="$ROOT_DIR/tools/generate_v1_7_run_artifacts.sh"
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

[[ -x "$GENERATOR" ]] || fail "Missing executable generator: tools/generate_v1_7_run_artifacts.sh"
[[ -f "$FIXTURE" ]] || fail "Missing sample analysis fixture"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

run_dir="$tmp_dir/run"
mkdir -p "$run_dir"

cp "$FIXTURE" "$run_dir/analysis.json"

before_hash="$(sha256sum "$run_dir/analysis.json" | awk '{print $1}')"

"$GENERATOR" "$run_dir" > "$tmp_dir/generator_stdout.txt"

after_hash="$(sha256sum "$run_dir/analysis.json" | awk '{print $1}')"

[[ "$before_hash" == "$after_hash" ]] \
  || fail "Generator modified original analysis.json"

[[ -f "$run_dir/analysis.enriched.json" ]] \
  || fail "Missing analysis.enriched.json"

[[ -f "$run_dir/classification_quality.json" ]] \
  || fail "Missing classification_quality.json"

[[ -f "$run_dir/classification_quality.md" ]] \
  || fail "Missing classification_quality.md"

jq empty "$run_dir/analysis.enriched.json" \
  || fail "analysis.enriched.json is invalid JSON"

jq empty "$run_dir/classification_quality.json" \
  || fail "classification_quality.json is invalid JSON"

grep -q "NetSniper v1.7 Quality Report" "$run_dir/classification_quality.md" \
  || fail "classification_quality.md missing report title"

host_count="$(jq '.host_count' "$run_dir/classification_quality.json")"
[[ "$host_count" -eq 4 ]] \
  || fail "Expected quality host_count 4, found $host_count"

classified_count="$(jq '.classified_count' "$run_dir/classification_quality.json")"
[[ "$classified_count" -ge 3 ]] \
  || fail "Expected at least 3 classified hosts, found $classified_count"

false_confidence_count="$(jq '.false_confidence_candidate_count' "$run_dir/classification_quality.json")"
[[ "$false_confidence_count" -eq 0 ]] \
  || fail "Expected 0 false-confidence candidates, found $false_confidence_count"

missing_identity_count="$(
  jq '
    [
      .hosts[]
      | select(
          (.host_id // .ip // .ip_address // .address // .target // .target_ip // .host_ip // "") == ""
        )
    ]
    | length
  ' "$run_dir/analysis.enriched.json"
)"
[[ "$missing_identity_count" -eq 0 ]] \
  || fail "Expected no missing host identities, found $missing_identity_count"

pass "NetSniper v1.7 run artifact generator produced stable run outputs"
pass "Generated analysis.enriched.json"
pass "Generated classification_quality.json"
pass "Generated classification_quality.md"
