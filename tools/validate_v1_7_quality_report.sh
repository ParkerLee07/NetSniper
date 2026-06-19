#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORTER="$ROOT_DIR/tools/report_v1_7_quality.py"
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

[[ -x "$REPORTER" ]] || fail "Missing executable reporter: tools/report_v1_7_quality.py"
[[ -f "$FIXTURE" ]] || fail "Missing analysis fixture"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

json_report="$tmp_dir/quality.json"
md_report="$tmp_dir/quality.md"
stdout_report="$tmp_dir/stdout.json"

python3 "$REPORTER" \
  --analysis "$FIXTURE" \
  --output-json "$json_report" \
  --output-md "$md_report" \
  > "$stdout_report"

jq empty "$json_report" || fail "Quality JSON report is invalid"
jq empty "$stdout_report" || fail "Quality stdout report is invalid"

[[ -s "$md_report" ]] || fail "Markdown report was not created"

schema_version="$(jq -r '.schema_version' "$json_report")"
[[ "$schema_version" == "netsniper-v1.7-quality-report-v1" ]] \
  || fail "Unexpected quality report schema_version: $schema_version"

host_count="$(jq '.host_count' "$json_report")"
[[ "$host_count" -eq 4 ]] || fail "Expected host_count 4, found $host_count"

classified_count="$(jq '.classified_count' "$json_report")"
[[ "$classified_count" -ge 3 ]] || fail "Expected at least 3 classified hosts, found $classified_count"

possible_count="$(jq '.possible_or_review_count' "$json_report")"
[[ "$possible_count" -ge 1 ]] || fail "Expected at least 1 possible/review host, found $possible_count"

false_confidence_count="$(jq '.false_confidence_candidate_count' "$json_report")"
[[ "$false_confidence_count" -eq 0 ]] \
  || fail "Expected 0 false-confidence candidates in fixture, found $false_confidence_count"

for required_type in \
  "Network Printer / MFP" \
  "Container Infrastructure" \
  "IP Camera / NVR" \
  "Web Server / Web Application Host"
do
  jq -e --arg t "$required_type" '.top_device_types[$t] != null' "$json_report" >/dev/null \
    || fail "Quality report missing top device type: $required_type"
done

jq -e '.confidence_band_counts.high >= 1 or .confidence_band_counts.strong >= 1' "$json_report" >/dev/null \
  || fail "Expected at least one strong/high confidence band"

jq -e '.review_queue_count >= 1' "$json_report" >/dev/null \
  || fail "Expected review_queue_count >= 1"

grep -q "NetSniper v1.7 Quality Report" "$md_report" \
  || fail "Markdown report missing title"

grep -q "False-Confidence Review Candidates" "$md_report" \
  || fail "Markdown report missing false-confidence section"

pass "NetSniper v1.7 quality report generated valid release-gate metrics"
pass "Report hosts: $host_count"
pass "Classified hosts: $classified_count"
pass "Possible/review hosts: $possible_count"
pass "False-confidence candidates: $false_confidence_count"
