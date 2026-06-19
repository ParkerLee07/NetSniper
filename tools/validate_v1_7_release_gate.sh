#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

pass() {
  echo "[PASS] $*"
}

command -v jq >/dev/null 2>&1 || fail "jq is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"

bash -n "$ROOT_DIR/netsniper.sh" || fail "netsniper.sh has shell syntax errors"

"$ROOT_DIR/tools/validate_v1_7_all.sh"
"$ROOT_DIR/tools/validate_v1_7_docs.sh"

latest_bundle="$(
  find "$ROOT_DIR/runs" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' 2>/dev/null \
    | sort -nr \
    | awk 'NR==1 {print $2}'
)"

[[ -n "$latest_bundle" ]] || fail "No run bundle found under runs/"

"$ROOT_DIR/tools/validate_v1_7_bundle_artifacts.sh" "$latest_bundle"

quality_json="$latest_bundle/classification_quality.json"

false_confidence_count="$(jq '.false_confidence_candidate_count' "$quality_json")"
unknown_exposed_count="$(jq '.unknown_with_exposed_services_count' "$quality_json")"
host_count="$(jq '.host_count' "$quality_json")"
classified_count="$(jq '.classified_count' "$quality_json")"

[[ "$false_confidence_count" -eq 0 ]] \
  || fail "Release gate failed: false-confidence candidates found: $false_confidence_count"

[[ "$unknown_exposed_count" -eq 0 ]] \
  || fail "Release gate failed: unknown hosts with exposed services found: $unknown_exposed_count"

[[ "$host_count" -ge 1 ]] \
  || fail "Release gate failed: latest bundle host_count is invalid"

[[ "$classified_count" -ge 1 ]] \
  || fail "Release gate failed: latest bundle classified_count is invalid"

pass "NetSniper v1.7 release gate passed"
pass "Latest bundle: $latest_bundle"
pass "Hosts: $host_count"
pass "Classified: $classified_count"
pass "False-confidence candidates: $false_confidence_count"
pass "Unknown exposed-service hosts: $unknown_exposed_count"
