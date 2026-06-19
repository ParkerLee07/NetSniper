#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bundle_dir="${1:-}"

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

pass() {
  echo "[PASS] $*"
}

if [[ -z "$bundle_dir" ]]; then
  bundle_dir="$(find "$ROOT_DIR/runs" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' 2>/dev/null \
    | sort -nr \
    | awk 'NR==1 {print $2}')"
fi

[[ -n "$bundle_dir" ]] || fail "No bundle directory provided and no runs/ bundle found"
[[ -d "$bundle_dir" ]] || fail "Bundle directory does not exist: $bundle_dir"

manifest="$bundle_dir/manifest.json"
analysis="$bundle_dir/analysis.json"
enriched="$bundle_dir/analysis.enriched.json"
quality_json="$bundle_dir/classification_quality.json"
quality_md="$bundle_dir/classification_quality.md"

[[ -f "$manifest" ]] || fail "Missing manifest.json"
[[ -f "$analysis" ]] || fail "Missing analysis.json"
[[ -f "$enriched" ]] || fail "Missing analysis.enriched.json"
[[ -f "$quality_json" ]] || fail "Missing classification_quality.json"
[[ -f "$quality_md" ]] || fail "Missing classification_quality.md"

jq empty "$manifest" || fail "manifest.json is invalid JSON"
jq empty "$analysis" || fail "analysis.json is invalid JSON"
jq empty "$enriched" || fail "analysis.enriched.json is invalid JSON"
jq empty "$quality_json" || fail "classification_quality.json is invalid JSON"

grep -q "NetSniper v1.7 Quality Report" "$quality_md" \
  || fail "classification_quality.md missing quality report title"

jq -e '
  .files.analysis_json == "analysis.json"
' "$manifest" >/dev/null \
  || fail "manifest files.analysis_json is missing or incorrect"

jq -e '
  .files.analysis_enriched_json == "analysis.enriched.json"
' "$manifest" >/dev/null \
  || fail "manifest files.analysis_enriched_json is missing or incorrect"

jq -e '
  .files.classification_quality_json == "classification_quality.json"
' "$manifest" >/dev/null \
  || fail "manifest files.classification_quality_json is missing or incorrect"

jq -e '
  .files.classification_quality_markdown == "classification_quality.md"
' "$manifest" >/dev/null \
  || fail "manifest files.classification_quality_markdown is missing or incorrect"

host_count="$(jq '.host_count' "$quality_json")"
classified_count="$(jq '.classified_count' "$quality_json")"
false_confidence_count="$(jq '.false_confidence_candidate_count' "$quality_json")"

[[ "$host_count" -ge 1 ]] \
  || fail "classification_quality.json host_count is invalid: $host_count"

[[ "$false_confidence_count" -eq 0 ]] \
  || fail "classification_quality.json has false-confidence candidates: $false_confidence_count"

pass "NetSniper v1.7 bundle artifacts are present and manifest-addressable"
pass "Bundle: $bundle_dir"
pass "Hosts: $host_count"
pass "Classified: $classified_count"
pass "False-confidence candidates: $false_confidence_count"
