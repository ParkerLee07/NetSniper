#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAXONOMY_FILE="$ROOT_DIR/classification/device_taxonomy.json"
DOC_TAXONOMY="$ROOT_DIR/docs/DEVICE_TAXONOMY.md"
DOC_EVIDENCE="$ROOT_DIR/docs/CLASSIFICATION_EVIDENCE.md"

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

pass() {
  echo "[PASS] $*"
}

command -v jq >/dev/null 2>&1 || fail "jq is required"

[[ -f "$TAXONOMY_FILE" ]] || fail "Missing classification/device_taxonomy.json"
[[ -f "$DOC_TAXONOMY" ]] || fail "Missing docs/DEVICE_TAXONOMY.md"
[[ -f "$DOC_EVIDENCE" ]] || fail "Missing docs/CLASSIFICATION_EVIDENCE.md"

jq empty "$TAXONOMY_FILE" || fail "Taxonomy JSON is invalid"

schema_version="$(jq -r '.schema_version // empty' "$TAXONOMY_FILE")"
[[ "$schema_version" == "netsniper-device-taxonomy-v1" ]] || fail "Unexpected schema_version: $schema_version"

class_count="$(jq '.device_classes | length' "$TAXONOMY_FILE")"
[[ "$class_count" -ge 10 ]] || fail "Expected at least 10 device classes, found $class_count"

band_count="$(jq '.confidence_bands | length' "$TAXONOMY_FILE")"
[[ "$band_count" -eq 4 ]] || fail "Expected 4 confidence bands, found $band_count"

jq -e '.evidence_reliability.high.default_points' "$TAXONOMY_FILE" >/dev/null || fail "Missing high reliability points"
jq -e '.evidence_reliability.medium.default_points' "$TAXONOMY_FILE" >/dev/null || fail "Missing medium reliability points"
jq -e '.evidence_reliability.low.default_points' "$TAXONOMY_FILE" >/dev/null || fail "Missing low reliability points"

for required_type in \
  "IP Camera / NVR" \
  "Network Printer / MFP" \
  "Container Infrastructure" \
  "Active Directory / Domain Controller" \
  "Database Server" \
  "Unknown" \
  "Ambiguous Device"
do
  jq -e --arg t "$required_type" '.device_classes[] | select(.primary_type == $t)' "$TAXONOMY_FILE" >/dev/null \
    || fail "Missing required device class: $required_type"
done

grep -q "Prefer \"Unknown\"" "$DOC_TAXONOMY" || fail "Taxonomy doc missing false-confidence principle"
grep -q "Contradiction Handling" "$DOC_EVIDENCE" || fail "Evidence doc missing contradiction handling section"

pass "NetSniper v1.7 taxonomy contract is present and valid"
pass "Device classes: $class_count"
pass "Confidence bands: $band_count"
