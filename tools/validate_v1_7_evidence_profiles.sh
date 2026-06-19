#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILES_FILE="$ROOT_DIR/classification/evidence_profiles.json"
TAXONOMY_FILE="$ROOT_DIR/classification/device_taxonomy.json"

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

pass() {
  echo "[PASS] $*"
}

command -v jq >/dev/null 2>&1 || fail "jq is required"

[[ -f "$PROFILES_FILE" ]] || fail "Missing classification/evidence_profiles.json"
[[ -f "$TAXONOMY_FILE" ]] || fail "Missing classification/device_taxonomy.json"

jq empty "$PROFILES_FILE" || fail "Evidence profiles JSON is invalid"
jq empty "$TAXONOMY_FILE" || fail "Taxonomy JSON is invalid"

schema_version="$(jq -r '.schema_version // empty' "$PROFILES_FILE")"
[[ "$schema_version" == "netsniper-evidence-profiles-v1" ]] || fail "Unexpected schema_version: $schema_version"

profile_count="$(jq '.profiles | length' "$PROFILES_FILE")"
[[ "$profile_count" -ge 8 ]] || fail "Expected at least 8 evidence profiles, found $profile_count"

for required_type in \
  "IP Camera / NVR" \
  "Network Printer / MFP" \
  "Container Infrastructure" \
  "Active Directory / Domain Controller" \
  "Database Server" \
  "NAS / Storage Appliance" \
  "Router / Gateway" \
  "Wireless Access Point"
do
  jq -e --arg t "$required_type" '.profiles[] | select(.primary_type == $t)' "$PROFILES_FILE" >/dev/null \
    || fail "Missing required evidence profile: $required_type"

  jq -e --arg t "$required_type" '
    .profiles[]
    | select(.primary_type == $t)
    | (.positive_evidence | length) >= 3
  ' "$PROFILES_FILE" >/dev/null \
    || fail "Profile has fewer than 3 positive evidence rules: $required_type"

  jq -e --arg t "$required_type" '
    .profiles[]
    | select(.primary_type == $t)
    | .default_siem_action
    | IN("display_only", "review_queue", "contradiction_review", "alert_candidate")
  ' "$PROFILES_FILE" >/dev/null \
    || fail "Profile has invalid default_siem_action: $required_type"
done

invalid_reliability_count="$(
  jq '
    [
      .profiles[].positive_evidence[]
      | select(.reliability | IN("high", "medium", "low") | not)
    ]
    | length
  ' "$PROFILES_FILE"
)"
[[ "$invalid_reliability_count" -eq 0 ]] || fail "Found evidence rules with invalid reliability values"

invalid_points_count="$(
  jq '
    [
      .profiles[].positive_evidence[]
      | select((.points | type) != "number" or .points < 1 or .points > 60)
    ]
    | length
  ' "$PROFILES_FILE"
)"
[[ "$invalid_points_count" -eq 0 ]] || fail "Found evidence rules with invalid point values"

missing_reason_count="$(
  jq '
    [
      .profiles[].positive_evidence[]
      | select((.reason // "") == "")
    ]
    | length
  ' "$PROFILES_FILE"
)"
[[ "$missing_reason_count" -eq 0 ]] || fail "Found evidence rules missing reasons"

missing_contradiction_reason_count="$(
  jq '
    [
      .profiles[].contradictions[]
      | select((.reason // "") == "")
    ]
    | length
  ' "$PROFILES_FILE"
)"
[[ "$missing_contradiction_reason_count" -eq 0 ]] || fail "Found contradiction rules missing reasons"

taxonomy_missing_count="$(
  jq -n \
    --slurpfile profiles "$PROFILES_FILE" \
    --slurpfile taxonomy "$TAXONOMY_FILE" '
      [
        $profiles[0].profiles[].primary_type as $p
        | select(
            [
              $taxonomy[0].device_classes[].primary_type
            ]
            | index($p)
            | not
          )
      ]
      | length
    '
)"
[[ "$taxonomy_missing_count" -eq 0 ]] || fail "One or more evidence profiles are missing from the taxonomy"

pass "NetSniper v1.7 evidence profiles are present and valid"
pass "Evidence profiles: $profile_count"
pass "Invalid reliability values: $invalid_reliability_count"
pass "Invalid point values: $invalid_points_count"
