#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE_DIR="$ROOT_DIR/tests/fixtures/classification_v1_7"
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

[[ -d "$FIXTURE_DIR" ]] || fail "Missing fixture directory: tests/fixtures/classification_v1_7"
[[ -f "$PROFILES_FILE" ]] || fail "Missing classification/evidence_profiles.json"
[[ -f "$TAXONOMY_FILE" ]] || fail "Missing classification/device_taxonomy.json"

fixture_count="$(find "$FIXTURE_DIR" -maxdepth 1 -type f -name '*.json' | wc -l | tr -d ' ')"
[[ "$fixture_count" -ge 8 ]] || fail "Expected at least 8 classification fixtures, found $fixture_count"

for fixture in "$FIXTURE_DIR"/*.json; do
  jq empty "$fixture" || fail "Invalid JSON fixture: $fixture"

  schema_version="$(jq -r '.schema_version // empty' "$fixture")"
  [[ "$schema_version" == "netsniper-classification-fixture-v1" ]] \
    || fail "Unexpected schema_version in $fixture: $schema_version"

  fixture_id="$(jq -r '.fixture_id // empty' "$fixture")"
  [[ -n "$fixture_id" ]] || fail "Missing fixture_id in $fixture"

  description="$(jq -r '.description // empty' "$fixture")"
  [[ -n "$description" ]] || fail "Missing description in $fixture"

  expected_type="$(jq -r '.expected.primary_type // empty' "$fixture")"
  [[ -n "$expected_type" ]] || fail "Missing expected.primary_type in $fixture"

  expected_category="$(jq -r '.expected.category // empty' "$fixture")"
  [[ -n "$expected_category" ]] || fail "Missing expected.category in $fixture"

  minimum_confidence="$(jq -r '.expected.minimum_confidence // empty' "$fixture")"
  [[ "$minimum_confidence" =~ ^[0-9]+$ ]] || fail "Invalid expected.minimum_confidence in $fixture"
  [[ "$minimum_confidence" -ge 1 && "$minimum_confidence" -le 100 ]] \
    || fail "expected.minimum_confidence out of range in $fixture"

  jq -e '.expected.allowed_confidence_bands | type == "array" and length >= 1' "$fixture" >/dev/null \
    || fail "Missing expected.allowed_confidence_bands in $fixture"

  invalid_band_count="$(
    jq '
      [
        .expected.allowed_confidence_bands[]
        | select((["weak", "possible", "strong", "high"] | index(.) | not))
      ]
      | length
    ' "$fixture"
  )"
  [[ "$invalid_band_count" -eq 0 ]] || fail "Invalid confidence band in $fixture"

  decision="$(jq -r '.expected.decision // empty' "$fixture")"
  case "$decision" in
    unknown|possible|classified|contradiction_review) ;;
    *) fail "Invalid expected.decision in $fixture: $decision" ;;
  esac

  siem_action="$(jq -r '.expected.siem_action // empty' "$fixture")"
  case "$siem_action" in
    display_only|review_queue|contradiction_review|alert_candidate) ;;
    *) fail "Invalid expected.siem_action in $fixture: $siem_action" ;;
  esac

  taxonomy_match_count="$(
    jq --arg t "$expected_type" '
      [
        .device_classes[]
        | select(.primary_type == $t)
      ]
      | length
    ' "$TAXONOMY_FILE"
  )"
  [[ "$taxonomy_match_count" -eq 1 ]] \
    || fail "Expected type is not present exactly once in taxonomy for $fixture: $expected_type"

  jq -e '.observed.open_ports | type == "array"' "$fixture" >/dev/null \
    || fail "observed.open_ports must be an array in $fixture"

  jq -e '.observed.service_hints | type == "array"' "$fixture" >/dev/null \
    || fail "observed.service_hints must be an array in $fixture"

  jq -e '.observed.vendor_hints | type == "array"' "$fixture" >/dev/null \
    || fail "observed.vendor_hints must be an array in $fixture"

  jq -e '.observed.http_titles | type == "array"' "$fixture" >/dev/null \
    || fail "observed.http_titles must be an array in $fixture"

  jq -e '.observed.hostname_hints | type == "array"' "$fixture" >/dev/null \
    || fail "observed.hostname_hints must be an array in $fixture"

  jq -e '.observed.network_roles | type == "array"' "$fixture" >/dev/null \
    || fail "observed.network_roles must be an array in $fixture"
done

for required_fixture in \
  camera_strong \
  printer_strong \
  container_strong \
  domain_controller_strong \
  database_strong \
  router_gateway_strong \
  ambiguous_web_device \
  printer_domain_contradiction
do
  [[ -f "$FIXTURE_DIR/$required_fixture.json" ]] \
    || fail "Missing required fixture: $required_fixture.json"
done

false_confidence_guard_count="$(
  jq -s '
    [
      .[]
      | select(.expected.false_confidence_guard == true)
    ]
    | length
  ' "$FIXTURE_DIR"/*.json
)"
[[ "$false_confidence_guard_count" -ge 2 ]] \
  || fail "Expected at least 2 false-confidence guard fixtures"

contradiction_fixture_count="$(
  jq -s '
    [
      .[]
      | select(.expected.expected_contradiction_review == true)
    ]
    | length
  ' "$FIXTURE_DIR"/*.json
)"
[[ "$contradiction_fixture_count" -ge 1 ]] \
  || fail "Expected at least 1 contradiction review fixture"

pass "NetSniper v1.7 synthetic classification fixtures are valid"
pass "Fixture count: $fixture_count"
pass "False-confidence guard fixtures: $false_confidence_guard_count"
pass "Contradiction fixtures: $contradiction_fixture_count"
