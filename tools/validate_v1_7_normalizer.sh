#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NORMALIZER="$ROOT_DIR/tools/normalize_v1_7_host.py"
HOST_CLASSIFIER="$ROOT_DIR/tools/classify_v1_7_host.py"
FIXTURE_DIR="$ROOT_DIR/tests/fixtures/normalizer_v1_7"

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

pass() {
  echo "[PASS] $*"
}

command -v jq >/dev/null 2>&1 || fail "jq is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"

[[ -x "$NORMALIZER" ]] || fail "Missing executable normalizer: tools/normalize_v1_7_host.py"
[[ -x "$HOST_CLASSIFIER" ]] || fail "Missing executable host classifier: tools/classify_v1_7_host.py"
[[ -d "$FIXTURE_DIR" ]] || fail "Missing normalizer fixture directory"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

fixture_count=0

for fixture in "$FIXTURE_DIR"/*.json; do
  fixture_count=$((fixture_count + 1))
  name="$(basename "$fixture" .json)"
  normalized="$tmp_dir/$name.normalized.json"

  python3 "$NORMALIZER" \
    --host-record "$fixture" \
    > "$normalized"

  jq empty "$normalized" || fail "Normalizer produced invalid JSON for $name"

  schema_version="$(jq -r '.schema_version' "$normalized")"
  [[ "$schema_version" == "netsniper-normalized-host-v1" ]] \
    || fail "$name produced unexpected schema_version: $schema_version"

  host_id="$(jq -r '.host_id' "$normalized")"
  [[ -n "$host_id" && "$host_id" != "null" && "$host_id" != "unknown-host" ]] \
    || fail "$name produced invalid host_id: $host_id"

  for field in open_ports service_hints vendor_hints http_titles hostname_hints network_roles; do
    jq -e --arg field "$field" '.observed[$field] | type == "array"' "$normalized" >/dev/null \
      || fail "$name missing observed.$field array"
  done

  port_count="$(jq '.observed.open_ports | length' "$normalized")"
  [[ "$port_count" -ge 1 ]] || fail "$name produced no open ports"

  classifier_output="$tmp_dir/$name.classified.json"

  python3 "$HOST_CLASSIFIER" \
    --host-record "$normalized" \
    > "$classifier_output"

  jq empty "$classifier_output" || fail "Classifier failed on normalized host $name"

  primary_type="$(jq -r '.primary_type' "$classifier_output")"
  [[ -n "$primary_type" && "$primary_type" != "null" ]] \
    || fail "$name classifier output missing primary_type"
done

# Specific expected behavior checks.
container_norm="$tmp_dir/container_raw_host.normalized.json"
container_class="$tmp_dir/container_raw_host.classified.json"

jq -e '.observed.open_ports | index("tcp/2375")' "$container_norm" >/dev/null \
  || fail "container_raw_host did not normalize tcp/2375"

[[ "$(jq -r '.primary_type' "$container_class")" == "Container Infrastructure" ]] \
  || fail "container_raw_host did not classify as Container Infrastructure"

printer_norm="$tmp_dir/printer_raw_host.normalized.json"
printer_class="$tmp_dir/printer_raw_host.classified.json"

jq -e '.observed.open_ports | index("tcp/9100")' "$printer_norm" >/dev/null \
  || fail "printer_raw_host did not normalize tcp/9100"

[[ "$(jq -r '.primary_type' "$printer_class")" == "Network Printer / MFP" ]] \
  || fail "printer_raw_host did not classify as Network Printer / MFP"

gateway_norm="$tmp_dir/gateway_raw_host.normalized.json"
gateway_class="$tmp_dir/gateway_raw_host.classified.json"

jq -e '.observed.network_roles | index("default_gateway")' "$gateway_norm" >/dev/null \
  || fail "gateway_raw_host did not normalize default_gateway role"

[[ "$(jq -r '.primary_type' "$gateway_class")" == "Router / Gateway" ]] \
  || fail "gateway_raw_host did not classify as Router / Gateway"

[[ "$fixture_count" -ge 3 ]] || fail "Expected at least 3 normalizer fixtures, found $fixture_count"

pass "NetSniper v1.7 host normalizer produced valid observed records"
pass "Normalizer fixtures: $fixture_count"
pass "Normalized records classify successfully"
