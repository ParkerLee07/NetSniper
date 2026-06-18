#!/usr/bin/env bash
set -euo pipefail

bundle_dir="${1:-}"

find_latest_manifest() {
  find . -name manifest.json -printf '%T@ %p\n' 2>/dev/null \
    | sort -nr \
    | head -1 \
    | cut -d' ' -f2-
}

if [ -z "$bundle_dir" ]; then
  manifest="$(find_latest_manifest || true)"
  if [ -n "$manifest" ]; then
    bundle_dir="$(dirname "$manifest")"
  fi
fi

if [ -z "$bundle_dir" ] || [ ! -d "$bundle_dir" ]; then
  echo "[-] No bundle directory found."
  echo
  echo "[*] I searched the repo for manifest.json and found:"
  find . -name manifest.json -printf '    %p\n' 2>/dev/null | head -20 || true
  echo
  echo "Usage: $0 [path/to/bundle_dir]"
  exit 1
fi

manifest_file="$bundle_dir/manifest.json"
analysis_file="$bundle_dir/analysis.json"

echo "[*] Validating NetSniper v1.4 telemetry bundle:"
echo "    $bundle_dir"

if [ ! -f "$manifest_file" ]; then
  echo "[-] Missing manifest.json in: $bundle_dir"
  exit 1
fi

if [ ! -f "$analysis_file" ]; then
  echo "[-] Missing analysis.json in: $bundle_dir"
  exit 1
fi

jq empty "$manifest_file" >/dev/null
jq empty "$analysis_file" >/dev/null

schema_version="$(jq -r '.schema_version // "missing"' "$manifest_file")"
scanner_version="$(jq -r '.scanner_version // "missing"' "$manifest_file")"
host_count="$(jq 'length' "$analysis_file")"

echo "[*] Manifest schema: $schema_version"
echo "[*] Scanner version: $scanner_version"
echo "[*] Analysis hosts:  $host_count"

if [ "$host_count" -eq 0 ]; then
  echo "[-] analysis.json contains zero hosts."
  exit 1
fi

missing_classification="$(jq '
  [
    .[] |
    select(
      (.classification? == null) or
      (.classification.schema_version? == null) or
      (.classification.type? == null) or
      (.classification.primary_type? == null) or
      (.classification.confidence? == null) or
      (.classification.confidence_label? == null) or
      (.classification.decision? == null) or
      (.classification.method? == null) or
      (.classification.evidence? == null) or
      (.classification.contradictions? == null) or
      (.classification.candidates? == null) or
      (.classification.secondary_candidates? == null)
    )
  ] | length
' "$analysis_file")"

if [ "$missing_classification" -ne 0 ]; then
  echo "[-] Bundle analysis.json is missing required v1.4 classification fields."
  exit 1
fi

echo "[+] PASS: Bundle contains valid NetSniper v1.4 intelligence."
echo
echo "[*] Bundle classification summary:"
jq -r '
  {
    hosts: length,
    classified: ([.[] | select(.classification.decision == "classified")] | length),
    possible: ([.[] | select(.classification.decision == "possible")] | length),
    unknown: ([.[] | select(.classification.decision == "unknown")] | length),
    contradictions: ([.[] | select((.classification.contradictions // []) | length > 0)] | length)
  }
' "$analysis_file"

echo
echo "[*] Preview:"
jq -r '
  .[] |
  [
    .host,
    .device_type,
    (.device_type_confidence | tostring),
    .classification.decision,
    .classification.type,
    (.classification.confidence | tostring),
    ((.classification.evidence // []) | length | tostring)
  ] | @tsv
' "$analysis_file" | column -t -s $'\t' | head -20
