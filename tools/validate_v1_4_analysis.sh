#!/usr/bin/env bash
set -euo pipefail

analysis_file="${1:-}"

if [ -z "$analysis_file" ]; then
  analysis_file=$(find targets -name 'analysis_*.json' -printf '%T@ %p\n' 2>/dev/null \
    | sort -nr \
    | head -1 \
    | cut -d' ' -f2-)
fi

if [ -z "$analysis_file" ] || [ ! -f "$analysis_file" ]; then
  echo "[-] No analysis JSON found."
  echo "Usage: $0 [path/to/analysis.json]"
  exit 1
fi

echo "[*] Validating NetSniper v1.4 analysis file:"
echo "    $analysis_file"

jq empty "$analysis_file" >/dev/null

host_count=$(jq 'length' "$analysis_file")

if [ "$host_count" -eq 0 ]; then
  echo "[-] Analysis file contains zero hosts."
  exit 1
fi

missing_required=$(jq '
  [
    .[] |
    select(
      (.host? == null) or
      (.device_type? == null) or
      (.device_type_confidence? == null) or
      (.scanner_version? == null) or
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
' "$analysis_file")

if [ "$missing_required" -ne 0 ]; then
  echo "[-] Some hosts are missing required v1.4 classification fields."
  jq '
    .[] |
    select(
      (.classification? == null) or
      (.classification.type? == null) or
      (.classification.decision? == null) or
      (.classification.candidates? == null)
    ) |
    {host, device_type, classification}
  ' "$analysis_file"
  exit 1
fi

bad_decisions=$(jq '
  [
    .[] |
    select(
      (.classification.decision != "classified") and
      (.classification.decision != "possible") and
      (.classification.decision != "unknown")
    )
  ] | length
' "$analysis_file")

if [ "$bad_decisions" -ne 0 ]; then
  echo "[-] Invalid classification.decision value found."
  exit 1
fi

bad_confidence_logic=$(jq '
  [
    .[] |
    select(
      (
        (.classification.confidence >= 40) and
        (.classification.decision != "classified")
      ) or
      (
        (.classification.confidence > 0 and .classification.confidence < 40) and
        (.classification.decision != "possible")
      ) or
      (
        (.classification.confidence == 0) and
        (.classification.decision != "unknown")
      )
    )
  ] | length
' "$analysis_file")

if [ "$bad_confidence_logic" -ne 0 ]; then
  echo "[-] Classification confidence/decision mismatch found."
  jq '
    .[] |
    select(
      (
        (.classification.confidence >= 40) and
        (.classification.decision != "classified")
      ) or
      (
        (.classification.confidence > 0 and .classification.confidence < 40) and
        (.classification.decision != "possible")
      ) or
      (
        (.classification.confidence == 0) and
        (.classification.decision != "unknown")
      )
    ) |
    {
      host,
      device_type,
      confidence: .classification.confidence,
      decision: .classification.decision
    }
  ' "$analysis_file"
  exit 1
fi

echo "[+] PASS: v1.4 analysis schema is valid."
echo
echo "[*] Summary:"
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
echo "[*] Top classifications:"
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
' "$analysis_file" | column -t -s $'\t' | head -30
