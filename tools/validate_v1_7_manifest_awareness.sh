#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MAIN_SCRIPT="$ROOT_DIR/netsniper.sh"

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

pass() {
  echo "[PASS] $*"
}

[[ -f "$MAIN_SCRIPT" ]] || fail "Missing netsniper.sh"

grep -q 'analysis_json: "analysis.json"' "$MAIN_SCRIPT" \
  || fail "Manifest is missing analysis_json reference"

grep -q 'analysis_enriched_json: "analysis.enriched.json"' "$MAIN_SCRIPT" \
  || fail "Manifest is missing analysis_enriched_json reference"

grep -q 'classification_quality_json: "classification_quality.json"' "$MAIN_SCRIPT" \
  || fail "Manifest is missing classification_quality_json reference"

grep -q 'classification_quality_markdown: "classification_quality.md"' "$MAIN_SCRIPT" \
  || fail "Manifest is missing classification_quality_markdown reference"

artifact_line="$(grep -n 'generate_v1_7_run_artifacts.sh' "$MAIN_SCRIPT" | head -1 | cut -d: -f1)"
manifest_line="$(grep -n 'classification_quality_json: "classification_quality.json"' "$MAIN_SCRIPT" | head -1 | cut -d: -f1)"

[[ -n "$artifact_line" && -n "$manifest_line" ]] \
  || fail "Could not locate artifact or manifest lines"

[[ "$artifact_line" -lt "$manifest_line" ]] \
  || fail "v1.7 artifacts should be generated before manifest references are finalized"

pass "NetSniper v1.7 manifest references enriched classification artifacts"
pass "Manifest includes analysis.enriched.json and classification quality reports"
