#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MAIN_SCRIPT="$ROOT_DIR/netsniper.sh"
GENERATOR="$ROOT_DIR/tools/generate_v1_7_run_artifacts.sh"

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

pass() {
  echo "[PASS] $*"
}

[[ -f "$MAIN_SCRIPT" ]] || fail "Missing netsniper.sh"
[[ -x "$GENERATOR" ]] || fail "Missing executable v1.7 artifact generator"

grep -q 'cp "\$analysis_json" "\$bundle_dir/analysis.json"' "$MAIN_SCRIPT" \
  || fail "netsniper.sh no longer copies analysis_json into bundle analysis.json"

grep -q 'generate_v1_7_run_artifacts.sh' "$MAIN_SCRIPT" \
  || fail "netsniper.sh does not call the v1.7 artifact generator"

grep -q 'classification artifacts generated' "$MAIN_SCRIPT" \
  || fail "netsniper.sh missing v1.7 artifact success message"

grep -q 'artifact generation failed' "$MAIN_SCRIPT" \
  || fail "netsniper.sh missing non-fatal failure warning"

grep -q 'Artifact generation is intentionally non-fatal' "$MAIN_SCRIPT" \
  || fail "netsniper.sh missing non-fatal design comment"

if grep -n 'generate_v1_7_run_artifacts.sh' "$MAIN_SCRIPT" | grep -q 'exit 1'; then
  fail "v1.7 artifact generation appears to be fatal"
fi

pass "NetSniper v1.7 artifact generation is hooked into bundle finalization"
pass "Artifact generation is non-fatal"
