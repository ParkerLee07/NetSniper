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

grep -q 'SCANNER_VERSION="v1.7.0"' "$ROOT_DIR/netsniper.sh" \
  || fail "netsniper.sh SCANNER_VERSION is not v1.7.0"

grep -q 'NETSNIPER v1.7' "$ROOT_DIR/netsniper.sh" \
  || fail "netsniper.sh banner does not show v1.7"

grep -q 'NetSniper v1.7.0 — Device Intelligence Expansion' "$ROOT_DIR/README.md" \
  || fail "README is missing v1.7 title"

grep -q 'Current release: \*\*NetSniper v1.7.0 — Device Intelligence Expansion\*\*' "$ROOT_DIR/README.md" \
  || fail "README current release does not point to v1.7.0"

grep -q 'analysis.enriched.json' "$ROOT_DIR/README.md" \
  || fail "README missing analysis.enriched.json documentation"

grep -q 'classification_quality.json' "$ROOT_DIR/README.md" \
  || fail "README missing classification_quality.json documentation"

grep -q 'classification_quality.md' "$ROOT_DIR/README.md" \
  || fail "README missing classification_quality.md documentation"

grep -q '^## v1.7.0 - 2026-06-19' "$ROOT_DIR/CHANGELOG.md" \
  || fail "CHANGELOG missing v1.7.0 entry"

grep -q 'validate_v1_7_release_gate.sh' "$ROOT_DIR/CHANGELOG.md" \
  || fail "CHANGELOG missing v1.7 release gate mention"

pass "NetSniper v1.7 docs and version markers are current"
