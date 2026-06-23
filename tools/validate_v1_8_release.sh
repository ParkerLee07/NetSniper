#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

pass() {
    echo "[PASS] $*"
}

grep -q 'SCANNER_VERSION="v1.8.0"' netsniper.sh \
    || fail "SCANNER_VERSION is not finalized as v1.8.0"

if grep -q 'SCANNER_VERSION="v1.8.0-dev"' netsniper.sh; then
    fail "Development version marker still present"
fi

grep -q 'NETSNIPER v1.8' netsniper.sh \
    || fail "Banner does not show NETSNIPER v1.8"

if grep -q 'Scan completes' netsniper.sh; then
    fail "Old 'Scan completes' wording is still present"
fi

grep -q 'Current release: \*\*NetSniper v1.8.0 — Headless Full-Inventory Telemetry\*\*' README.md \
    || fail "README current release does not point to v1.8.0"

grep -q '^## v1.8.0 - 2026-06-23' CHANGELOG.md \
    || fail "CHANGELOG missing v1.8.0 entry"

grep -q -- '--non-interactive' README.md \
    || fail "README does not mention --non-interactive"

grep -q 'full discovered inventory preservation' CHANGELOG.md \
    || fail "CHANGELOG does not mention full discovered inventory preservation"

[ -x tools/validate_v1_8_headless_cli.sh ] \
    || fail "Missing executable v1.8 headless CLI validator"

[ -x tools/validate_v1_8_full_inventory_bundle.sh ] \
    || fail "Missing executable v1.8 full inventory validator"

./tools/validate_v1_8_headless_cli.sh
./tools/validate_v1_8_full_inventory_bundle.sh
./tools/validate_v1_7_all.sh

pass "NetSniper v1.8 release validation passed"
