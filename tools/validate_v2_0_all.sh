#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

ok() {
    echo "[PASS] $1"
}

cd "$(dirname "$0")/.." || exit 1

bash -n netsniper.sh \
    || fail "netsniper.sh has shell syntax errors"

grep -Eq 'SCANNER_VERSION="v2\.0\.0(-dev)?"' netsniper.sh \
    || fail "SCANNER_VERSION must be v2.0.0-dev or v2.0.0"

./tools/validate_v2_0_status_contract.sh \
    || fail "v2.0 status contract validator failed"

./tools/validate_v2_0_manifest_v3.sh \
    || fail "v2.0 manifest v3 validator failed"

./tools/validate_v2_0_profile_budgets.sh \
    || fail "v2.0 profile budget validator failed"

./tools/validate_v2_0_bundle_quality.sh \
    || fail "v2.0 bundle quality validator failed"

./tools/validate_v2_0_deltaaegis_fixtures.sh \
    || fail "v2.0 DeltaAegis fixture validator failed"

./tools/validate_v1_9_all.sh \
    || fail "v1.9 compatibility validators failed"

ok "All NetSniper v2.0 validators passed"
