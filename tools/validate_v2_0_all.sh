#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

ok() {
    echo "[PASS] $1"
}

run_step() {
    local label="$1"
    shift

    echo "[*] $label"
    "$@" || fail "$label failed"
}

cd "$(dirname "$0")/.." || exit 1

bash -n netsniper.sh \
    || fail "netsniper.sh has shell syntax errors"

grep -Eq 'SCANNER_VERSION="v(2\.0\.0(-dev)?|2\.1\.0-dev)"' netsniper.sh \
    || fail "SCANNER_VERSION must be v2.0.0-dev, v2.0.0, or v2.1.0-dev"

# Run the expensive v1.9 compatibility/fake-Nmap suite exactly once.
# This produces a fresh valid bundle for the later v2 validators to inspect.
run_step "v1.9 compatibility validators" \
    ./tools/validate_v1_9_all.sh

# Status contract is cheap and independent.
run_step "v2.0 status contract" \
    ./tools/validate_v2_0_status_contract.sh

# The remaining v2 validators inspect the already-generated bundle and their
# own structural contracts. Nested prerequisite validators are intentionally
# skipped here to avoid rerunning fake-Nmap scans multiple times.
run_step "v2.0 manifest v3 contract" \
    env NETSNIPER_SKIP_NESTED_VALIDATORS=1 ./tools/validate_v2_0_manifest_v3.sh

run_step "v2.0 profile budget contract" \
    env NETSNIPER_SKIP_NESTED_VALIDATORS=1 ./tools/validate_v2_0_profile_budgets.sh

run_step "v2.0 bundle quality contract" \
    env NETSNIPER_SKIP_NESTED_VALIDATORS=1 ./tools/validate_v2_0_bundle_quality.sh

run_step "v2.0 DeltaAegis fixtures" \
    ./tools/validate_v2_0_deltaaegis_fixtures.sh

ok "All NetSniper v2.0 validators passed"
