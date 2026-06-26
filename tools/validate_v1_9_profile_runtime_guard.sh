#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

pass() {
    echo "[PASS] $1"
}

cd "$(dirname "$0")/.." || exit 1

bash -n netsniper.sh || fail "netsniper.sh has shell syntax errors"

./tools/validate_v1_9_scan_command_planner.sh \
    || fail "scan command planner validator failed"

grep -Fq 'SCAN_PROFILE_EFFECTIVE="balanced"' netsniper.sh \
    || fail "effective profile default is missing"

grep -Fq 'quick|balanced)' netsniper.sh \
    || fail "runtime guard does not allow quick/balanced"

grep -Fq 'accurate|deep)' netsniper.sh \
    || fail "runtime guard does not explicitly block accurate/deep"

grep -Fq 'runtime execution is not enabled in this v1.9 checkpoint' netsniper.sh \
    || fail "runtime guard message missing"

if ./netsniper.sh \
    --non-interactive \
    --target 192.168.56.0/30 \
    --greenbone no \
    --json-status \
    --profile accurate \
    >/tmp/netsniper-accurate-guard.out 2>&1; then
    cat /tmp/netsniper-accurate-guard.out >&2
    fail "accurate profile unexpectedly executed before runtime wiring"
fi

grep -Fq "Scan profile 'accurate' is planned but runtime execution is not enabled" \
    /tmp/netsniper-accurate-guard.out \
    || fail "accurate guard message missing"

if ./netsniper.sh \
    --non-interactive \
    --target 192.168.56.0/30 \
    --greenbone no \
    --json-status \
    --profile deep \
    >/tmp/netsniper-deep-guard.out 2>&1; then
    cat /tmp/netsniper-deep-guard.out >&2
    fail "deep profile unexpectedly executed before runtime wiring"
fi

grep -Fq "Scan profile 'deep' is planned but runtime execution is not enabled" \
    /tmp/netsniper-deep-guard.out \
    || fail "deep guard message missing"

# The runtime scan command itself should still remain unchanged at this checkpoint.
if grep -Fq -- '--version-intensity' netsniper.sh; then
    fail "runtime netsniper.sh should not use --version-intensity yet"
fi

if grep -Fq -- ' -O ' netsniper.sh; then
    fail "runtime netsniper.sh should not use OS detection yet"
fi

pass "NetSniper v1.9 profile runtime guard validation passed"
