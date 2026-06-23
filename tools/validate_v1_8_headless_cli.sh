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

bash -n netsniper.sh || fail "netsniper.sh has shell syntax errors"

help_output="$(./netsniper.sh --help 2>&1)"
echo "$help_output" | grep -q -- "--non-interactive" || fail "--help does not mention --non-interactive"
echo "$help_output" | grep -q -- "--target" || fail "--help does not mention --target"
echo "$help_output" | grep -q -- "--json-status" || fail "--help does not mention --json-status"

if timeout 5 ./netsniper.sh --non-interactive --greenbone no >/tmp/netsniper_missing_target.out 2>&1; then
    fail "headless mode without --target unexpectedly succeeded"
fi
grep -q -- "--non-interactive requires --target" /tmp/netsniper_missing_target.out \
    || fail "missing target error was not clear"

if timeout 5 ./netsniper.sh --non-interactive --target not-a-cidr --greenbone no >/tmp/netsniper_bad_target.out 2>&1; then
    fail "invalid CIDR unexpectedly succeeded"
fi
grep -q -- "Invalid or unsafe target" /tmp/netsniper_bad_target.out \
    || fail "invalid CIDR error was not clear"

if timeout 5 ./netsniper.sh --non-interactive --target 8.8.8.0/24 --greenbone no >/tmp/netsniper_public_target.out 2>&1; then
    fail "public CIDR unexpectedly succeeded"
fi
grep -q -- "Invalid or unsafe target" /tmp/netsniper_public_target.out \
    || fail "public CIDR rejection was not clear"

if timeout 5 ./netsniper.sh --non-interactive --target 192.168.5.0/24 --greenbone maybe >/tmp/netsniper_bad_greenbone.out 2>&1; then
    fail "invalid Greenbone option unexpectedly succeeded"
fi
grep -q -- "--greenbone must be yes or no" /tmp/netsniper_bad_greenbone.out \
    || fail "invalid Greenbone option error was not clear"

if timeout 5 ./netsniper.sh --non-interactive --target 192.168.5.0/24 --greenbone yes --json-status >/tmp/netsniper_greenbone_yes.out 2>&1; then
    fail "headless Greenbone yes unexpectedly succeeded in checkpoint 1"
fi
grep -q -- "Headless Greenbone launch is not enabled" /tmp/netsniper_greenbone_yes.out \
    || fail "headless Greenbone yes rejection was not clear"
grep -q -- '"status": "failed"' /tmp/netsniper_greenbone_yes.out \
    || fail "json-status failure object was not emitted"

NETSNIPER_TEST_MODE=1 bash -c 'source ./netsniper.sh; type parse_cli_args >/dev/null; type run_headless_pipeline >/dev/null' \
    || fail "headless functions are not available under NETSNIPER_TEST_MODE"

pass "NetSniper v1.8 headless CLI validation passed"
