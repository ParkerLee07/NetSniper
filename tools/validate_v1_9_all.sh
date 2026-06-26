#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

pass() {
    echo "[PASS] $1"
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

bash -n netsniper.sh || fail "netsniper.sh has shell syntax errors"

./tools/validate_v1_9_scan_profile_contract.sh
./tools/validate_v1_9_profile_cli_parsing.sh
./tools/validate_v1_9_scan_command_planner.sh
./tools/validate_v1_9_profile_runtime_guard.sh
./tools/validate_v1_9_manifest_profile_metadata.sh
./tools/validate_v1_9_quick_balanced_runtime_planner.sh
./tools/validate_v1_9_accurate_tcp_runtime_fake_nmap.sh

pass "All NetSniper v1.9 fast validators passed"
