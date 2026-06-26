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

grep -q 'SCANNER_VERSION="v1.9.0"' netsniper.sh \
    || fail "SCANNER_VERSION is not finalized as v1.9.0"

if grep -q 'SCANNER_VERSION="v1.9.0-dev"' netsniper.sh; then
    fail "Development version marker still present"
fi

grep -q 'NETSNIPER v1.9' netsniper.sh \
    || fail "Banner does not show NETSNIPER v1.9"

grep -q 'Current release: \*\*NetSniper v1.9.0 — Accuracy Profiles and Evidence Passes\*\*' README.md \
    || fail "README current release does not point to v1.9.0"

grep -q '^## v1.9.0 - 2026-06-26' CHANGELOG.md \
    || fail "CHANGELOG missing v1.9.0 entry"

grep -q './tools/validate_v1_9_release.sh' README.md \
    || fail "README does not recommend the v1.9 release gate"

grep -q -- '--profile' README.md \
    || fail "README does not mention --profile"

grep -q 'os_detection.xml' README.md \
    || fail "README does not mention OS evidence artifacts"

grep -q 'udp_lite.xml' README.md \
    || fail "README does not mention UDP-lite evidence artifacts"

grep -q 'accurate_tcp_service_depth_os_udp_lite' netsniper.sh \
    || fail "accurate runtime stage marker missing"

grep -q 'Change Scan Profile' netsniper.sh \
    || fail "interactive menu does not expose profile selection"

grep -q 'SCAN_PROFILE_B64=' netsniper.sh \
    || fail "saved config does not persist scan profile"

[ -x tools/validate_v1_9_all.sh ] \
    || fail "Missing executable v1.9 all validator"

[ -x tools/validate_v1_9_accurate_udp_lite_fake_nmap.sh ] \
    || fail "Missing executable v1.9 UDP-lite fake-Nmap validator"

[ -x tools/validate_v1_9_interactive_profile_config.sh ] \
    || fail "Missing executable v1.9 interactive profile config validator"

./tools/validate_v1_9_all.sh
./tools/validate_v1_8_headless_cli.sh
./tools/validate_v1_8_full_inventory_bundle.sh
./tools/validate_v1_7_all.sh

latest_run="$(ls -td runs/* 2>/dev/null | head -1)"
[ -n "$latest_run" ] || fail "No run directory found after validation"
[ -s "$latest_run/manifest.json" ] || fail "Latest run manifest missing"

jq -e '
  .scanner_version == "v1.9.0"
  and .schema_version == "netsniper-run-v2"
  and .scan_profile_requested == "accurate"
  and .scan_profile_effective == "accurate"
  and .scan_profile_runtime_stage == "accurate_tcp_service_depth_os_udp_lite"
  and .os_detection_available == true
  and .udp_lite_available == true
  and .files.os_detection_xml == "os_detection.xml"
  and .files.udp_lite_xml == "udp_lite.xml"
' "$latest_run/manifest.json" >/dev/null \
    || {
        jq . "$latest_run/manifest.json" >&2
        fail "Latest v1.9 fake-Nmap manifest does not contain expected v1.9 metadata"
    }

pass "NetSniper v1.9 release validation passed"
