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

./tools/validate_v1_9_accurate_tcp_runtime_fake_nmap.sh \
    || fail "accurate fake-nmap runtime validator failed"

latest_run="$(ls -td runs/* 2>/dev/null | head -1)"
[ -n "$latest_run" ] || fail "no run directory found after fake-nmap validation"

for file in os_detection.xml os_detection.gnmap os_detection.nmap; do
    [ -s "$latest_run/$file" ] \
        || fail "missing OS evidence artifact: $latest_run/$file"
done

jq -e '
  .scan_profile_effective == "accurate"
  and .scan_profile_runtime_stage == "accurate_tcp_service_depth_os_udp_lite"
  and .os_detection_available == true
  and .files.os_detection_xml == "os_detection.xml"
  and .files.os_detection_gnmap == "os_detection.gnmap"
  and .files.os_detection_nmap == "os_detection.nmap"
' "$latest_run/manifest.json" >/dev/null \
    || {
        jq . "$latest_run/manifest.json" >&2
        fail "OS evidence manifest metadata is incorrect"
    }

pass "NetSniper v1.9 accurate OS evidence fake-nmap validation passed"
pass "Fake run: $latest_run"
