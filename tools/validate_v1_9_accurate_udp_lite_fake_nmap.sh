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

for file in udp_lite.xml udp_lite.gnmap udp_lite.nmap; do
    [ -s "$latest_run/$file" ] \
        || fail "missing UDP-lite evidence artifact: $latest_run/$file"
done

jq -e '
  .scan_profile_effective == "accurate"
  and .scan_profile_runtime_stage == "accurate_tcp_service_depth_os_udp_lite"
  and .udp_lite_available == true
  and .files.udp_lite_xml == "udp_lite.xml"
  and .files.udp_lite_gnmap == "udp_lite.gnmap"
  and .files.udp_lite_nmap == "udp_lite.nmap"
' "$latest_run/manifest.json" >/dev/null \
    || {
        jq . "$latest_run/manifest.json" >&2
        fail "UDP-lite manifest metadata is incorrect"
    }

pass "NetSniper v1.9 accurate UDP-lite fake-nmap validation passed"
pass "Fake run: $latest_run"
