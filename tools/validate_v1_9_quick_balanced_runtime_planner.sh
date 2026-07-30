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

./tools/validate_v1_9_manifest_profile_metadata.sh \
    || fail "manifest profile metadata validator failed"

python3 tools/plan_v1_9_scan_command.py quick >/tmp/netsniper-runtime-plan-quick.json
python3 tools/plan_v1_9_scan_command.py balanced >/tmp/netsniper-runtime-plan-balanced.json
python3 tools/plan_v1_9_scan_command.py accurate >/tmp/netsniper-runtime-plan-accurate.json

jq -e '
  .tcp.args == ["-sV", "-T4", "-p", "$TRUEAEGIS_PORTS"]
  and .os_detection.enabled == false
  and .udp_lite.enabled == false
' /tmp/netsniper-runtime-plan-quick.json >/dev/null \
    || fail "quick profile should remain TCP-only"

jq -e '
  .tcp.args == ["-sV", "-T4", "-p", "$TRUEAEGIS_PORTS"]
  and .os_detection.enabled == false
  and .udp_lite.enabled == false
' /tmp/netsniper-runtime-plan-balanced.json >/dev/null \
    || fail "balanced profile should remain v1.8-compatible TCP-only"

jq -e '
  .tcp.args == ["-sV", "-T4", "--version-intensity", "7", "-p", "$TRUEAEGIS_PORTS"]
  and .os_detection.enabled == true
  and .udp_lite.enabled == true
' /tmp/netsniper-runtime-plan-accurate.json >/dev/null \
    || fail "accurate TCP/OS/UDP-lite plan is incorrect"

if ./netsniper.sh \
    --non-interactive \
    --target 192.168.56.0/30 \
    --greenbone no \
    --json-status \
    --profile deep \
    >/tmp/netsniper-deep-runtime-block.out 2>&1; then
    cat /tmp/netsniper-deep-runtime-block.out >&2
    fail "deep profile unexpectedly executed before runtime wiring"
fi

grep -Fq "Scan profile 'deep' is not supported" \
    /tmp/netsniper-deep-runtime-block.out \
    || fail "deep block message missing"

pass "NetSniper v1.9 quick/balanced runtime planner validation passed"
