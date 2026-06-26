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

grep -Fq 'plan_v1_9_scan_command.py' netsniper.sh \
    || fail "runtime scan does not call v1.9 command planner"

grep -Fq 'mapfile -t TCP_SCAN_ARGS' netsniper.sh \
    || fail "runtime scan does not load planner TCP args"

grep -Fq 'nmap "${TCP_SCAN_ARGS[@]}"' netsniper.sh \
    || fail "runtime nmap command is not planner-driven"

grep -Fq 'v1.8-compatible quick/balanced planner emits: nmap -sV -T4 -p "$TRUEAEGIS_PORTS"' netsniper.sh \
    || fail "v1.8 compatibility marker missing"

for profile in quick balanced; do
    plan="/tmp/netsniper-runtime-plan-$profile.json"
    python3 tools/plan_v1_9_scan_command.py "$profile" > "$plan"
    jq -e '
      .tcp.args == ["-sV", "-T4", "-p", "$TRUEAEGIS_PORTS"]
      and .os_detection.enabled == false
      and .udp_lite.enabled == false
      and .safety.full_tcp == false
      and .safety.intrusive_scripts == false
    ' "$plan" >/dev/null \
        || fail "$profile profile is no longer v1.8-compatible"
done

# Deep must still be blocked until its runtime path is explicitly validated.
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

grep -Fq "Scan profile 'deep' is planned but runtime execution is not enabled" \
    /tmp/netsniper-deep-runtime-block.out \
    || fail "deep block message missing"

python3 tools/plan_v1_9_scan_command.py accurate >/tmp/netsniper-runtime-plan-accurate.json
jq -e '
  .tcp.args == ["-sV", "-T4", "--version-intensity", "7", "-p", "$TRUEAEGIS_PORTS"]
  and .os_detection.enabled == true
  and .udp_lite.enabled == true
' /tmp/netsniper-runtime-plan-accurate.json >/dev/null \
    || fail "accurate TCP service-depth plan is incorrect"

# OS evidence is now wired for accurate only; UDP-lite should still not be wired.
if grep -Fq -- ' -sU ' netsniper.sh; then
    fail "runtime netsniper.sh should not use UDP-lite yet"
fi

pass "NetSniper v1.9 quick/balanced runtime planner validation passed"
