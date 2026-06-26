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

grep -Fq 'SCAN_PROFILE_RUNTIME_STAGE="v1_8_compatible_tcp"' netsniper.sh \
    || fail "runtime stage default is missing"

grep -Fq 'quick|balanced)' netsniper.sh \
    || fail "runtime guard does not allow quick/balanced"

grep -Fq 'accurate)' netsniper.sh \
    || fail "runtime guard does not allow accurate TCP stage"

grep -Fq 'accurate_tcp_service_depth' netsniper.sh \
    || fail "accurate TCP runtime stage marker missing"

grep -Fq 'deep)' netsniper.sh \
    || fail "runtime guard does not explicitly block deep"

if grep -Fq 'accurate|deep)' netsniper.sh; then
    fail "accurate should no longer be blocked with deep"
fi

python3 tools/plan_v1_9_scan_command.py accurate >/tmp/netsniper-accurate-plan.json

jq -e '
  .profile == "accurate"
  and (.tcp.args == ["-sV", "-T4", "--version-intensity", "7", "-p", "$TRUEAEGIS_PORTS"])
  and .os_detection.enabled == true
  and .udp_lite.enabled == true
' /tmp/netsniper-accurate-plan.json >/dev/null \
    || fail "accurate planner no longer contains expected TCP service-depth plan"

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

# OS detection and UDP-lite should still not be wired into netsniper.sh runtime.
if grep -Fq -- ' -O ' netsniper.sh; then
    fail "OS detection should not be added to runtime scan behavior in this stage"
fi

if grep -Fq -- ' -sU ' netsniper.sh; then
    fail "UDP-lite should not be added to runtime scan behavior in this stage"
fi

pass "NetSniper v1.9 profile runtime guard validation passed"
