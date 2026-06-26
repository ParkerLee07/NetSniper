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
    || fail "runtime guard does not allow accurate"

grep -Fq 'accurate_tcp_service_depth_os_evidence' netsniper.sh \
    || fail "accurate OS evidence runtime stage marker missing"

grep -Fq 'deep)' netsniper.sh \
    || fail "runtime guard does not explicitly block deep"

if grep -Fq 'accurate|deep)' netsniper.sh; then
    fail "accurate should not be blocked with deep"
fi

grep -Fq 'Running non-fatal OS evidence pass for accurate profile' netsniper.sh \
    || fail "accurate OS evidence runtime pass is missing"

grep -Fq -- '--osscan-limit' netsniper.sh \
    || fail "OS evidence pass should use --osscan-limit"

python3 tools/plan_v1_9_scan_command.py accurate >/tmp/netsniper-accurate-plan.json

jq -e '
  .profile == "accurate"
  and (.tcp.args == ["-sV", "-T4", "--version-intensity", "7", "-p", "$TRUEAEGIS_PORTS"])
  and .os_detection.enabled == true
  and .os_detection.evidence_only == true
  and (.os_detection.args == ["-O"])
  and .udp_lite.enabled == true
' /tmp/netsniper-accurate-plan.json >/dev/null \
    || fail "accurate planner no longer contains expected TCP plus OS evidence plan"

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

if grep -Fq -- ' -sU ' netsniper.sh; then
    fail "UDP-lite should not be added to runtime scan behavior in this stage"
fi

pass "NetSniper v1.9 profile runtime guard validation passed"
