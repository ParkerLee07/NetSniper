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

python3 -m py_compile tools/resolve_v1_9_scan_profile.py \
    || fail "profile resolver has Python syntax errors"

./tools/validate_v1_9_scan_profile_contract.sh \
    || fail "scan profile contract validator failed"

grep -Fq -- '--profile <name>' netsniper.sh \
    || fail "usage does not mention --profile"

grep -Fq -- '--scan-profile <name>' netsniper.sh \
    || fail "usage does not mention --scan-profile"

grep -Fq -- '--profile|--scan-profile)' netsniper.sh \
    || fail "argument parser does not handle profile aliases"

grep -Fq 'NETSNIPER_SCAN_PROFILE:-balanced' netsniper.sh \
    || fail "balanced default profile is not configured"

grep -Fq 'resolve_v1_9_scan_profile.py' netsniper.sh \
    || fail "netsniper.sh does not call profile resolver"

for profile in quick balanced accurate deep; do
    resolved="$(python3 tools/resolve_v1_9_scan_profile.py "$profile" --name-only)"
    [[ "$resolved" == "$profile" ]] \
        || fail "profile resolver returned $resolved for $profile"
done

default_resolved="$(python3 tools/resolve_v1_9_scan_profile.py --name-only)"
[[ "$default_resolved" == "balanced" ]] \
    || fail "default profile should resolve to balanced"

if python3 tools/resolve_v1_9_scan_profile.py invalid-profile >/tmp/netsniper-profile-invalid.out 2>&1; then
    cat /tmp/netsniper-profile-invalid.out >&2
    fail "invalid profile unexpectedly resolved"
fi

grep -Fq "invalid scan profile" /tmp/netsniper-profile-invalid.out \
    || fail "invalid profile error message is not useful"

help_output="$(./netsniper.sh --help 2>&1 || true)"
grep -Fq -- '--profile <name>' <<<"$help_output" \
    || fail "--help output missing --profile"
grep -Fq -- '--scan-profile <name>' <<<"$help_output" \
    || fail "--help output missing --scan-profile"

if ./netsniper.sh \
    --non-interactive \
    --target 192.168.56.0/30 \
    --greenbone no \
    --json-status \
    --profile invalid-profile \
    >/tmp/netsniper-invalid-profile-cli.out 2>&1; then
    cat /tmp/netsniper-invalid-profile-cli.out >&2
    fail "invalid CLI profile unexpectedly succeeded"
fi

grep -Fq "Invalid scan profile" /tmp/netsniper-invalid-profile-cli.out \
    || fail "CLI invalid profile rejection message missing"

python3 - <<'PY'
from pathlib import Path

text = Path("netsniper.sh").read_text(encoding="utf-8")

assert "-sV" in text, "service detection flag disappeared"
assert "-T4" in text, "default timing flag disappeared"
assert "$TRUEAEGIS_PORTS" in text, "curated monitored TCP ports disappeared"

if "--version-intensity" in text:
    raise SystemExit("version intensity should not be added to runtime scan behavior in this stage")

if " -O " in text or "\n-O " in text:
    raise SystemExit("OS detection should not be added to runtime scan behavior in this stage")

print("[PASS] default scan command behavior remains v1.8-like")
PY

pass "NetSniper v1.9 profile CLI parsing validation passed"
