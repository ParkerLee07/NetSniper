#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

ok() {
    echo "[PASS] $1"
}

cd "$(dirname "$0")/.." || exit 1

bash -n netsniper.sh \
    || fail "netsniper.sh has a syntax error"

python3 - <<'PY'
import json
from pathlib import Path

data = json.loads(Path("config/scan_profiles.json").read_text(encoding="utf-8"))
profiles = {profile["name"]: profile for profile in data["profiles"]}

expected = {
    "quick": (300, 30, True),
    "balanced": (900, 60, True),
    "accurate": (1800, 120, True),
    "deep": (7200, 300, False),
}

for name, (budget, host_timeout, enforced) in expected.items():
    profile = profiles[name]
    assert profile["runtime_budget_seconds"] == budget, profile
    assert profile["host_timeout_seconds"] == host_timeout, profile
    assert profile["budget_enforced"] is enforced, profile

print("[PASS] v2.0 profile budget config checks passed")
PY

python3 tools/plan_v1_9_scan_command.py quick >/tmp/netsniper-v2-plan-quick.json
python3 tools/plan_v1_9_scan_command.py balanced >/tmp/netsniper-v2-plan-balanced.json
python3 tools/plan_v1_9_scan_command.py accurate >/tmp/netsniper-v2-plan-accurate.json

jq -e '
  .tcp.args == ["-sV", "-T4", "-p", "$TRUEAEGIS_PORTS"]
  and .runtime.runtime_budget_seconds == 300
  and .runtime.host_timeout_seconds == 30
  and .runtime.budget_enforced == true
' /tmp/netsniper-v2-plan-quick.json >/dev/null \
    || fail "quick profile plan should preserve TCP args and expose quick budget metadata"

jq -e '
  .tcp.args == ["-sV", "-T4", "-p", "$TRUEAEGIS_PORTS"]
  and .runtime.runtime_budget_seconds == 900
  and .runtime.host_timeout_seconds == 60
  and .runtime.budget_enforced == true
' /tmp/netsniper-v2-plan-balanced.json >/dev/null \
    || fail "balanced profile plan should preserve TCP args and expose balanced budget metadata"

jq -e '
  .tcp.args == ["-sV", "-T4", "--version-intensity", "7", "-p", "$TRUEAEGIS_PORTS"]
  and .runtime.runtime_budget_seconds == 1800
  and .runtime.host_timeout_seconds == 120
  and .runtime.budget_enforced == true
' /tmp/netsniper-v2-plan-accurate.json >/dev/null \
    || fail "accurate profile plan should expose accurate budget metadata"

grep -Fq 'PROFILE_RUNTIME_BUDGET_SECONDS=' netsniper.sh \
    || fail "runtime budget global missing"

grep -Fq 'PROFILE_HOST_TIMEOUT_SECONDS=' netsniper.sh \
    || fail "host timeout global missing"

grep -Fq 'PROFILE_BUDGET_EXCEEDED=false' netsniper.sh \
    || fail "budget exceeded state missing"

grep -Fq 'timeout "${PROFILE_RUNTIME_BUDGET_SECONDS}s"' netsniper.sh \
    || fail "runtime budget is not enforced through timeout"

grep -Fq 'profile_runtime_budget_seconds' netsniper.sh \
    || fail "status/manifest budget field missing"

if [ "${NETSNIPER_SKIP_NESTED_VALIDATORS:-0}" != "1" ]; then
    ./tools/validate_v2_0_manifest_v3.sh \
        || fail "manifest v3 validator failed after budget changes"
else
    echo "[SKIP] Nested validators skipped in validate_v2_0_profile_budgets.sh"
fi

latest_run="$(ls -td runs/* 2>/dev/null | head -1)"
[ -n "$latest_run" ] \
    || fail "no run directory found"

manifest="$latest_run/manifest.json"
[ -s "$manifest" ] \
    || fail "latest manifest missing: $manifest"

jq -e '
  .schema_version == "netsniper-run-v3"
  and .effective_profile == "accurate"
  and .profile_runtime_budget_seconds == 1800
  and .profile_host_timeout_seconds == 120
  and (.profile_duration_seconds | type == "number")
  and .profile_budget_exceeded == false
  and .profile_runtime.runtime_budget_seconds == .profile_runtime_budget_seconds
  and .profile_runtime.host_timeout_seconds == .profile_host_timeout_seconds
  and .profile_runtime.duration_seconds == .profile_duration_seconds
  and .profile_runtime.budget_exceeded == .profile_budget_exceeded
  and .quality.deltaaegis_ready == true
' "$manifest" >/dev/null \
    || {
        jq . "$manifest" >&2
        fail "latest manifest does not contain v2.0 profile budget metadata"
    }

if [ "${NETSNIPER_SKIP_NESTED_VALIDATORS:-0}" != "1" ]; then
    ./tools/validate_v2_0_status_contract.sh \
        || fail "status contract validator failed after budget changes"
else
    echo "[SKIP] Nested validators skipped in validate_v2_0_profile_budgets.sh"
fi

ok "NetSniper v2.0 profile budget validation passed"
