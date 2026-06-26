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

python3 -m py_compile \
    tools/resolve_v1_9_scan_profile.py \
    tools/plan_v1_9_scan_command.py \
    || fail "v1.9 profile planning Python syntax check failed"

./tools/validate_v1_9_profile_cli_parsing.sh \
    || fail "profile CLI parsing validator failed"

for profile in quick balanced accurate deep; do
    python3 tools/plan_v1_9_scan_command.py "$profile" >/tmp/netsniper-plan-"$profile".json
    jq empty /tmp/netsniper-plan-"$profile".json \
        || fail "planner emitted invalid JSON for $profile"

    jq -e --arg profile "$profile" '
      .schema_version == "netsniper-scan-command-plan-v1"
      and .profile == $profile
      and (.tcp.enabled == true)
      and (.tcp.args | type == "array")
      and (.os_detection.args | type == "array")
      and (.udp_lite.args | type == "array")
    ' /tmp/netsniper-plan-"$profile".json >/dev/null \
        || fail "planner emitted invalid structure for $profile"
done

jq -e '
  .profile == "quick"
  and .manual_only == false
  and .deltaaegis_safe_default == true
  and .tcp.port_mode == "curated"
  and (.tcp.args == ["-sV", "-T4", "-p", "$TRUEAEGIS_PORTS"])
  and .os_detection.enabled == false
  and .udp_lite.enabled == false
  and .safety.full_tcp == false
  and .safety.intrusive_scripts == false
' /tmp/netsniper-plan-quick.json >/dev/null \
    || fail "quick profile command plan is incorrect"

jq -e '
  .profile == "balanced"
  and .manual_only == false
  and .deltaaegis_safe_default == true
  and .tcp.port_mode == "curated"
  and (.tcp.args == ["-sV", "-T4", "-p", "$TRUEAEGIS_PORTS"])
  and .os_detection.enabled == false
  and .udp_lite.enabled == false
  and .safety.full_tcp == false
  and .safety.intrusive_scripts == false
' /tmp/netsniper-plan-balanced.json >/dev/null \
    || fail "balanced profile command plan is not v1.8-compatible"

jq -e '
  .profile == "accurate"
  and .manual_only == false
  and .deltaaegis_safe_default == false
  and .tcp.port_mode == "curated"
  and (.tcp.args == ["-sV", "-T4", "--version-intensity", "7", "-p", "$TRUEAEGIS_PORTS"])
  and .os_detection.enabled == true
  and .os_detection.evidence_only == true
  and (.os_detection.args == ["-O"])
  and .udp_lite.enabled == true
  and (.udp_lite.args == ["-sU", "-p", "53,67,68,123,137,161,1900,5353,5355"])
  and .safety.full_tcp == false
  and .safety.intrusive_scripts == false
' /tmp/netsniper-plan-accurate.json >/dev/null \
    || fail "accurate profile command plan is incorrect"

jq -e '
  .profile == "deep"
  and .manual_only == true
  and .deltaaegis_safe_default == false
  and .tcp.port_mode == "full"
  and (.tcp.args == ["-sV", "-T3", "--version-intensity", "9", "-p-"])
  and .os_detection.enabled == true
  and .os_detection.evidence_only == true
  and (.os_detection.args == ["-O"])
  and .udp_lite.enabled == true
  and .safety.full_tcp == true
  and .safety.intrusive_scripts == false
' /tmp/netsniper-plan-deep.json >/dev/null \
    || fail "deep profile command plan is incorrect"

default_profile="$(python3 tools/plan_v1_9_scan_command.py | jq -r '.profile')"
[[ "$default_profile" == "balanced" ]] \
    || fail "default command plan should be balanced"

# Runtime scan behavior must remain unchanged in this planning-only stage.
if grep -Fq -- '--version-intensity' netsniper.sh; then
    fail "runtime netsniper.sh should not use --version-intensity yet"
fi

if grep -Fq -- ' -O ' netsniper.sh; then
    fail "runtime netsniper.sh should not use OS detection yet"
fi

pass "NetSniper v1.9 scan command planner validation passed"
