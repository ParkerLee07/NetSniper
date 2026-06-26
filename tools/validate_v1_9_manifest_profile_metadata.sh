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

./tools/validate_v1_9_profile_runtime_guard.sh \
    || fail "profile runtime guard validator failed"

grep -Fq -- '--arg scan_profile "FAST_MONITORED_TCP"' netsniper.sh \
    || fail "legacy FAST_MONITORED_TCP scan_profile arg was removed"

grep -Fq -- '--arg scan_profile_requested "$SCAN_PROFILE"' netsniper.sh \
    || fail "manifest does not record requested v1.9 scan profile"

grep -Fq -- '--arg scan_profile_effective "$SCAN_PROFILE_EFFECTIVE"' netsniper.sh \
    || fail "manifest does not record effective v1.9 scan profile"

grep -Fq -- '--arg scan_profile_runtime_stage "$SCAN_PROFILE_RUNTIME_STAGE"' netsniper.sh \
    || fail "manifest does not record v1.9 runtime profile stage"

grep -Fq -- '--arg scan_profile_contract_schema "netsniper-scan-profiles-v1"' netsniper.sh \
    || fail "manifest does not record scan profile contract schema"

grep -Fq 'scan_profile: $scan_profile' netsniper.sh \
    || fail "legacy manifest scan_profile field was removed"

grep -Fq 'scan_profile_requested: $scan_profile_requested' netsniper.sh \
    || fail "manifest scan_profile_requested field missing"

grep -Fq 'scan_profile_effective: $scan_profile_effective' netsniper.sh \
    || fail "manifest scan_profile_effective field missing"

grep -Fq 'scan_profile_runtime_stage: $scan_profile_runtime_stage' netsniper.sh \
    || fail "manifest scan_profile_runtime_stage field missing"

grep -Fq 'os_detection_available: $os_detection_available' netsniper.sh \
    || fail "manifest os_detection_available field missing"

grep -Fq 'udp_lite_available: $udp_lite_available' netsniper.sh \
    || fail "manifest udp_lite_available field missing"

grep -Fq 'os_detection_xml: (if $os_detection_available then "os_detection.xml" else null end)' netsniper.sh \
    || fail "manifest files.os_detection_xml field missing"

grep -Fq 'udp_lite_xml: (if $udp_lite_available then "udp_lite.xml" else null end)' netsniper.sh \
    || fail "manifest files.udp_lite_xml field missing"

grep -Fq 'scan_profile_contract_schema: $scan_profile_contract_schema' netsniper.sh \
    || fail "manifest scan_profile_contract_schema field missing"

python3 - <<'PY'
from pathlib import Path

text = Path("netsniper.sh").read_text(encoding="utf-8")

legacy = text.find('--arg scan_profile "FAST_MONITORED_TCP"')
requested = text.find('--arg scan_profile_requested "$SCAN_PROFILE"')
effective = text.find('--arg scan_profile_effective "$SCAN_PROFILE_EFFECTIVE"')
runtime_stage = text.find('--arg scan_profile_runtime_stage "$SCAN_PROFILE_RUNTIME_STAGE"')
os_available = text.find('--argjson os_detection_available "$os_detection_available"')
udp_available = text.find('--argjson udp_lite_available "$udp_lite_available"')
schema = text.find('--arg scan_profile_contract_schema "netsniper-scan-profiles-v1"')

assert legacy != -1, "legacy scan_profile arg missing"
assert requested != -1, "requested profile arg missing"
assert effective != -1, "effective profile arg missing"
assert runtime_stage != -1, "runtime stage arg missing"
assert os_available != -1, "os_detection_available arg missing"
assert udp_available != -1, "udp_lite_available arg missing"
assert schema != -1, "profile contract schema arg missing"
assert legacy < requested < effective < runtime_stage < os_available < udp_available < schema, "manifest profile args are out of expected order"

legacy_field = text.find('scan_profile: $scan_profile')
requested_field = text.find('scan_profile_requested: $scan_profile_requested')
effective_field = text.find('scan_profile_effective: $scan_profile_effective')
runtime_stage_field = text.find('scan_profile_runtime_stage: $scan_profile_runtime_stage')
os_available_field = text.find('os_detection_available: $os_detection_available')
udp_available_field = text.find('udp_lite_available: $udp_lite_available')
schema_field = text.find('scan_profile_contract_schema: $scan_profile_contract_schema')

assert legacy_field != -1, "legacy scan_profile field missing"
assert requested_field != -1, "requested profile field missing"
assert effective_field != -1, "effective profile field missing"
assert runtime_stage_field != -1, "runtime stage field missing"
assert os_available_field != -1, "os_detection_available field missing"
assert udp_available_field != -1, "udp_lite_available field missing"
assert schema_field != -1, "profile contract schema field missing"
assert legacy_field < requested_field < effective_field < runtime_stage_field < os_available_field < udp_available_field < schema_field, "manifest profile fields are out of expected order"

if "netsniper-run-v2" not in text:
    raise SystemExit("manifest schema compatibility marker disappeared")

print("[PASS] v1.9 manifest profile metadata ordering checks passed")
PY

# This stage must not change actual scan behavior.
if grep -Fq -- '--version-intensity' netsniper.sh; then
    fail "runtime netsniper.sh should not use --version-intensity yet"
fi

if grep -Fq -- ' -O ' netsniper.sh; then
    fail "runtime netsniper.sh should not use OS detection yet"
fi

pass "NetSniper v1.9 manifest profile metadata validation passed"
