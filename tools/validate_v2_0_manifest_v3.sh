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

grep -Eq 'SCANNER_VERSION="v(2\.0\.0(-dev)?|2\.1\.0-dev)"' netsniper.sh \
    || fail "scanner version is not v2.0.0-dev, v2.0.0, or v2.1.0-dev"

grep -Fq 'netsniper-run-v3' netsniper.sh \
    || fail "manifest v3 schema marker missing"

grep -Fq 'netsniper-run-v2' netsniper.sh \
    || fail "legacy manifest v2 compatibility marker missing"

grep -Fq 'manifest_contract' netsniper.sh \
    || fail "manifest_contract field missing"

grep -Fq 'network_scope' netsniper.sh \
    || fail "network_scope field missing"

grep -Fq 'requested_profile' netsniper.sh \
    || fail "requested_profile field missing"

grep -Fq 'effective_profile' netsniper.sh \
    || fail "effective_profile field missing"

grep -Fq 'profile_contract' netsniper.sh \
    || fail "profile_contract field missing"

grep -Fq 'duration_seconds' netsniper.sh \
    || fail "duration_seconds field missing"

grep -Fq 'legacy_schema_versions' netsniper.sh \
    || fail "manifest compatibility block missing"

if [ "${NETSNIPER_SKIP_NESTED_VALIDATORS:-0}" != "1" ]; then
    ./tools/validate_v1_9_manifest_profile_metadata.sh \
        || fail "legacy v1.9 manifest profile metadata compatibility failed"
else
    echo "[SKIP] Nested validators skipped in validate_v2_0_manifest_v3.sh"
fi

if [ "${NETSNIPER_SKIP_NESTED_VALIDATORS:-0}" != "1" ]; then
    ./tools/validate_v1_9_accurate_udp_lite_fake_nmap.sh \
        || fail "fake accurate UDP-lite runtime did not produce a valid bundle"
else
    echo "[SKIP] Nested validators skipped in validate_v2_0_manifest_v3.sh"
fi

latest_run="$(ls -td runs/* 2>/dev/null | head -1)"
[ -n "$latest_run" ] \
    || fail "no run directory found"

manifest="$latest_run/manifest.json"
[ -s "$manifest" ] \
    || fail "latest manifest missing: $manifest"

jq -e '
  .schema_version == "netsniper-run-v3"
  and .manifest_contract == "netsniper-run-v3"
  and .legacy_schema_version == "netsniper-run-v2"
  and (.scanner_version == "v2.0.0-dev" or .scanner_version == "v2.0.0" or .scanner_version == "v2.1.0-dev")
  and .target == "192.168.56.0/30"
  and .network_scope == .target
  and .scan_profile == "FAST_MONITORED_TCP"
  and .profile_contract == "FAST_MONITORED_TCP"
  and .scan_profile_requested == "accurate"
  and .scan_profile_effective == "accurate"
  and .requested_profile == .scan_profile_requested
  and .effective_profile == .scan_profile_effective
  and .profile_fingerprint == .profile.fingerprint
  and (.run_dir | type == "string" and length > 0)
  and (.started_at | type == "string" and length > 0)
  and (.completed_at | type == "string" and length > 0)
  and (.duration_seconds | type == "number")
  and .quality.manifest_valid == true
  and .quality.required_files_present == true
  and .quality.deltaaegis_ready == true
  and (.quality.warnings | type == "array")
  and (.quality.errors | type == "array")
  and (.compatibility.legacy_schema_versions | index("netsniper-run-v2"))
  and .files.analysis_json == "analysis.json"
  and .files.analysis_enriched_json == "analysis.enriched.json"
  and .files.classification_quality_json == "classification_quality.json"
' "$manifest" >/dev/null \
    || {
        jq . "$manifest" >&2
        fail "latest manifest does not satisfy NetSniper v2.0 manifest v3 contract"
    }

python3 - "$manifest" <<'PY'
import json
import sys
from pathlib import Path

manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))

required_top_level = {
    "schema_version",
    "manifest_contract",
    "legacy_schema_version",
    "scan_id",
    "scanner_version",
    "target",
    "network_scope",
    "status",
    "requested_profile",
    "effective_profile",
    "profile_contract",
    "profile_fingerprint",
    "run_dir",
    "started_at",
    "completed_at",
    "duration_seconds",
    "quality",
    "compatibility",
    "files",
    "counts",
    "telemetry",
}

missing = sorted(required_top_level - set(manifest))
assert not missing, missing

assert manifest["schema_version"] == "netsniper-run-v3"
assert manifest["requested_profile"] in {"quick", "balanced", "accurate"}
assert manifest["effective_profile"] in {"quick", "balanced", "accurate"}
assert manifest["profile_contract"] == "FAST_MONITORED_TCP"
assert manifest["duration_seconds"] >= 0
assert manifest["quality"]["deltaaegis_ready"] is True

print("[PASS] v2.0 manifest v3 python contract checks passed")
PY

ok "NetSniper v2.0 manifest v3 validation passed"
