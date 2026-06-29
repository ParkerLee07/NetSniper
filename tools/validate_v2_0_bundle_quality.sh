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

grep -Fq 'write_bundle_quality_report()' netsniper.sh \
    || fail "bundle quality function missing"

grep -Fq 'netsniper-bundle-quality-v1' netsniper.sh \
    || fail "bundle quality schema marker missing"

grep -Fq 'bundle_quality.json' netsniper.sh \
    || fail "bundle_quality.json is not referenced"

if [ "${NETSNIPER_SKIP_NESTED_VALIDATORS:-0}" != "1" ]; then
    ./tools/validate_v2_0_profile_budgets.sh \
        || fail "profile budget validator failed before bundle quality checks"
else
    echo "[SKIP] Nested validators skipped in validate_v2_0_bundle_quality.sh"
fi

latest_run="$(ls -td runs/* 2>/dev/null | head -1)"
[ -n "$latest_run" ] \
    || fail "no run directory found"

manifest="$latest_run/manifest.json"
quality="$latest_run/bundle_quality.json"

[ -s "$manifest" ] \
    || fail "latest manifest missing: $manifest"

[ -s "$quality" ] \
    || fail "bundle quality report missing: $quality"

jq -e '
  .schema_version == "netsniper-bundle-quality-v1"
  and .deltaaegis_ready == true
  and .manifest_valid == true
  and .required_files_present == true
  and .counts_valid == true
  and .classification_quality_valid == true
  and .profile_fields_valid == true
  and .target_scope_valid == true
  and .status_complete == true
  and (.required_files | type == "array" and length > 0)
  and .counts.hosts_txt == .counts.analysis_json
  and .counts.hosts_txt == .counts.analysis_enriched_json
  and .profile.effective_profile == "accurate"
  and .profile.profile_contract == "FAST_MONITORED_TCP"
  and (.warnings | type == "array")
  and (.errors | type == "array" and length == 0)
' "$quality" >/dev/null \
    || {
        jq . "$quality" >&2
        fail "bundle_quality.json does not satisfy v2.0 quality contract"
    }

jq -e '
  .schema_version == "netsniper-run-v3"
  and .files.bundle_quality_json == "bundle_quality.json"
  and .files.hosts == "hosts.txt"
  and .quality.schema_version == "netsniper-bundle-quality-v1"
  and .quality.deltaaegis_ready == true
  and .quality.required_files_present == true
  and .quality.counts_valid == true
' "$manifest" >/dev/null \
    || {
        jq . "$manifest" >&2
        fail "manifest does not reference embedded bundle quality report"
    }

python3 - "$quality" "$latest_run" <<'PY'
import json
import sys
from pathlib import Path

quality_path = Path(sys.argv[1])
bundle_dir = Path(sys.argv[2])

quality = json.loads(quality_path.read_text(encoding="utf-8"))

missing = []

for record in quality["required_files"]:
    path = bundle_dir / record["path"]
    if not path.exists():
        missing.append(record["path"])

assert not missing, missing
assert quality["bundle_path"], quality
assert quality["manifest_path"], quality
assert quality["deltaaegis_ready"] is True, quality
assert quality["errors"] == [], quality

print("[PASS] v2.0 bundle quality python checks passed")
PY

if [ "${NETSNIPER_SKIP_NESTED_VALIDATORS:-0}" != "1" ]; then
    ./tools/validate_v2_0_manifest_v3.sh \
        || fail "manifest v3 validator failed after bundle quality changes"
else
    echo "[SKIP] Nested validators skipped in validate_v2_0_bundle_quality.sh"
fi

if [ "${NETSNIPER_SKIP_NESTED_VALIDATORS:-0}" != "1" ]; then
    ./tools/validate_v2_0_status_contract.sh \
        || fail "status contract validator failed after bundle quality changes"
else
    echo "[SKIP] Nested validators skipped in validate_v2_0_bundle_quality.sh"
fi

ok "NetSniper v2.0 bundle quality validation passed"
