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
    || fail "netsniper.sh has shell syntax errors"

grep -Fq 'SCANNER_VERSION="v2.0.0"' netsniper.sh \
    || fail "SCANNER_VERSION is not finalized as v2.0.0"

grep -Fq 'Current release: **NetSniper v2.0.0' README.md \
    || fail "README current release does not point to v2.0.0"

grep -Fq '## v2.0.0 - 2026-06-29' CHANGELOG.md \
    || fail "CHANGELOG missing v2.0.0 entry"

python3 - <<'PY'
import json
from pathlib import Path

profiles = json.loads(Path("config/scan_profiles.json").read_text(encoding="utf-8"))
assert profiles["release_target"] == "v2.0.0", profiles
assert profiles["default_profile"] == "balanced", profiles

by_name = {profile["name"]: profile for profile in profiles["profiles"]}
for name, budget, host_timeout, enforced in [
    ("quick", 300, 30, True),
    ("balanced", 900, 60, True),
    ("accurate", 1800, 120, True),
    ("deep", 7200, 300, False),
]:
    profile = by_name[name]
    assert profile["runtime_budget_seconds"] == budget, profile
    assert profile["host_timeout_seconds"] == host_timeout, profile
    assert profile["budget_enforced"] is enforced, profile

print("[PASS] fast profile metadata checks passed")
PY

./tools/validate_v2_0_status_contract.sh \
    || fail "status contract failed"

./tools/validate_v2_0_deltaaegis_fixtures.sh \
    || fail "DeltaAegis fixture validation failed"

jq -e '
  .schema_version == "netsniper-run-v3"
  and .manifest_contract == "netsniper-run-v3"
  and .legacy_schema_version == "netsniper-run-v2"
  and .scanner_version == "v2.0.0-fixture"
  and .quality.schema_version == "netsniper-bundle-quality-v1"
  and .quality.deltaaegis_ready == true
' examples/deltaaegis-fixtures/accurate-complete/manifest.json >/dev/null \
    || fail "accurate fixture manifest does not satisfy v2.0 fast checks"

ok "NetSniper v2.0 fast validation passed"
