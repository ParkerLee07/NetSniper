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

./tools/validate_v2_0_all.sh \
    || fail "v2.0 all-in validator failed"


grep -Fq 'SCANNER_VERSION="v2.0.0"' netsniper.sh \
    || fail "SCANNER_VERSION is not finalized as v2.0.0"

if grep -Fq 'SCANNER_VERSION="v2.0.0-dev"' netsniper.sh; then
    fail "development scanner version marker is still present"
fi

grep -Fq 'Current release: **NetSniper v2.0.0 — Reliable Telemetry Sensor for DeltaAegis**' README.md \
    || fail "README current release does not point to v2.0.0"

grep -Fq '## v2.0.0 - 2026-06-29' CHANGELOG.md \
    || fail "CHANGELOG missing v2.0.0 entry"

python3 - <<'PY'
import json
from pathlib import Path

data = json.loads(Path("config/scan_profiles.json").read_text(encoding="utf-8"))
assert data["release_target"] == "v2.0.0", data
print("[PASS] v2.0 release metadata JSON checks passed")
PY

for required_doc in \
    docs/V2_0_TELEMETRY_CONTRACT.md \
    docs/V2_0_RELEASE_CHECKLIST.md \
    examples/deltaaegis-fixtures/README.md
do
    [ -s "$required_doc" ] \
        || fail "missing required release documentation: $required_doc"
done

grep -Fq 'netsniper-status-v1' docs/V2_0_TELEMETRY_CONTRACT.md \
    || fail "telemetry contract doc missing status schema marker"

grep -Fq 'netsniper-run-v3' docs/V2_0_TELEMETRY_CONTRACT.md \
    || fail "telemetry contract doc missing manifest schema marker"

grep -Fq 'netsniper-bundle-quality-v1' docs/V2_0_TELEMETRY_CONTRACT.md \
    || fail "telemetry contract doc missing bundle quality schema marker"

grep -Fq 'examples/deltaaegis-fixtures' docs/V2_0_RELEASE_CHECKLIST.md \
    || fail "release checklist missing fixture reference"

for fixture in quick-complete balanced-complete accurate-complete failed-quality; do
    [ -s "examples/deltaaegis-fixtures/$fixture/manifest.json" ] \
        || fail "missing fixture manifest: $fixture"

    [ -s "examples/deltaaegis-fixtures/$fixture/bundle_quality.json" ] \
        || fail "missing fixture quality report: $fixture"
done

tracked_fixture_evidence_count="$(
    git ls-files examples/deltaaegis-fixtures \
        | grep -Ec '\.(xml|gnmap|nmap)$' || true
)"

[ "$tracked_fixture_evidence_count" -ge 20 ] \
    || fail "fixture evidence artifacts are not fully tracked"

if git status --short | grep -q .; then
    echo "[WARN] Working tree has uncommitted changes."
    git status --short
fi

ok "NetSniper v2.0 release gate passed"
