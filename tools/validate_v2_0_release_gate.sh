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
