#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

fail() {
    printf '[FAIL] %s\n' "$*" >&2
    exit 1
}

pass() {
    printf '[PASS] %s\n' "$*"
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
export PYTHONDONTWRITEBYTECODE=1

cleanup_python_caches() {
    find netsniper_core tools         -type d -name __pycache__ -prune -exec rm -rf {} +         2>/dev/null || true
}
trap cleanup_python_caches EXIT

printf '%s\n' 'NetSniper v2.1.1 Release Gate'
printf '%s\n' '================================'

source_ref="$(git branch --show-current)"
if [[ -z "$source_ref" ]]; then
    source_ref="${GITHUB_HEAD_REF:-${GITHUB_REF_NAME:-}}"
fi
case "$source_ref" in
    hotfix/v2.1.1-bundle-quality-integrity|main)
        pass "supported release-validation source $source_ref"
        ;;
    *)
        fail "unsupported release-validation source: ${source_ref:-detached-without-source-ref}"
        ;;
esac

[[ -z "$(git status --porcelain)" ]] || fail "working tree is not clean"
pass "clean working tree"

git diff --check || fail "whitespace errors"
bash -n netsniper.sh || fail "netsniper.sh syntax"
bash -n tools/validate_v2_1_bundle_integrity_hotfix_all.sh || fail "hotfix-gate shell syntax"
bash -n tools/validate_v2_1_stage1_2_all.sh || fail "complete-gate shell syntax"
bash -n tools/validate_v2_1_release_gate.sh || fail "release-gate shell syntax"

python3 -m py_compile     netsniper_core/*.py     tools/analyze_v2_1_gnmap.py     tools/classify_v2_1_host.py     tools/finalize_v2_1_bundle_integrity.py     tools/generate_v2_1_run_artifacts.py     tools/replay_v2_1_corpus.py     tools/validate_v2_1_bundle_integrity_hotfix.py     tools/validate_v2_1_corpus_activation.py     tools/validate_v2_1_deltaaegis_enrichment.py     tools/validate_v2_1_embedded_admin_boundary.py     tools/validate_v2_1_empirical_calibration.py     tools/validate_v2_1_observation_integrity.py     tools/validate_v2_1_observed_behavior_corrections.py     tools/validate_v2_1_release_metadata.py     tools/validate_v2_1_stage1_2.py     || fail "Python syntax"
pass "Bash and Python syntax"

python3 tools/validate_v2_1_release_metadata.py     || fail "v2.1.1 release metadata"

./tools/validate_v2_1_bundle_integrity_hotfix_all.sh     || fail "v2.1.1 bundle-integrity hotfix gate"

./tools/validate_v2_1_stage1_2_all.sh     || fail "v2.1 complete behavioral and compatibility gate"

[[ -z "$(git status --porcelain)" ]] || fail "validation mutated the repository"
git diff --check || fail "post-validation whitespace errors"

pass "NetSniper v2.1.1 release gate complete"
