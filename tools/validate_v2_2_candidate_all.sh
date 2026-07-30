#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
cd "$(dirname "$0")/.."
fail(){ echo "[FAIL] NetSniper v2.2 candidate: $*" >&2; exit 1; }
pass(){ echo "[PASS] $*"; }
branch="$(git branch --show-current)"
case "$branch" in feature/v2.2-runtime-integrity|main) ;; *) fail "unsupported branch: ${branch:-DETACHED}";; esac
before="$(git status --porcelain=v1 --untracked-files=all)"
git diff --check || fail "whitespace errors"
bash -n netsniper.sh install.sh tools/validate_v2_2_runtime_safety_all.sh tools/validate_v2_2_deltaaegis_compatibility.sh
python3 -m py_compile netsniper_core/*.py tools/*.py
if command -v shellcheck >/dev/null 2>&1; then shellcheck -x --severity=warning netsniper.sh install.sh; fi
./tools/validate_v2_2_runtime_safety_all.sh
./tools/validate_v2_1_stage1_2_all.sh
./tools/validate_v2_1_bundle_integrity_hotfix_all.sh
python3 tools/validate_v2_1_empirical_calibration.py
python3 tools/validate_v2_1_deltaaegis_enrichment.py
./tools/validate_v2_2_deltaaegis_compatibility.sh "${DELTAAEGIS_ROOT:-$HOME/DeltaAegis}"
after="$(git status --porcelain=v1 --untracked-files=all)"
[ "$after" = "$before" ] || fail "validation changed the candidate tree"
git diff --check || fail "post-validation whitespace errors"
pass "NetSniper v2.2 candidate gate complete"
