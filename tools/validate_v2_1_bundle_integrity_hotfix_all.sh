#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

cd "$(dirname -- "${BASH_SOURCE[0]}")/.."

cleanup_python_caches() {
    find netsniper_core tools \
        -type d -name __pycache__ -prune -exec rm -rf {} + \
        2>/dev/null || true
}
trap cleanup_python_caches EXIT

echo "=== NETSNIPER V2.1 BUNDLE-INTEGRITY HOTFIX GATE ==="

bash -n netsniper.sh
python3 -m py_compile \
    netsniper_core/capabilities.py \
    tools/finalize_v2_1_bundle_integrity.py \
    tools/validate_v2_1_bundle_integrity_hotfix.py

python3 tools/validate_v2_1_bundle_integrity_hotfix.py
python3 tools/validate_v2_1_stage1_2.py

git diff --check

echo "[PASS] NetSniper v2.1 bundle-integrity hotfix gate"
