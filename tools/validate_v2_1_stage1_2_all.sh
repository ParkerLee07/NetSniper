#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "[FAIL] $*" >&2
    exit 1
}

pass() {
    echo "[PASS] $*"
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export PYTHONDONTWRITEBYTECODE=1

bash -n netsniper.sh || fail "netsniper.sh syntax"

python3 - <<'PY' || exit_code=$?
from __future__ import annotations

import ast
from pathlib import Path

paths = [
    *sorted(Path("netsniper_core").glob("*.py")),
    Path("tools/analyze_v2_1_gnmap.py"),
    Path("tools/classify_v2_1_host.py"),
    Path("tools/generate_v2_1_run_artifacts.py"),
    Path("tools/validate_v2_1_stage1_2.py"),
]

for path in paths:
    source = path.read_text(encoding="utf-8")
    ast.parse(source, filename=str(path))

print(f"[PASS] Python syntax ({len(paths)} files)")
PY

if [[ "${exit_code:-0}" -ne 0 ]]; then
    fail "Python syntax"
fi

./tools/validate_v2_1_stage1_2.py \
    || fail "v2.1 Stages 1-2 contract validator"

./tools/validate_v2_0_all.sh \
    || fail "v2.0 runtime compatibility suite"

pass "NetSniper v2.1 Stages 1-2 and v2.0 compatibility suites passed"
