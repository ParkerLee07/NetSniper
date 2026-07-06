#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "[NetSniper runtime copy accuracy] syntax check"
bash -n netsniper.sh

echo "[NetSniper runtime copy accuracy] release wording checks"

python3 - <<'PYCHECK'
from pathlib import Path

text = Path("netsniper.sh").read_text(encoding="utf-8")

required = [
    'SCANNER_VERSION="v2.0.0"',
    "DeltaAegis dashboard or schedule orchestration",
    "runtime execution is not enabled in NetSniper v2.0.0.",
    "Headless Greenbone launch is not enabled in NetSniper v2.0.0.",
]

for marker in required:
    if marker not in text:
        raise SystemExit(f"Missing current NetSniper wording: {marker}")

stale = [
    "future DeltaAegis dashboard scan control",
    "this v1.9 release",
    "this v2.0 checkpoint",
    "this v1.8 checkpoint",
]

for marker in stale:
    if marker in text:
        raise SystemExit(f"Stale NetSniper wording remains: {marker}")

print("NetSniper runtime copy accuracy checks passed")
PYCHECK
