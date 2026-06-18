#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/NetSniper}" || {
  echo "[-] Could not enter NetSniper repo."
  exit 1
}

echo "[*] Running shell syntax check..."
bash -n netsniper.sh

echo "[*] Running v1.4 analysis validator..."
./tools/validate_v1_4_analysis.sh

echo "[*] Running v1.4 bundle validator..."
./tools/validate_v1_4_bundle.sh

echo "[*] Validating NetSniper v1.4 documentation..."

python3 - <<'PY'
from pathlib import Path

checks = {
    "README.md": [
        "NetSniper v1.4.0 Current Capabilities",
        "Evidence-based classification",
        "Classification schema",
        "netsniper-classification-v1",
        "DeltaAegis-ready schema aliases",
    ],
    "CHANGELOG.md": [
        "## v1.4.0 - 2026-06-18",
        "Evidence-based device classification engine",
        "Classification schema version: `netsniper-classification-v1`",
        "tools/validate_v1_4_analysis.sh",
        "tools/validate_v1_4_bundle.sh",
    ],
    "Docs/deltaaegis-integration.md": [
        "NetSniper v1.4.0 DeltaAegis Classification Contract",
        "netsniper-classification-v1",
        "Per-host classification object",
        "Compatibility fields",
        "Decision model",
    ],
}

for filename, phrases in checks.items():
    path = Path(filename)

    if not path.is_file():
        raise SystemExit(f"[-] Missing file: {filename}")

    text = path.read_text(encoding="utf-8")
    missing = [phrase for phrase in phrases if phrase not in text]

    if missing:
        raise SystemExit(f"[-] {filename} missing expected phrase(s): {missing}")

readme = Path("README.md").read_text(encoding="utf-8")
changelog = Path("CHANGELOG.md").read_text(encoding="utf-8")
integration = Path("Docs/deltaaegis-integration.md").read_text(encoding="utf-8")
script = Path("netsniper.sh").read_text(encoding="utf-8")

if "Current Release NetSniper v1.3.1" in readme:
    raise SystemExit("[-] README.md still says current release is v1.3.1.")

if "SCANNER_VERSION=\"v1.4.0-dev\"" in script:
    raise SystemExit("[-] netsniper.sh still has dev scanner version.")

if "NETSNIPER ENGINE v1.3.1" in script:
    raise SystemExit("[-] netsniper.sh still has stale v1.3.1 engine header.")

if "netsniper-classification-v1" not in script:
    raise SystemExit("[-] netsniper.sh does not expose v1.4 classification schema.")

print("[+] PASS: NetSniper v1.4.0 documentation and version markers are valid.")
PY

echo
echo "[+] PASS: NetSniper v1.4.0 documentation validation succeeded."
