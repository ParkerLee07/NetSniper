#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/NetSniper}" || {
  echo "[-] Could not enter NetSniper repo."
  exit 1
}

echo "[*] Running behavior validator first..."
./tools/validate_v1_5_behavior.sh

echo "[*] Validating service-text classifier evidence..."

python3 - <<'PY'
from pathlib import Path

text = Path("netsniper.sh").read_text(encoding="utf-8")

required = [
    "line_has()",
    "v1.5 service-text classification evidence",
    'add_classification_evidence "nas" "service-text" "storage-product"',
    'add_classification_evidence "printer" "service-text" "printer-product"',
    'add_classification_evidence "camera" "service-text" "camera-product"',
    'add_classification_evidence "wireless_ap" "service-text" "ap-product"',
    'add_classification_evidence "managed_switch" "service-text" "switch-product"',
    'add_classification_evidence "ups" "service-text" "power-product"',
    'add_classification_evidence "security_appliance" "service-text" "security-product"',
    'add_classification_evidence "hypervisor" "service-text" "hypervisor-product"',
    'add_classification_evidence "dev_admin" "service-text" "admin-tool"',
    'add_classification_evidence "iot" "service-text" "embedded-product"',
    'add_classification_evidence "web" "service-text" "web-server-product"',
    'add_classification_evidence "windows_server" "service-text" "windows-server-product"',
    'add_classification_evidence "linux_server" "service-text" "linux-unix-product"',
]

missing = [item for item in required if item not in text]

if missing:
    raise SystemExit(f"[-] Missing service-text classifier content: {missing}")

print("[+] PASS: service-text evidence rules are present.")
PY

echo
echo "[+] PASS: NetSniper v1.5 service-text evidence validation succeeded."
