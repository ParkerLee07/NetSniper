#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/NetSniper}" || {
  echo "[-] Could not enter NetSniper repo."
  exit 1
}

echo "[*] Running compact v1.5 progress validator..."
./tools/validate_v1_5_classifier_progress.sh

echo "[*] Validating Development/Admin and IoT classifier additions..."

python3 - <<'PY'
from pathlib import Path

text = Path("netsniper.sh").read_text(encoding="utf-8")

required = [
    "DEV_ADMIN_SCORE=0",
    "IOT_SCORE=0",
    "dev_admin) DEV_ADMIN_SCORE",
    "iot) IOT_SCORE",
    'update_best_candidate "Development / Admin Interface" "$DEV_ADMIN_SCORE"',
    'update_best_candidate "IoT / Embedded Device" "$IOT_SCORE"',
    '{device_type: "Development / Admin Interface", confidence: $dev_admin}',
    '{device_type: "IoT / Embedded Device", confidence: $iot}',
    'has_port 3000 && add_classification_evidence "dev_admin"',
    'has_port 5601 && add_classification_evidence "dev_admin"',
    'has_port 9090 && add_classification_evidence "dev_admin"',
    'add_classification_evidence "dev_admin" "port-combination" "tcp/3000+9090"',
    'has_port 5555 && add_classification_evidence "iot"',
    'add_classification_evidence "iot" "port-combination" "upnp+web"',
]

missing = [item for item in required if item not in text]

if missing:
    raise SystemExit(f"[-] Missing Development/Admin or IoT classifier content: {missing}")

print("[+] PASS: Development/Admin and IoT classifier additions are present.")
PY

echo
echo "[+] PASS: NetSniper v1.5 Development/Admin + IoT validation succeeded."
