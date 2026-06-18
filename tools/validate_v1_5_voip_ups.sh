#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/NetSniper}" || {
  echo "[-] Could not enter NetSniper repo."
  exit 1
}

echo "[*] Running shell syntax check..."
bash -n netsniper.sh

echo "[*] Running v1.5 base validators..."
./tools/validate_v1_5_taxonomy.sh
./tools/validate_v1_5_fixtures.sh
./tools/validate_v1_5_web_demotion.sh
./tools/validate_v1_5_router_nas.sh

echo "[*] Validating VoIP and UPS classifier additions..."

python3 - <<'PY'
from pathlib import Path

text = Path("netsniper.sh").read_text(encoding="utf-8")

required = [
    "VOIP_SCORE=0",
    "UPS_SCORE=0",
    "voip) VOIP_SCORE",
    "ups) UPS_SCORE",
    'update_best_candidate "VoIP Phone / PBX" "$VOIP_SCORE"',
    'update_best_candidate "UPS / Power Device" "$UPS_SCORE"',
    '{device_type: "VoIP Phone / PBX", confidence: $voip}',
    '{device_type: "UPS / Power Device", confidence: $ups}',
    'has_port 5060 && add_classification_evidence "voip"',
    'has_port 5061 && add_classification_evidence "voip"',
    'add_classification_evidence "voip" "port-combination" "sip+web"',
    'has_port 161 && add_classification_evidence "ups"',
    'add_classification_evidence "ups" "port-combination" "snmp+web"',
    "5060/open",
    "5061/open",
    "161/open",
]

missing = [item for item in required if item not in text]

if missing:
    raise SystemExit(f"[-] Missing VoIP/UPS classifier content: {missing}")

print("[+] PASS: VoIP and UPS classifier additions are present.")
PY

echo
echo "[+] PASS: NetSniper v1.5 VoIP/UPS validation succeeded."
