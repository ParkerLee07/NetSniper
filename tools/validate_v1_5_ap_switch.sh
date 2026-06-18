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
./tools/validate_v1_5_voip_ups.sh
./tools/validate_v1_5_security_hypervisor.sh
./tools/validate_v1_5_windows_linux.sh

echo "[*] Validating AP/Switch classifier additions..."

python3 - <<'PY'
from pathlib import Path

text = Path("netsniper.sh").read_text(encoding="utf-8")

required = [
    "AP_SCORE=0",
    "SWITCH_SCORE=0",
    "wireless_ap) AP_SCORE",
    "managed_switch) SWITCH_SCORE",
    'update_best_candidate "Wireless Access Point" "$AP_SCORE"',
    'update_best_candidate "Managed Switch / Network Infrastructure" "$SWITCH_SCORE"',
    '{device_type: "Wireless Access Point", confidence: $ap}',
    '{device_type: "Managed Switch / Network Infrastructure", confidence: $switch_score}',
    'has_port 161 && add_classification_evidence "managed_switch"',
    'add_classification_evidence "managed_switch" "port-combination" "snmp+ssh"',
    'add_classification_evidence "managed_switch" "port-combination" "snmp+web"',
    'add_classification_evidence "wireless_ap" "port-combination" "upnp+web"',
]

missing = [item for item in required if item not in text]

if missing:
    raise SystemExit(f"[-] Missing AP/Switch classifier content: {missing}")

print("[+] PASS: AP/Switch classifier additions are present.")
PY

echo
echo "[+] PASS: NetSniper v1.5 AP/Switch validation succeeded."
