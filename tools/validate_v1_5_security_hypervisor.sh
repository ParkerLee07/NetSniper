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

echo "[*] Validating Security Appliance and Hypervisor classifier additions..."

python3 - <<'PY'
from pathlib import Path

text = Path("netsniper.sh").read_text(encoding="utf-8")

required = [
    "SECURITY_SCORE=0",
    "HYPERVISOR_SCORE=0",
    "security_appliance) SECURITY_SCORE",
    "hypervisor) HYPERVISOR_SCORE",
    'update_best_candidate "Security Appliance" "$SECURITY_SCORE"',
    'update_best_candidate "Hypervisor / Virtualization Host" "$HYPERVISOR_SCORE"',
    '{device_type: "Security Appliance", confidence: $security}',
    '{device_type: "Hypervisor / Virtualization Host", confidence: $hypervisor}',
    'has_port 500 && add_classification_evidence "security_appliance"',
    'has_port 4500 && add_classification_evidence "security_appliance"',
    'add_classification_evidence "security_appliance" "port-combination" "vpn+https"',
    'has_port 8006 && add_classification_evidence "hypervisor"',
    'has_port 5900 && add_classification_evidence "hypervisor"',
    'add_classification_evidence "hypervisor" "port-combination" "tcp/8006+22"',
    "500/open",
    "4500/open",
    "8006/open",
]

missing = [item for item in required if item not in text]

if missing:
    raise SystemExit(f"[-] Missing Security/Hypervisor classifier content: {missing}")

print("[+] PASS: Security Appliance and Hypervisor classifier additions are present.")
PY

echo
echo "[+] PASS: NetSniper v1.5 Security/Hypervisor validation succeeded."
