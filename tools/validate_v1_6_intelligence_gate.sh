#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/NetSniper}" || {
  echo "[-] Could not enter NetSniper repo."
  exit 1
}

echo "[*] NetSniper v1.6 intelligence gate"
echo

echo "[*] Checking shell syntax..."
bash -n netsniper.sh

echo "[*] Checking v1.6 version/intelligence markers..."

python3 - <<'PY'
from pathlib import Path

script = Path("netsniper.sh").read_text(encoding="utf-8")

required = [
    'SCANNER_VERSION="v1.6.0"',
    "evidence_reliability()",
    "calibrated_decision()",
    "siem_action()",
    "calibration_reason()",
    "add_classification_validator()",
    "add_passive_classification_validators()",
    "classification_validation_state()",
    "add_service_text_product_validators()",
    "validator_summary:",
    "confidence_band:",
    "calibrated_decision:",
    "siem_action:",
    "validation_state:",
    "contradiction_count:",
    "validators:",
]

missing = [item for item in required if item not in script]

if missing:
    raise SystemExit(f"[-] Missing v1.6 intelligence marker(s): {missing}")

print("[+] PASS: v1.6 intelligence markers are present.")
PY

echo "[*] Checking required v1.6 validators..."

required_validators=(
  tools/validate_v1_6_calibration.sh
  tools/validate_v1_6_passive_validators.sh
  tools/validate_v1_6_contradiction_gating.sh
  tools/validate_v1_6_service_text_validators.sh
  tools/validate_v1_6_validator_summary.sh
)

for validator in "${required_validators[@]}"; do
  if [ ! -x "$validator" ]; then
    echo "[-] Missing or non-executable validator: $validator"
    exit 1
  fi
done

echo "[*] Running v1.6 calibration validator..."
./tools/validate_v1_6_calibration.sh

echo "[*] Running v1.6 passive validator check..."
./tools/validate_v1_6_passive_validators.sh

echo "[*] Running v1.6 contradiction gating validator..."
./tools/validate_v1_6_contradiction_gating.sh

echo "[*] Running v1.6 service-text validator..."
./tools/validate_v1_6_service_text_validators.sh

echo "[*] Running v1.6 validator summary check..."
./tools/validate_v1_6_validator_summary.sh

echo "[*] Running v1.5 behavior regression validator..."
./tools/validate_v1_5_behavior.sh

echo
echo "[+] PASS: NetSniper v1.6 intelligence gate succeeded."
