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

echo "[*] Validating Windows/Linux classifier additions..."

python3 - <<'PY'
from pathlib import Path

text = Path("netsniper.sh").read_text(encoding="utf-8")

required = [
    "WINDOWS_SERVER_SCORE=0",
    "WINDOWS_WORKSTATION_SCORE=0",
    "LINUX_SERVER_SCORE=0",
    "windows_server) WINDOWS_SERVER_SCORE",
    "windows_workstation) WINDOWS_WORKSTATION_SCORE",
    "linux_server) LINUX_SERVER_SCORE",
    'update_best_candidate "Windows Server" "$WINDOWS_SERVER_SCORE"',
    'update_best_candidate "Windows Workstation" "$WINDOWS_WORKSTATION_SCORE"',
    'update_best_candidate "Linux Server" "$LINUX_SERVER_SCORE"',
    '{device_type: "Windows Server", confidence: $windows_server}',
    '{device_type: "Windows Workstation", confidence: $windows_workstation}',
    '{device_type: "Linux Server", confidence: $linux_server}',
    'add_classification_evidence "windows_server" "port-combination" "tcp/88+389+445"',
    'add_classification_evidence "windows_workstation" "port-combination" "tcp/445+3389"',
    'add_classification_evidence "linux_server" "port-combination" "ssh+nfs"',
    "111/open",
    "135/open",
]

missing = [item for item in required if item not in text]

if missing:
    raise SystemExit(f"[-] Missing Windows/Linux classifier content: {missing}")

for stale in [
    'update_best_candidate "Windows Host" "$WINDOWS_SCORE"',
    'update_best_candidate "Linux / Web Server" "$LINUX_WEB_SCORE"',
    'update_best_candidate "Likely Active Directory / Domain Controller" "$AD_SCORE"',
    '{device_type: "Windows Host", confidence: $windows}',
    '{device_type: "Linux / Web Server", confidence: $linux_web}',
]:
    if stale in text:
        raise SystemExit(f"[-] Stale broad classifier content remains: {stale}")

print("[+] PASS: Windows Server, Windows Workstation, and Linux Server classifier additions are present.")
PY

echo
echo "[+] PASS: NetSniper v1.5 Windows/Linux validation succeeded."
