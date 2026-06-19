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

echo "[*] Validating Router/Gateway and NAS classifier additions..."

python3 - <<'PY'
from pathlib import Path

text = Path("netsniper.sh").read_text(encoding="utf-8")

required = [
    "ROUTER_GATEWAY_SCORE=0",
    "NAS_SCORE=0",
    "router_gateway) ROUTER_GATEWAY_SCORE",
    "nas) NAS_SCORE",
    'update_best_candidate "Router / Gateway" "$ROUTER_GATEWAY_SCORE"',
    'update_best_candidate "NAS / File Server" "$NAS_SCORE"',
    '{device_type: "Router / Gateway", confidence: $router_gateway}',
    '{device_type: "NAS / File Server", confidence: $nas}',
    'has_port 7547 && add_classification_evidence "router_gateway"',
    'add_classification_evidence "router_gateway" "port-combination" "dns+web"',
    'has_port 2049 && add_classification_evidence "nas"',
    'add_classification_evidence "nas" "port-combination" "smb+nfs"',
    "1900/open|2049/open|2375/open",
]

missing = [item for item in required if item not in text]

if missing:
    raise SystemExit(f"[-] Missing Router/NAS classifier content: {missing}")

print("[+] PASS: Router/Gateway and NAS classifier additions are present.")
PY

echo
echo "[+] PASS: NetSniper v1.5 Router/NAS validation succeeded."
