#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/NetSniper}" || {
  echo "[-] Could not enter NetSniper repo."
  exit 1
}

echo "[*] Running shell syntax check..."
bash -n netsniper.sh

echo "[*] Running v1.5 taxonomy and fixture validators..."
./tools/validate_v1_5_taxonomy.sh
./tools/validate_v1_5_fixtures.sh

echo "[*] Validating v1.5 web-interface demotion..."

python3 - <<'PY'
from pathlib import Path

text = Path("netsniper.sh").read_text(encoding="utf-8")

required = [
    "# NETSNIPER_CLASSIFICATION_ENGINE_V150_DEV",
    'has_port 80 && add_classification_evidence "web" "port" "tcp/80" 10',
    'has_port 443 && add_classification_evidence "web" "port" "tcp/443" 10',
    'has_port 8080 && add_classification_evidence "web" "port" "tcp/8080" 8',
    "HTTP service detected; treated as weak web-interface evidence",
    "HTTPS service detected; treated as weak web-interface evidence",
    'update_best_candidate "Web Server / Web Application Host" "$WEB_SCORE"',
    '{device_type: "Web Server / Web Application Host", confidence: $web}',
]

missing = [item for item in required if item not in text]

if missing:
    raise SystemExit(f"[-] Missing v1.5 web-demotion content: {missing}")

for stale in [
    'update_best_candidate "Web Server" "$WEB_SCORE"',
    '{device_type: "Web Server", confidence: $web}',
    'has_port 80 && add_classification_evidence "web" "port" "tcp/80" 20',
    'has_port 443 && add_classification_evidence "web" "port" "tcp/443" 20',
]:
    if stale in text:
        raise SystemExit(f"[-] Stale overconfident web classification remains: {stale}")

print("[+] PASS: generic web interface evidence is weak and no longer labeled as plain Web Server.")
PY

echo
echo "[+] PASS: NetSniper v1.5 web-interface demotion validation succeeded."
