#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/NetSniper}" || {
  echo "[-] Could not enter NetSniper repo."
  exit 1
}

echo "[*] Validating NetSniper v1.5 classification taxonomy..."

test -f Docs/classification-v1.5-taxonomy.md

python3 - <<'PY'
from pathlib import Path

path = Path("Docs/classification-v1.5-taxonomy.md")
text = path.read_text(encoding="utf-8")

required = [
    "NetSniper v1.5 Classification Taxonomy",
    "Web Interface = evidence",
    "Web Server / Web Application Host",
    "Router / Gateway",
    "Wireless Access Point",
    "Managed Switch / Network Infrastructure",
    "Network Printer / Multifunction Printer",
    "IP Camera / NVR",
    "NAS / File Server",
    "VoIP Phone / PBX",
    "UPS / Power Device",
    "Security Appliance",
    "Hypervisor / Virtualization Host",
    "Container Infrastructure",
    "Database Server",
    "Windows Workstation",
    "Windows Server",
    "Linux Server",
    "Development / Admin Interface",
    "IoT / Embedded Device",
    "Client Device",
    "Unknown / Ambiguous",
    "Unknown / Ambiguous is preferable to a confident but unsupported label.",
]

missing = [item for item in required if item not in text]

if missing:
    raise SystemExit(f"[-] Missing taxonomy phrase(s): {missing}")

print("[+] PASS: NetSniper v1.5 classification taxonomy contains required categories and principles.")
PY

echo
echo "[+] PASS: NetSniper v1.5 taxonomy validation succeeded."
