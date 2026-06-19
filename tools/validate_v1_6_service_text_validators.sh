#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/NetSniper}" || {
  echo "[-] Could not enter NetSniper repo."
  exit 1
}

echo "[*] Checking shell syntax..."
bash -n netsniper.sh

echo "[*] Checking service-text validator markers..."

python3 - <<'PY'
from pathlib import Path

text = Path("netsniper.sh").read_text(encoding="utf-8")

required = [
    "add_service_text_product_validators()",
    "service_text_product_validator",
    "Storage product text was observed",
    "Camera, NVR, DVR, or ONVIF product text",
    "Web server or web application runtime product text",
]

missing = [item for item in required if item not in text]

if missing:
    raise SystemExit(f"[-] Missing service-text validator marker(s): {missing}")

print("[+] PASS: service-text validator markers are present.")
PY

echo "[*] Running service-text validator behavior test..."

tmp_root="$(mktemp -d)"
trap 'rm -rf "$tmp_root"' EXIT

export NETSNIPER_TEST_MODE=1

# shellcheck disable=SC1091
source ./netsniper.sh

SCAN_DIR="$tmp_root/scans"
TARGET_DIR="$tmp_root/targets"
NET="192.0.2.0/24"

mkdir -p "$SCAN_DIR" "$TARGET_DIR"

cat > "$SCAN_DIR/fast_scan.gnmap" <<'GNMAP'
Host: 192.0.2.10 () Ports: 80/open/tcp//http///
Host: 192.0.2.20 () Ports: 80/open/tcp//http//nginx///
Host: 192.0.2.30 () Ports: 554/open/tcp//rtsp//Reolink IP Camera///, 80/open/tcp//http//Reolink Web UI///
Host: 192.0.2.40 () Ports: 445/open/tcp//microsoft-ds//Synology DiskStation///, 2049/open/tcp//nfs///
Host: 192.0.2.50 () Ports: 80/open/tcp//http//UniFi Access Point///, 1900/open/tcp//upnp///
Host: 192.0.2.60 () Ports: 80/open/tcp//http//APC UPS Network Management Card///, 161/open/tcp//snmp///
GNMAP

analyze_hosts > "$tmp_root/analyze.log"

json_file="$(ls -t "$TARGET_DIR"/analysis_*.json 2>/dev/null | head -1)"

if [ ! -f "$json_file" ]; then
  echo "[-] No analysis JSON file was produced."
  cat "$tmp_root/analyze.log"
  exit 1
fi

python3 - "$json_file" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))

hosts = data if isinstance(data, list) else (
    data.get("hosts")
    or data.get("targets")
    or data.get("results")
    or data.get("analysis")
    or data.get("devices")
    or []
)

if not isinstance(hosts, list):
    raise SystemExit("[-] Analysis JSON did not contain a host list.")

by_ip = {}

for item in hosts:
    if not isinstance(item, dict):
        continue

    key = (
        item.get("ip")
        or item.get("host")
        or item.get("address")
        or item.get("target")
        or item.get("ip_address")
    )

    if key:
        by_ip[str(key)] = item

expected = {
    "192.0.2.20": "Web Server / Web Application Host",
    "192.0.2.30": "IP Camera / NVR",
    "192.0.2.40": "NAS / File Server",
    "192.0.2.50": "Wireless Access Point",
    "192.0.2.60": "UPS / Power Device",
}

required_ips = set(expected) | {"192.0.2.10"}
missing_ips = sorted(required_ips - set(by_ip))

if missing_ips:
    raise SystemExit(f"[-] Missing expected hosts: {missing_ips}")

def validators(ip):
    classification = by_ip[ip].get("classification") or {}
    values = classification.get("validators") or []

    if not isinstance(values, list):
        raise SystemExit(f"[-] {ip}: validators is not a list")

    return values

def has_service_text_validator(ip, candidate):
    for item in validators(ip):
        if not isinstance(item, dict):
            continue
        if (
            item.get("name") == "service_text_product_validator"
            and item.get("status") == "confirmed"
            and item.get("candidate") == candidate
        ):
            return True

    return False

failures = []

for ip, candidate in expected.items():
    if not has_service_text_validator(ip, candidate):
        failures.append(f"{ip}: missing confirmed service_text_product_validator for {candidate}")

generic_validators = validators("192.0.2.10")

if any(
    isinstance(item, dict)
    and item.get("name") == "service_text_product_validator"
    for item in generic_validators
):
    failures.append("192.0.2.10: generic HTTP-only host should not receive service_text_product_validator")

for ip, candidate in expected.items():
    classification = by_ip[ip].get("classification") or {}

    if classification.get("validation_state") != "validated":
        failures.append(f"{ip}: expected validation_state=validated, got {classification.get('validation_state')}")

if failures:
    print("[-] Service-text validator behavior failures:")
    for failure in failures:
        print(f"    - {failure}")
    raise SystemExit(1)

print("[+] PASS: v1.6 service-text product validators are valid.")
print(f"[+] Analysis JSON: {path}")
PY

echo
echo "[+] PASS: NetSniper v1.6 service-text validator validation succeeded."
