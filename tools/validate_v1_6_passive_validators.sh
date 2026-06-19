#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/NetSniper}" || {
  echo "[-] Could not enter NetSniper repo."
  exit 1
}

echo "[*] Checking shell syntax..."
bash -n netsniper.sh

echo "[*] Checking passive validator markers..."

python3 - <<'PY'
from pathlib import Path

text = Path("netsniper.sh").read_text(encoding="utf-8")

required = [
    "candidate_key_for_type()",
    "candidate_evidence_count()",
    "classification_contradiction_count()",
    "add_passive_classification_validators()",
    "high_reliability_evidence_validator",
    "weak_evidence_validator",
    "generic_web_interface_validator",
    "contradiction_validator"
]

missing = [item for item in required if item not in text]

if missing:
    raise SystemExit(f"[-] Missing passive validator marker(s): {missing}")

print("[+] PASS: passive validator markers are present.")
PY

echo "[*] Running passive validator behavior test..."

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
Host: 192.0.2.40 () Ports: 554/open/tcp//rtsp///, 445/open/tcp//microsoft-ds///
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

required_ips = {"192.0.2.10", "192.0.2.20", "192.0.2.30", "192.0.2.40"}
missing_ips = sorted(required_ips - set(by_ip))

if missing_ips:
    raise SystemExit(f"[-] Missing expected hosts: {missing_ips}")

def classification(ip):
    return by_ip[ip].get("classification") or {}

def validator_names(ip):
    validators = classification(ip).get("validators") or []

    if not isinstance(validators, list):
        raise SystemExit(f"[-] {ip}: validators is not a list")

    return {item.get("name"): item for item in validators if isinstance(item, dict)}

failures = []

generic = classification("192.0.2.10")
generic_validators = validator_names("192.0.2.10")

if generic.get("confidence_band") != "weak":
    failures.append(f"192.0.2.10: expected weak band, got {generic.get('confidence_band')}")

if "weak_evidence_validator" not in generic_validators:
    failures.append("192.0.2.10: missing weak_evidence_validator")

if "generic_web_interface_validator" not in generic_validators:
    failures.append("192.0.2.10: missing generic_web_interface_validator")

if any(v.get("status") == "confirmed" for v in generic_validators.values()):
    failures.append("192.0.2.10: weak generic web host should not have confirmed validator")

web = classification("192.0.2.20")
web_validators = validator_names("192.0.2.20")

if web.get("confidence_band") != "possible":
    failures.append(f"192.0.2.20: expected possible band, got {web.get('confidence_band')}")

if "high_reliability_evidence_validator" not in web_validators:
    failures.append("192.0.2.20: nginx service-text host missing high_reliability_evidence_validator")

camera = classification("192.0.2.30")
camera_validators = validator_names("192.0.2.30")

if camera.get("confidence_band") != "confirmed":
    failures.append(f"192.0.2.30: expected confirmed band, got {camera.get('confidence_band')}")

if "high_reliability_evidence_validator" not in camera_validators:
    failures.append("192.0.2.30: Reolink host missing high_reliability_evidence_validator")

contradictory = classification("192.0.2.40")
contradictory_validators = validator_names("192.0.2.40")

if not contradictory.get("contradictions"):
    failures.append("192.0.2.40: expected contradiction records")

if "contradiction_validator" not in contradictory_validators:
    failures.append("192.0.2.40: missing contradiction_validator")

if failures:
    print("[-] Passive validator behavior failures:")
    for failure in failures:
        print(f"    - {failure}")
    raise SystemExit(1)

print("[+] PASS: v1.6 passive validator behavior is valid.")
print(f"[+] Analysis JSON: {path}")
PY

echo
echo "[+] PASS: NetSniper v1.6 passive validator validation succeeded."
