#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/NetSniper}" || {
  echo "[-] Could not enter NetSniper repo."
  exit 1
}

echo "[*] Checking shell syntax..."
bash -n netsniper.sh

echo "[*] Checking validator summary markers..."

python3 - <<'PY'
from pathlib import Path

text = Path("netsniper.sh").read_text(encoding="utf-8")

required = [
    "validator_summary:",
    "confirmed:",
    "inconclusive:",
    "refuted:",
    "not_applicable:",
    "names:"
]

missing = [item for item in required if item not in text]

if missing:
    raise SystemExit(f"[-] Missing validator summary marker(s): {missing}")

print("[+] PASS: validator summary markers are present.")
PY

echo "[*] Running validator summary behavior test..."

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
Host: 192.0.2.40 () Ports: 554/open/tcp//rtsp//Reolink IP Camera///, 80/open/tcp//http//Reolink Web UI///, 445/open/tcp//microsoft-ds///, 3389/open/tcp//ms-wbt-server///
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

def summary(ip):
    value = classification(ip).get("validator_summary")

    if not isinstance(value, dict):
        raise SystemExit(f"[-] {ip}: validator_summary is missing or not an object")

    return value

failures = []

weak = summary("192.0.2.10")

if weak.get("total", 0) < 1:
    failures.append("192.0.2.10: weak host should have validator summary total >= 1")

if weak.get("confirmed", 0) != 0:
    failures.append("192.0.2.10: weak generic web host should have zero confirmed validators")

if "weak_evidence_validator" not in weak.get("names", []):
    failures.append("192.0.2.10: weak summary missing weak_evidence_validator name")

web = summary("192.0.2.20")

if web.get("confirmed", 0) < 1:
    failures.append("192.0.2.20: nginx host should have confirmed validator count >= 1")

if "service_text_product_validator" not in web.get("names", []):
    failures.append("192.0.2.20: web summary missing service_text_product_validator")

camera = summary("192.0.2.30")

if camera.get("confirmed", 0) < 1:
    failures.append("192.0.2.30: Reolink camera should have confirmed validator count >= 1")

conflicted = summary("192.0.2.40")
conflicted_classification = classification("192.0.2.40")

if conflicted_classification.get("validation_state") != "conflicted":
    failures.append("192.0.2.40: expected validation_state=conflicted")

if conflicted.get("inconclusive", 0) < 1:
    failures.append("192.0.2.40: conflicted host should have inconclusive validator count >= 1")

if "contradiction_validator" not in conflicted.get("names", []):
    failures.append("192.0.2.40: conflicted summary missing contradiction_validator")

for ip in required_ips:
    current = summary(ip)
    total_by_status = (
        int(current.get("confirmed", 0))
        + int(current.get("inconclusive", 0))
        + int(current.get("refuted", 0))
        + int(current.get("not_applicable", 0))
        + int(current.get("error", 0))
    )

    if total_by_status != int(current.get("total", 0)):
        failures.append(f"{ip}: validator summary status counts do not equal total")

if failures:
    print("[-] Validator summary behavior failures:")
    for failure in failures:
        print(f"    - {failure}")
    raise SystemExit(1)

print("[+] PASS: v1.6 validator summary behavior is valid.")
print(f"[+] Analysis JSON: {path}")
PY

echo
echo "[+] PASS: NetSniper v1.6 validator summary validation succeeded."
