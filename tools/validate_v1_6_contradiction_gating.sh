#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/NetSniper}" || {
  echo "[-] Could not enter NetSniper repo."
  exit 1
}

echo "[*] Checking shell syntax..."
bash -n netsniper.sh

echo "[*] Checking contradiction gating markers..."

python3 - <<'PY'
from pathlib import Path

text = Path("netsniper.sh").read_text(encoding="utf-8")

required = [
    "classification_validation_state()",
    "CLASSIFICATION_VALIDATION_STATE",
    "CLASSIFICATION_CONTRADICTION_TOTAL",
    "contradiction_review",
    "validation_state:",
    "contradiction_count:"
]

missing = [item for item in required if item not in text]

if missing:
    raise SystemExit(f"[-] Missing contradiction gating marker(s): {missing}")

print("[+] PASS: contradiction gating markers are present.")
PY

echo "[*] Running contradiction gating behavior test..."

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

required_ips = {"192.0.2.10", "192.0.2.30", "192.0.2.40"}
missing_ips = sorted(required_ips - set(by_ip))

if missing_ips:
    raise SystemExit(f"[-] Missing expected hosts: {missing_ips}")

def classification(ip):
    return by_ip[ip].get("classification") or {}

failures = []

weak = classification("192.0.2.10")

if weak.get("validation_state") != "unvalidated":
    failures.append(
        "192.0.2.10: weak HTTP-only host should be unvalidated, got "
        f"{weak.get('validation_state')}"
    )

if int(weak.get("contradiction_count") or 0) != 0:
    failures.append("192.0.2.10: weak host should have zero contradictions")

clean_camera = classification("192.0.2.30")

if clean_camera.get("validation_state") != "validated":
    failures.append(
        "192.0.2.30: clean Reolink camera should be validated, got "
        f"{clean_camera.get('validation_state')}"
    )

if clean_camera.get("siem_action") != "alert_eligible":
    failures.append(
        "192.0.2.30: clean confirmed camera should remain alert_eligible, got "
        f"{clean_camera.get('siem_action')}"
    )

conflicted = classification("192.0.2.40")

if conflicted.get("validation_state") != "conflicted":
    failures.append(
        "192.0.2.40: contradictory camera/Windows host should be conflicted, got "
        f"{conflicted.get('validation_state')}"
    )

if int(conflicted.get("contradiction_count") or 0) < 1:
    failures.append("192.0.2.40: expected contradiction_count >= 1")

if conflicted.get("calibrated_decision") != "review_only":
    failures.append(
        "192.0.2.40: conflicted host should be review_only, got "
        f"{conflicted.get('calibrated_decision')}"
    )

if conflicted.get("siem_action") != "contradiction_review":
    failures.append(
        "192.0.2.40: conflicted host should use contradiction_review, got "
        f"{conflicted.get('siem_action')}"
    )

if conflicted.get("decision") != "classified":
    failures.append(
        "192.0.2.40: legacy decision should remain classified for compatibility, got "
        f"{conflicted.get('decision')}"
    )

if failures:
    print("[-] Contradiction gating behavior failures:")
    for failure in failures:
        print(f"    - {failure}")
    raise SystemExit(1)

print("[+] PASS: v1.6 contradiction-aware SIEM gating is valid.")
print(f"[+] Analysis JSON: {path}")
PY

echo
echo "[+] PASS: NetSniper v1.6 contradiction gating validation succeeded."
