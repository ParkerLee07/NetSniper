#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/NetSniper}" || {
  echo "[-] Could not enter NetSniper repo."
  exit 1
}

echo "[*] Checking shell syntax..."
bash -n netsniper.sh

echo "[*] Checking v1.6 calibration markers..."

python3 - <<'PY'
from pathlib import Path

text = Path("netsniper.sh").read_text(encoding="utf-8")

required = [
    'SCANNER_VERSION="v1.6.0-dev"',
    "evidence_reliability()",
    "calibrated_decision()",
    "siem_action()",
    "calibration_reason()",
    "add_classification_validator()",
    "confidence_band:",
    "calibrated_decision:",
    "siem_action:",
    "calibration_reason:",
    "validators:",
    "reliability: $reliability",
]

missing = [item for item in required if item not in text]

if missing:
    raise SystemExit(f"[-] Missing v1.6 calibration marker(s): {missing}")

print("[+] PASS: v1.6 calibration markers are present.")
PY

echo "[*] Running synthetic calibration behavior test..."

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
Host: 192.0.2.40 () Ports: 3000/open/tcp//http///, 9090/open/tcp//http///
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

failures = []

for ip, host in by_ip.items():
    classification = host.get("classification") or {}

    for key in [
        "confidence_band",
        "calibrated_decision",
        "siem_action",
        "calibration_reason",
        "validators",
    ]:
        if key not in classification:
            failures.append(f"{ip}: missing classification.{key}")

    evidence = classification.get("evidence") or []

    if not isinstance(evidence, list):
        failures.append(f"{ip}: evidence is not a list")
    else:
        for index, item in enumerate(evidence):
            if "reliability" not in item:
                failures.append(f"{ip}: evidence[{index}] missing reliability")

generic = by_ip["192.0.2.10"].get("classification") or {}

if int(generic.get("confidence") or 0) >= 40:
    failures.append("192.0.2.10: HTTP-only host should remain below 40 confidence")

if generic.get("confidence_band") != "weak":
    failures.append(f"192.0.2.10: expected weak band, got {generic.get('confidence_band')}")

if generic.get("calibrated_decision") != "review_only":
    failures.append(
        "192.0.2.10: weak host should be review_only, got "
        f"{generic.get('calibrated_decision')}"
    )

if generic.get("siem_action") != "display_only":
    failures.append(
        "192.0.2.10: weak host should be display_only, got "
        f"{generic.get('siem_action')}"
    )

web = by_ip["192.0.2.20"].get("classification") or {}

if web.get("confidence_band") != "possible":
    failures.append(f"192.0.2.20: nginx host should be possible, got {web.get('confidence_band')}")

if web.get("siem_action") != "review_queue":
    failures.append(f"192.0.2.20: possible host should be review_queue, got {web.get('siem_action')}")

camera = by_ip["192.0.2.30"].get("classification") or {}

if camera.get("confidence_band") != "confirmed":
    failures.append(f"192.0.2.30: Reolink host should be confirmed, got {camera.get('confidence_band')}")

if camera.get("calibrated_decision") != "classified":
    failures.append(
        "192.0.2.30: confirmed host should be classified, got "
        f"{camera.get('calibrated_decision')}"
    )

if camera.get("siem_action") != "alert_eligible":
    failures.append(
        "192.0.2.30: confirmed host should be alert_eligible, got "
        f"{camera.get('siem_action')}"
    )

admin = by_ip["192.0.2.40"].get("classification") or {}

if admin.get("confidence_band") not in {"likely", "confirmed"}:
    failures.append(
        "192.0.2.40: admin stack should be likely or confirmed, got "
        f"{admin.get('confidence_band')}"
    )

if failures:
    print("[-] Calibration validation failures:")
    for failure in failures:
        print(f"    - {failure}")
    raise SystemExit(1)

print("[+] PASS: v1.6 calibrated confidence behavior is valid.")
print(f"[+] Analysis JSON: {path}")
PY

echo
echo "[+] PASS: NetSniper v1.6 calibration validation succeeded."
