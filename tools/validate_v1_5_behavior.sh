#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/NetSniper}" || {
  echo "[-] Could not enter NetSniper repo."
  exit 1
}

echo "[*] Running compact static validator..."
./tools/validate_v1_5_classifier_progress.sh

echo "[*] Running synthetic behavior smoke test..."

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
Host: 192.0.2.1 () Ports: 7547/open/tcp//cwmp///, 53/open/tcp//domain///, 80/open/tcp//http///, 443/open/tcp//https///
Host: 192.0.2.10 () Ports: 445/open/tcp//microsoft-ds///, 2049/open/tcp//nfs///, 5000/open/tcp//http///
Host: 192.0.2.31 () Ports: 6443/open/tcp//https///, 10250/open/tcp//https///
Host: 192.0.2.41 () Ports: 53/open/tcp//domain///, 88/open/tcp//kerberos-sec///, 389/open/tcp//ldap///, 445/open/tcp//microsoft-ds///
Host: 192.0.2.47 () Ports: 9100/open/tcp//jetdirect///, 631/open/tcp//ipp///, 80/open/tcp//http///
Host: 192.0.2.51 () Ports: 3000/open/tcp//http///, 9090/open/tcp//http///
Host: 192.0.2.70 () Ports: 80/open/tcp//http///
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

if isinstance(data, dict):
    hosts = data.get("hosts") or data.get("results") or data.get("analysis") or []
else:
    hosts = data

if not isinstance(hosts, list):
    raise SystemExit("[-] Analysis JSON did not contain a host list.")

by_ip = {
    item.get("ip"): item
    for item in hosts
    if isinstance(item, dict) and item.get("ip")
}

expected = {
    "192.0.2.1": "Router / Gateway",
    "192.0.2.10": "NAS / File Server",
    "192.0.2.31": "Container Infrastructure",
    "192.0.2.41": "Windows Server",
    "192.0.2.47": "Network Printer / Multifunction Printer",
    "192.0.2.51": "Development / Admin Interface",
}

failures = []

for ip, expected_type in expected.items():
    host = by_ip.get(ip)

    if not host:
        failures.append(f"{ip}: missing from output")
        continue

    classification = host.get("classification") or {}
    actual = classification.get("primary_type") or classification.get("type")
    confidence = int(classification.get("confidence") or 0)

    if actual != expected_type:
        failures.append(f"{ip}: expected {expected_type}, got {actual}")

    if confidence < 40:
        failures.append(f"{ip}: confidence too low: {confidence}")

generic = by_ip.get("192.0.2.70")

if not generic:
    failures.append("192.0.2.70: missing generic HTTP-only host")
else:
    classification = generic.get("classification") or {}
    primary = classification.get("primary_type") or classification.get("type")
    confidence = int(classification.get("confidence") or 0)
    decision = classification.get("decision")

    if primary == "Web Server" or confidence >= 40 or decision == "classified":
        failures.append(
            "192.0.2.70: generic HTTP-only host became overconfident "
            f"(primary={primary}, confidence={confidence}, decision={decision})"
        )

if failures:
    print("[-] Behavior validation failures:")
    for failure in failures:
        print(f"    - {failure}")
    raise SystemExit(1)

print(f"[+] PASS: behavior smoke test validated {len(expected) + 1} synthetic hosts.")
print(f"[+] Analysis JSON: {path}")
PY

echo
echo "[+] PASS: NetSniper v1.5 behavior smoke validation succeeded."
