#!/usr/bin/env bash
set -euo pipefail

cd "${REPO_DIR:-$HOME/NetSniper}" || {
  echo "[-] Could not enter NetSniper repo."
  exit 1
}

echo "[*] Validating NetSniper v1.5 classification fixtures..."

test -f fixtures/classification-v1.5-fixtures.json
test -f docs/classification-v1.5-taxonomy.md

python3 - <<'PY'
from pathlib import Path
import json

fixture_path = Path("fixtures/classification-v1.5-fixtures.json")
taxonomy_path = Path("docs/classification-v1.5-taxonomy.md")

data = json.loads(fixture_path.read_text(encoding="utf-8"))
taxonomy = taxonomy_path.read_text(encoding="utf-8")

expected_categories = {
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
    "Web Server / Web Application Host",
    "Development / Admin Interface",
    "IoT / Embedded Device",
    "Client Device",
    "Unknown / Ambiguous",
}

if data.get("fixtures_version") != "netsniper-classification-fixtures-v1.5":
    raise SystemExit("[-] Invalid fixtures_version.")

if data.get("classification_schema") != "netsniper-classification-v1":
    raise SystemExit("[-] Invalid classification_schema.")

fixtures = data.get("fixtures")

if not isinstance(fixtures, list) or not fixtures:
    raise SystemExit("[-] fixtures must be a non-empty list.")

names = set()
covered = set()

for item in fixtures:
    name = item.get("name")
    host = item.get("host")
    expected = item.get("expected")

    if not name or not isinstance(name, str):
        raise SystemExit(f"[-] Fixture missing valid name: {item}")

    if name in names:
        raise SystemExit(f"[-] Duplicate fixture name: {name}")

    names.add(name)

    if not isinstance(host, dict):
        raise SystemExit(f"[-] Fixture {name} missing host object.")

    if "ip" not in host:
        raise SystemExit(f"[-] Fixture {name} missing host.ip.")

    ports = host.get("ports")

    if not isinstance(ports, list):
        raise SystemExit(f"[-] Fixture {name} host.ports must be a list.")

    for entry in ports:
        if not isinstance(entry, dict):
            raise SystemExit(f"[-] Fixture {name} has invalid port object: {entry}")

        if "proto" not in entry or "port" not in entry:
            raise SystemExit(f"[-] Fixture {name} port missing proto/port: {entry}")

        if entry["proto"] not in {"tcp", "udp"}:
            raise SystemExit(f"[-] Fixture {name} has invalid proto: {entry}")

        if not isinstance(entry["port"], int) or not (1 <= entry["port"] <= 65535):
            raise SystemExit(f"[-] Fixture {name} has invalid port number: {entry}")

    if not isinstance(expected, dict):
        raise SystemExit(f"[-] Fixture {name} missing expected object.")

    primary = expected.get("primary_type")
    decision = expected.get("decision")
    min_conf = expected.get("min_confidence")
    max_conf = expected.get("max_confidence")

    if primary not in expected_categories:
        raise SystemExit(f"[-] Fixture {name} has invalid primary_type: {primary}")

    if decision not in {"classified", "possible", "unknown"}:
        raise SystemExit(f"[-] Fixture {name} has invalid decision: {decision}")

    if not isinstance(min_conf, int) or not isinstance(max_conf, int):
        raise SystemExit(f"[-] Fixture {name} confidence bounds must be integers.")

    if not (0 <= min_conf <= max_conf <= 100):
        raise SystemExit(f"[-] Fixture {name} has invalid confidence bounds.")

    covered.add(primary)

missing_categories = sorted(expected_categories - covered)

if missing_categories:
    raise SystemExit(f"[-] Missing fixture coverage for categories: {missing_categories}")

for category in expected_categories:
    if category not in taxonomy:
        raise SystemExit(f"[-] Taxonomy missing category covered by fixtures: {category}")

negative = next(
    (
        item for item in fixtures
        if item.get("name") == "generic_web_interface_only_not_web_server"
    ),
    None,
)

if negative is None:
    raise SystemExit("[-] Missing negative-control web-interface fixture.")

negative_expected = negative["expected"]

if negative_expected["primary_type"] == "Web Server / Web Application Host":
    raise SystemExit("[-] Generic web interface fixture must not expect Web Server as primary type.")

if negative_expected["max_confidence"] > 39:
    raise SystemExit("[-] Generic web interface fixture should remain weak evidence only.")

secondary = negative_expected.get("secondary_candidates", [])

if "Web Server / Web Application Host" not in secondary:
    raise SystemExit("[-] Generic web interface fixture should preserve Web Server as a weak secondary candidate.")

print(f"[+] PASS: {len(fixtures)} v1.5 classification fixtures are valid.")
print("[+] Covered categories:")

for category in sorted(covered):
    print(f"    - {category}")
PY

echo
echo "[+] PASS: NetSniper v1.5 fixture validation succeeded."
