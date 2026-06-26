#!/usr/bin/env bash
set -euo pipefail

fail() {
    echo "[FAIL] $1" >&2
    exit 1
}

pass() {
    echo "[PASS] $1"
}

cd "$(dirname "$0")/.." || exit 1

[[ -f docs/V1_9_ACCURACY_GUIDELINES.md ]] \
    || fail "missing v1.9 accuracy guidelines"

[[ -f config/scan_profiles.json ]] \
    || fail "missing scan profile contract"

grep -Fq 'NetSniper remains' docs/V1_9_ACCURACY_GUIDELINES.md \
    || fail "guidelines missing NetSniper product boundary"

grep -Fq 'NetSniper must not add' docs/V1_9_ACCURACY_GUIDELINES.md \
    || fail "guidelines missing no-web-dashboard boundary"

grep -Fq 'DeltaAegis owns dashboards' docs/V1_9_ACCURACY_GUIDELINES.md \
    || fail "guidelines missing DeltaAegis dashboard ownership"

python3 - <<'PYJSON'
import json
from pathlib import Path

profile_path = Path("config/scan_profiles.json")
data = json.loads(profile_path.read_text(encoding="utf-8"))

assert data["schema_version"] == "netsniper-scan-profiles-v1", data
assert data["release_target"] == "v1.9.0", data
assert data["default_profile"] == "balanced", data

profiles = data.get("profiles")
assert isinstance(profiles, list), data
assert len(profiles) == 4, profiles

by_name = {profile["name"]: profile for profile in profiles}
expected = {"quick", "balanced", "accurate", "deep"}
assert set(by_name) == expected, by_name

defaults = [profile["name"] for profile in profiles if profile.get("default") is True]
assert defaults == ["balanced"], defaults

assert by_name["balanced"]["manual_only"] is False
assert by_name["balanced"]["deltaaegis_safe_default"] is True
assert by_name["balanced"]["full_tcp"] is False
assert by_name["balanced"]["udp_lite"] is False
assert by_name["balanced"]["os_detection"] is False
assert by_name["balanced"]["intrusive_scripts"] is False

assert by_name["accurate"]["version_intensity"] == 7
assert by_name["accurate"]["os_detection"] is True
assert by_name["accurate"]["os_detection_evidence_only"] is True
assert by_name["accurate"]["udp_lite"] is True
assert by_name["accurate"]["full_tcp"] is False
assert by_name["accurate"]["intrusive_scripts"] is False

assert by_name["deep"]["manual_only"] is True
assert by_name["deep"]["full_tcp"] is True
assert by_name["deep"]["version_intensity"] == 9
assert by_name["deep"]["intrusive_scripts"] is False

udp_ports = data.get("udp_lite_ports")
assert isinstance(udp_ports, list), udp_ports
assert set(udp_ports) == {53, 67, 68, 123, 137, 161, 1900, 5353, 5355}, udp_ports

forbidden = set(data.get("forbidden_defaults", []))
for required in {
    "full_tcp",
    "full_udp",
    "intrusive_scripts",
    "credential_checks",
    "exploit_checks",
    "default_password_checks",
    "web_dashboard",
}:
    assert required in forbidden, forbidden

for profile in profiles:
    assert profile["tcp_port_mode"] in {"curated", "full"}, profile
    assert profile["nmap_timing"] in {"-T3", "-T4"}, profile
    assert isinstance(profile["service_detection"], bool), profile
    assert isinstance(profile["accuracy_notes"], list), profile
    assert profile["accuracy_notes"], profile

print("[PASS] v1.9 scan profile contract JSON checks passed")
PYJSON

python3 - <<'PYWEB'
import re
from pathlib import Path

patterns = re.compile(
    r"Flask|FastAPI|uvicorn|http\.server|BaseHTTPRequestHandler|app\.run|"
    r"<html|</html>|localhost:[0-9]+",
    re.IGNORECASE,
)

runtime_files = [
    Path("netsniper.sh"),
    Path("install.sh"),
]

runtime_files.extend(sorted(Path("tools").glob("*.py")))

matches = []
for path in runtime_files:
    if not path.is_file():
        continue
    text = path.read_text(encoding="utf-8", errors="ignore")
    for lineno, line in enumerate(text.splitlines(), start=1):
        if patterns.search(line):
            matches.append(f"{path}:{lineno}:{line.strip()}")

if matches:
    print("\n".join(matches))
    raise SystemExit("web/dashboard/server pattern found in NetSniper runtime files")

print("[PASS] v1.9 no-web-runtime boundary checks passed")
PYWEB

pass "NetSniper v1.9 scan profile contract validation passed"
