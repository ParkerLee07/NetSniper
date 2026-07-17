#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netsniper_core.classifier import classify_host
from netsniper_core.contracts import UNCERTAINTY_REASONS, load_json

FIXED_TIME = "2026-07-15T00:00:00Z"
FIXTURE_PATH = ROOT / "fixtures/embedded-admin-boundary/cases.json"
PROFILES_PATH = ROOT / "classification/evidence_profiles.json"


def fail(message: str) -> None:
    raise SystemExit(f"[FAIL] {message}")


def passed(message: str) -> None:
    print(f"[PASS] {message}")


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def web_role(result: dict[str, Any]) -> dict[str, Any]:
    return next(
        (role for role in result.get("roles", []) if role.get("label") == "web_server"),
        {"label": "web_server", "confidence": 0, "decision": "unknown", "uncertainty_reasons": []},
    )


def validate_case(case: dict[str, Any], profiles: dict[str, Any]) -> None:
    case_id = str(case["case_id"])
    first = classify_host(case["host_record"], profiles, generated_at=FIXED_TIME)
    second = classify_host(case["host_record"], profiles, generated_at=FIXED_TIME)
    assert_true(first == second, f"{case_id}: classification is not deterministic")

    role = web_role(first)
    expect = case["expect"]
    assert_true(role["decision"] == expect["web_server_decision"], f"{case_id}: web-server decision mismatch")
    confidence = int(role["confidence"])
    assert_true(
        int(expect["web_server_minimum_confidence"]) <= confidence <= int(expect["web_server_maximum_confidence"]),
        f"{case_id}: web-server confidence {confidence} outside expected range",
    )

    reasons = set(role.get("uncertainty_reasons", []))
    assert_true(set(expect.get("required_reasons", [])).issubset(reasons), f"{case_id}: required uncertainty reason missing")
    assert_true(not set(expect.get("forbidden_reasons", [])) & reasons, f"{case_id}: forbidden uncertainty reason present")

    family_label = expect.get("required_family_label")
    if family_label:
        assert_true(first["device_family"]["label"] == family_label, f"{case_id}: expected family {family_label}")
        assert_true(first["device_family"]["decision"] == "classified", f"{case_id}: appliance family is not classified")

    required_role = expect.get("required_role_label")
    if required_role:
        matched = next((item for item in first["roles"] if item.get("label") == required_role), None)
        assert_true(matched is not None and matched.get("decision") == "classified", f"{case_id}: required appliance role is not classified")

    legacy = first["legacy_projection"]
    if expect.get("legacy_primary_type"):
        assert_true(legacy["primary_type"] == expect["legacy_primary_type"], f"{case_id}: legacy primary type mismatch")
    if expect.get("legacy_decision"):
        assert_true(legacy["decision"] == expect["legacy_decision"], f"{case_id}: legacy decision mismatch")
    if expect.get("forbidden_legacy_primary_type"):
        assert_true(legacy["primary_type"] != expect["forbidden_legacy_primary_type"], f"{case_id}: forbidden legacy web-server projection survived")


def main() -> int:
    fixtures = load_json(FIXTURE_PATH)
    profiles = load_json(PROFILES_PATH)
    assert_true(fixtures.get("schema_version") == "netsniper-embedded-admin-boundary-fixtures-v1", "fixture schema mismatch")
    assert_true(fixtures.get("sanitized") is True, "fixture set is not marked sanitized")
    cases = fixtures.get("cases", [])
    assert_true(isinstance(cases, list) and len(cases) == 7, "expected seven embedded-admin regression cases")

    text = FIXTURE_PATH.read_text(encoding="utf-8")
    assert_true("192.168." not in text and "10." not in text and not re.search(r"172\.(1[6-9]|2[0-9]|3[01])\.", text), "fixture contains RFC1918 addressing")
    assert_true(not re.search(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b", text), "fixture contains a MAC address")
    passed("sanitized regression cases contain no reference-network identifiers")

    web_profile = next((item for item in profiles.get("axis_profiles", []) if item.get("axis") == "role" and item.get("label") == "web_server"), None)
    assert_true(web_profile is not None, "web-server profile missing")
    guard = web_profile.get("classification_guard", {})
    assert_true(guard.get("kind") == "embedded_admin_web_server_boundary", "machine-readable web-server guard missing")
    assert_true(set(guard.get("minimum_classified_independence_groups", [])) == {"web_service", "server_context"}, "classified web-server independence contract changed")
    assert_true(profiles.get("scoring_policy", {}).get("embedded_admin_web_server_cap") == 39, "embedded-admin cap must remain 39")
    assert_true("embedded_admin_interface" in UNCERTAINTY_REASONS, "controlled uncertainty vocabulary is missing embedded_admin_interface")
    passed("machine-readable guard, independence groups, confidence cap, and uncertainty vocabulary agree")

    for case in cases:
        validate_case(case, profiles)
    passed("embedded printers, controllers, cameras, and network appliances remain review-only as web servers")
    passed("standalone web servers still classify with independent server context")
    passed("HTTP-only evidence remains weak and legacy appliance projection is preserved")

    assert_true(not (ROOT / "fixtures/device-corpus/evaluation").exists(), "formal evaluation tree remains")
    passed("embedded-administration cases run as ordinary regression checks without evaluation-seal dependencies")

    shell = (ROOT / "tools/validate_v2_1_stage1_2_all.sh").read_text(encoding="utf-8")
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert_true("validate_v2_1_embedded_admin_boundary.py" in shell, "complete gate omits embedded-admin validator")
    assert_true("validate_v2_1_embedded_admin_boundary.py" in ci, "CI syntax list omits embedded-admin validator")
    passed("embedded-administration regression is wired into CI and the complete gate")

    passed("NetSniper v2.1 embedded administration boundary validator complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
