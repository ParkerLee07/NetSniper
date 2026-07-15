#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netsniper_core.contracts import load_json
from netsniper_core.corpus_replay import FIXED_REPLAY_TIME, replay_corpus

EXPECTED_ACTIVE_SPLITS = {"development": 14, "regression": 4}
EXPECTED_TOTAL_SPLITS = {"development": 14, "evaluation": 12, "regression": 4}
EXPECTED_FIXTURE_FILE_COUNT = 36


def fail(message: str) -> None:
    raise SystemExit(f"[FAIL] {message}")


def passed(message: str) -> None:
    print(f"[PASS] {message}")


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def confined(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError:
        fail(f"corpus path escapes repository: {relative}")
    return candidate


def validate_manifest_activation() -> tuple[dict, list[dict]]:
    manifest = load_json(ROOT / "fixtures/device-corpus/manifest.json")
    schema = load_json(ROOT / "fixtures/device-corpus/schema.json")
    fixtures = manifest.get("fixtures", [])
    assert_true(manifest.get("status") == "approved", "corpus manifest is not approved")
    assert_true(isinstance(fixtures, list) and len(fixtures) == 30, "corpus must contain exactly 30 fixtures")

    split_counts = Counter(item["dataset_split"] for item in fixtures)
    assert_true(dict(split_counts) == EXPECTED_TOTAL_SPLITS, "frozen 14/12/4 split changed")
    active = [item for item in fixtures if item["status"] == "active"]
    planned = [item for item in fixtures if item["status"] == "planned"]
    active_counts = Counter(item["dataset_split"] for item in active)
    assert_true(dict(active_counts) == EXPECTED_ACTIVE_SPLITS, "active fixtures are not exactly development + regression")
    assert_true(len(active) == 18, "exactly 18 fixtures must be active")
    assert_true(len(planned) == 12, "exactly 12 evaluation fixtures must remain planned")
    assert_true(
        all(item["dataset_split"] == "evaluation" for item in planned),
        "a non-evaluation fixture remains planned or an evaluation fixture was activated",
    )
    assert_true(
        all(item["fixture_kind"] == "synthetic" for item in active),
        "only synthetic fixtures may be active at this checkpoint",
    )
    assert_true(
        all(item["fixture_kind"] == "sanitized_real" for item in fixtures[-3:]),
        "sanitized-real evaluation placeholders changed",
    )

    if importlib.util.find_spec("jsonschema") is not None:
        import jsonschema

        jsonschema.validate(manifest, schema)
        passed("activated corpus manifest validates against JSON Schema")
    else:
        passed("activated corpus manifest semantic validation passed without optional jsonschema")

    passed("frozen split preserved with 18 active development/regression fixtures")
    return manifest, active


def _classification_payload(data: dict) -> dict:
    if isinstance(data.get("host_record"), dict):
        return data["host_record"]
    if isinstance(data.get("synthetic_observation"), dict):
        return data["synthetic_observation"]
    return {}


def _assert_no_target_leakage(fixture_id: str, data: dict, relative: str) -> None:
    if data.get("mode") not in {None, "classification"}:
        return
    payload = _classification_payload(data)
    forbidden = {
        key: payload.get(key)
        for key in ("network_role", "network_roles", "role", "roles")
        if payload.get(key) not in (None, "", [], {})
    }
    assert_true(
        not forbidden,
        f"{fixture_id} embeds classification-target fields in {relative}: {forbidden}",
    )


def validate_fixture_files(active: list[dict]) -> None:
    active_root = ROOT / "fixtures/device-corpus/active"
    files = sorted(path for path in active_root.rglob("*.json") if path.is_file())
    assert_true(len(files) == EXPECTED_FIXTURE_FILE_COUNT, "active corpus must contain exactly 36 JSON files")
    expected_paths: set[Path] = set()
    for fixture in active:
        source_paths = fixture.get("source_artifacts", [])
        assert_true(len(source_paths) == 1, f"{fixture['fixture_id']} must have one source artifact")
        normalized = fixture.get("normalized_evidence_path")
        assert_true(isinstance(normalized, str), f"{fixture['fixture_id']} lacks normalized evidence")
        for relative in [*source_paths, normalized]:
            path = confined(ROOT, relative)
            assert_true(path.is_file(), f"missing active fixture file: {relative}")
            expected_paths.add(path)
            data = load_json(path)
            _assert_no_target_leakage(fixture["fixture_id"], data, relative)
        assert_true(
            fixture["provenance"].get("recorded_at") == FIXED_REPLAY_TIME,
            f"{fixture['fixture_id']} provenance timestamp is not fixed",
        )
    assert_true(set(files) == expected_paths, "active corpus tree contains unreferenced or missing JSON files")
    passed(
        "all active files are confined, referenced, and free of classification-target leakage"
    )


def validate_profile_calibration() -> None:
    profiles = load_json(ROOT / "classification/evidence_profiles.json")
    by_key = {
        (item["axis"], item["label"]): item
        for item in profiles.get("axis_profiles", [])
    }
    infrastructure = by_key[("device_family", "network_infrastructure")]
    infrastructure_rules = {
        item.get("id"): item
        for item in infrastructure["positive_evidence"]
    }
    assert_true(
        "infrastructure_explicit_role" not in infrastructure_rules,
        "network-infrastructure family still trusts a pre-labeled role",
    )
    infrastructure_product = infrastructure_rules.get(
        "infrastructure_network_product"
    )
    assert_true(
        isinstance(infrastructure_product, dict)
        and infrastructure_product.get("source") == "service"
        and int(infrastructure_product.get("points", 0)) == 50,
        "network-infrastructure observable product calibration mismatch",
    )
    ap = by_key[("role", "wireless_access_point")]
    ap_rules = {
        item.get("id"): item
        for item in ap["positive_evidence"]
    }
    assert_true(
        "role_ap_explicit_role" not in ap_rules,
        "wireless access point role still trusts a pre-labeled role",
    )
    ap_product = ap_rules.get("role_ap_product")
    assert_true(
        isinstance(ap_product, dict)
        and ap_product.get("source") == "service"
        and int(ap_product.get("points", 0)) == 50,
        "wireless access point observable product calibration mismatch",
    )
    client = by_key[("device_family", "client_endpoint")]
    client_points = {
        item["id"]: int(item["points"])
        for item in client["positive_evidence"]
        if item["id"] in {"client_windows_os", "client_macos_os", "client_mobile_os"}
    }
    assert_true(client_points == {
        "client_windows_os": 55,
        "client_macos_os": 55,
        "client_mobile_os": 55,
    }, "client endpoint OS calibration mismatch")
    database = by_key[("role", "database_server")]
    db_product = next(item for item in database["positive_evidence"] if item["id"] == "role_db_product_v2")
    assert_true(
        int(db_product["points"]) == 70 and db_product.get("unique_identifying") is True,
        "database product signature is not uniquely classified",
    )
    dns = by_key[("role", "dns_server")]
    dns_product = next(item for item in dns["positive_evidence"] if item["id"] == "dns_product")
    assert_true(int(dns_product["points"]) == 55, "DNS product calibration mismatch")
    passed("development calibration uses observable evidence and is machine-readable")


def validate_replay() -> dict:
    report = replay_corpus(
        ROOT,
        splits={"development", "regression"},
        generated_at=FIXED_REPLAY_TIME,
    )
    metrics = report["metrics"]
    expected_rates = {
        "deterministic_replay_rate": 1.0,
        "host_retention_rate": 1.0,
        "schema_validity_rate": 1.0,
        "uncertainty_reason_compliance_rate": 1.0,
        "confidence_cap_compliance_rate": 1.0,
        "contradiction_review_rate": 1.0,
        "legacy_projection_match_rate": 1.0,
        "fixture_expectation_pass_rate": 1.0,
    }
    assert_true(report["passed"] is True, "one or more active fixtures failed")
    assert_true(report["split_counts"] == EXPECTED_ACTIVE_SPLITS, "replay selected the wrong splits")
    assert_true(metrics["active_fixture_count"] == 18, "replay did not execute 18 fixtures")
    assert_true(metrics["output_fixture_count"] == 18, "replay did not retain all 18 hosts")
    for name, expected in expected_rates.items():
        assert_true(metrics[name] == expected, f"{name} is not {expected}")
    assert_true(metrics["false_high_confidence_count"] == 0, "false high-confidence result detected")
    assert_true(metrics["false_classified_unknown_count"] == 0, "unknown control was falsely classified")
    passed("18 active fixtures replay deterministically with every exact gate at 100%")
    return report


def validate_cli_determinism(report: dict) -> None:
    with tempfile.TemporaryDirectory(prefix="netsniper-corpus-replay-") as temporary:
        first = Path(temporary) / "first.json"
        second = Path(temporary) / "second.json"
        base = [
            sys.executable,
            str(ROOT / "tools/replay_v2_1_corpus.py"),
            "--split", "development",
            "--split", "regression",
            "--generated-at", FIXED_REPLAY_TIME,
        ]
        for output in (first, second):
            completed = subprocess.run(
                [*base, "--output", str(output), "--summary-only"],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            if completed.returncode != 0:
                print(completed.stdout)
                print(completed.stderr, file=sys.stderr)
                fail("corpus replay CLI failed")
        assert_true(first.read_bytes() == second.read_bytes(), "replay CLI outputs are not byte-identical")
        cli_report = load_json(first)
        assert_true(cli_report["metrics"] == report["metrics"], "CLI and in-process replay metrics differ")
    passed("independent corpus CLI runs produce byte-identical output")


def validate_gate_integration() -> None:
    shell = (ROOT / "tools/validate_v2_1_stage1_2_all.sh").read_text(encoding="utf-8")
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    docs = (ROOT / "docs/v2.1-corpus-activation.md").read_text(encoding="utf-8")
    assert_true("validate_v2_1_corpus_activation.py" in shell, "complete v2.1 gate omits corpus activation")
    assert_true("replay_v2_1_corpus.py" in ci, "CI syntax list omits corpus replay tool")
    assert_true("validate_v2_1_corpus_activation.py" in ci, "CI syntax list omits activation validator")
    assert_true("14 development" in docs and "4 regression" in docs and "12 evaluation" in docs, "activation documentation lacks split hold")
    passed("corpus replay is wired into the complete gate, CI, and documentation")


def main() -> int:
    _, active = validate_manifest_activation()
    validate_fixture_files(active)
    validate_profile_calibration()
    report = validate_replay()
    validate_cli_determinism(report)
    validate_gate_integration()
    passed("NetSniper v2.1 deterministic corpus activation validator complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
