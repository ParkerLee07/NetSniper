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

EXPECTED_SPLITS = {"development": 14, "regression": 4}
EXPECTED_FIXTURE_FILE_COUNT = 36
FORBIDDEN_FORMAL_EVALUATION_PATHS = (
    "fixtures/device-corpus/evaluation",
    "docs/v2.1-evaluation-candidate-reseal.md",
    "docs/v2.1-evaluation-corpus-preparation.md",
    "tools/validate_v2_1_evaluation_candidate_reseal.py",
    "tools/validate_v2_1_evaluation_preparation.py",
    "docs/v2.1-sanitized-real-fixture-activation.md",
    "tools/validate_v2_1_sanitized_real_activation.py",
)


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


def validate_formal_evaluation_removed(manifest: dict, schema: dict) -> None:
    assert_true("evaluation_policy" not in manifest, "manifest still contains evaluation_policy")
    assert_true("metric_gates" not in manifest, "manifest still contains metric_gates")
    assert_true("evaluation_policy" not in schema.get("properties", {}), "schema still defines evaluation_policy")
    assert_true("metric_gates" not in schema.get("properties", {}), "schema still defines metric_gates")
    split_values = schema["$defs"]["fixture"]["properties"]["dataset_split"]["enum"]
    assert_true(split_values == ["development", "regression"], "schema still permits a formal evaluation split")
    for relative in FORBIDDEN_FORMAL_EVALUATION_PATHS:
        assert_true(not (ROOT / relative).exists(), f"formal evaluation artifact still exists: {relative}")
    replay = (ROOT / "tools/replay_v2_1_corpus.py").read_text(encoding="utf-8")
    assert_true('choices=["development", "regression"]' in replay, "replay CLI split choices are not simplified")
    assert_true('"evaluation"' not in replay, "replay CLI still exposes evaluation")
    passed("formal evaluation, seal, replay-authorization, and statistical-gate machinery is absent")


def validate_manifest() -> tuple[dict, list[dict]]:
    manifest = load_json(ROOT / "fixtures/device-corpus/manifest.json")
    schema = load_json(ROOT / "fixtures/device-corpus/schema.json")
    fixtures = manifest.get("fixtures", [])
    assert_true(manifest.get("status") == "approved", "corpus manifest is not approved")
    assert_true(isinstance(fixtures, list) and len(fixtures) == 18, "corpus must contain exactly 18 fixtures")
    assert_true(all(item.get("status") == "active" for item in fixtures), "every remaining fixture must be active")
    assert_true(all(item.get("fixture_kind") == "synthetic" for item in fixtures), "current corpus must contain only synthetic tests")
    split_counts = Counter(item["dataset_split"] for item in fixtures)
    assert_true(dict(split_counts) == EXPECTED_SPLITS, "corpus is not exactly 14 development and 4 regression fixtures")
    assert_true(not any(item.get("dataset_split") == "evaluation" for item in fixtures), "evaluation fixture remains in manifest")

    if importlib.util.find_spec("jsonschema") is not None:
        import jsonschema
        jsonschema.validate(manifest, schema)
        passed("deterministic corpus manifest validates against JSON Schema")
    else:
        passed("deterministic corpus semantic validation passed without optional jsonschema")

    validate_formal_evaluation_removed(manifest, schema)
    passed("exact 14-development/4-regression corpus is active")
    return manifest, fixtures


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
    assert_true(not forbidden, f"{fixture_id} embeds classification-target fields in {relative}: {forbidden}")


def validate_fixture_files(fixtures: list[dict]) -> None:
    active_root = ROOT / "fixtures/device-corpus/active"
    files = sorted(path for path in active_root.rglob("*.json") if path.is_file())
    assert_true(len(files) == EXPECTED_FIXTURE_FILE_COUNT, "active corpus must contain exactly 36 JSON files")
    expected_paths: set[Path] = set()
    for fixture in fixtures:
        source_paths = fixture.get("source_artifacts", [])
        assert_true(len(source_paths) == 1, f"{fixture['fixture_id']} must have one source artifact")
        normalized = fixture.get("normalized_evidence_path")
        assert_true(isinstance(normalized, str), f"{fixture['fixture_id']} lacks normalized evidence")
        for relative in [*source_paths, normalized]:
            path = confined(ROOT, relative)
            assert_true(path.is_file(), f"missing fixture file: {relative}")
            expected_paths.add(path)
            data = load_json(path)
            _assert_no_target_leakage(fixture["fixture_id"], data, relative)
        assert_true(fixture["provenance"].get("recorded_at") == FIXED_REPLAY_TIME, f"{fixture['fixture_id']} provenance timestamp is not fixed")
    assert_true(set(files) == expected_paths, "active corpus tree contains unreferenced or missing JSON files")
    passed("all 36 test inputs are confined, referenced, and free of classification-target leakage")


def validate_coverage(manifest: dict, fixtures: list[dict]) -> None:
    coverage = manifest.get("coverage_requirements", {})
    family_counts = Counter(item["ground_truth"]["device_family"] for item in fixtures)
    role_counts = Counter(role for item in fixtures for role in item["ground_truth"]["roles"])
    tags = {tag for item in fixtures for tag in item.get("scenario_tags", [])}
    for label, minimum in coverage.get("minimum_active_fixtures_per_family", {}).items():
        assert_true(family_counts[label] >= int(minimum), f"family coverage below minimum: {label}")
    for label, minimum in coverage.get("minimum_active_fixtures_per_role", {}).items():
        assert_true(role_counts[label] >= int(minimum), f"role coverage below minimum: {label}")
    required_tags = set(coverage.get("required_scenario_tags", []))
    assert_true(required_tags <= tags, f"required scenario tags missing: {sorted(required_tags - tags)}")
    assert_true("sanitized-real" not in required_tags, "real-capture floor remains in deterministic corpus policy")
    passed("declared family, role, and scenario regression coverage is satisfied")


def validate_profile_calibration() -> None:
    profiles = load_json(ROOT / "classification/evidence_profiles.json")
    by_key = {(item["axis"], item["label"]): item for item in profiles.get("axis_profiles", [])}
    infrastructure = by_key[("device_family", "network_infrastructure")]
    infrastructure_rules = {item.get("id"): item for item in infrastructure["positive_evidence"]}
    assert_true("infrastructure_explicit_role" not in infrastructure_rules, "network-infrastructure family trusts a pre-labeled role")
    product = infrastructure_rules.get("infrastructure_network_product")
    assert_true(isinstance(product, dict) and product.get("source") == "service" and int(product.get("points", 0)) == 50, "network-infrastructure observable product calibration mismatch")
    ap = by_key[("role", "wireless_access_point")]
    ap_rules = {item.get("id"): item for item in ap["positive_evidence"]}
    assert_true("role_ap_explicit_role" not in ap_rules, "wireless access point role trusts a pre-labeled role")
    ap_product = ap_rules.get("role_ap_product")
    assert_true(isinstance(ap_product, dict) and ap_product.get("source") == "service" and int(ap_product.get("points", 0)) == 50, "wireless access point observable product calibration mismatch")
    passed("development calibration continues to use observable evidence")


def validate_replay() -> dict:
    report = replay_corpus(ROOT, splits={"development", "regression"}, generated_at=FIXED_REPLAY_TIME)
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
    assert_true(report["passed"] is True, "one or more deterministic fixtures failed")
    assert_true(report["split_counts"] == EXPECTED_SPLITS, "replay selected the wrong splits")
    assert_true(metrics["active_fixture_count"] == 18, "replay did not execute 18 fixtures")
    assert_true(metrics["output_fixture_count"] == 18, "replay did not retain all 18 hosts")
    for name, expected in expected_rates.items():
        assert_true(metrics[name] == expected, f"{name} is not {expected}")
    assert_true(metrics["false_high_confidence_count"] == 0, "false high-confidence result detected")
    assert_true(metrics["false_classified_unknown_count"] == 0, "unknown control was falsely classified")
    passed("18 fixtures replay deterministically with every exact test gate at 100%")
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
            completed = subprocess.run([*base, "--output", str(output), "--summary-only"], cwd=ROOT, capture_output=True, text=True)
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
    characterization = (ROOT / "docs/v2.1-real-world-characterization.md").read_text(encoding="utf-8")
    assert_true("validate_v2_1_corpus_activation.py" in shell, "complete v2.1 gate omits corpus validator")
    assert_true("replay_v2_1_corpus.py" in ci, "CI syntax list omits corpus replay tool")
    assert_true("validate_v2_1_corpus_activation.py" in ci, "CI syntax list omits corpus validator")
    assert_true("14 development" in docs and "4 regression" in docs, "corpus documentation lacks exact split counts")
    assert_true("statistical" in characterization.lower() and "accuracy percentage" in characterization.lower(), "characterization documentation lacks non-statistical boundary")
    passed("deterministic corpus and characterization boundaries are wired into validation and documentation")


def main() -> int:
    manifest, fixtures = validate_manifest()
    validate_fixture_files(fixtures)
    validate_coverage(manifest, fixtures)
    validate_profile_calibration()
    report = validate_replay()
    validate_cli_determinism(report)
    validate_gate_integration()
    passed("NetSniper v2.1 deterministic corpus validator complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
