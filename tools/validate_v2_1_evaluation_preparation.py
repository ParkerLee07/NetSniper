#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netsniper_core.contracts import load_json

SEAL_VERSION = "netsniper-evaluation-preparation-seal-v1"
BASE_COMMIT = "a760fc7e125a223181cf44c63a151c3eebcbe460"
FREEZE_COMMIT = "a4c027c9ab5f2fd1e7484b2ae9f8a76b10988c03"
FIXED_TIME = "2026-07-15T00:00:00Z"
EXPECTED_SPLITS = {"development": 14, "evaluation": 12, "regression": 4}
EXPECTED_ACTIVE = {"development": 14, "regression": 4}
EXPECTED_SYNTHETIC_IDS = {
    "synthetic-security-gateway-01",
    "synthetic-linux-web-db-container-01",
    "synthetic-network-video-recorder-01",
    "synthetic-nas-01",
    "synthetic-linux-workstation-01",
    "synthetic-pbx-01",
    "synthetic-ups-monitor-01",
    "synthetic-iot-embedded-01",
    "synthetic-ambiguous-web-admin-01",
}
EXPECTED_REAL_IDS = {
    "sanitized-real-home-router-01",
    "sanitized-real-printer-01",
    "sanitized-real-client-endpoint-01",
}
FORBIDDEN_INPUT_KEYS = {"network_role", "network_roles", "role", "roles"}


def fail(message: str) -> None:
    raise SystemExit(f"[FAIL] {message}")


def passed(message: str) -> None:
    print(f"[PASS] {message}")


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def confined(relative: str, required_root: Path | None = None) -> Path:
    candidate = (ROOT / relative).resolve()
    try:
        candidate.relative_to(ROOT.resolve())
    except ValueError:
        fail(f"evaluation path escapes repository: {relative}")
    if required_root is not None:
        try:
            candidate.relative_to(required_root.resolve())
        except ValueError:
            fail(f"evaluation path escapes required root: {relative}")
    return candidate


def walk_forbidden(value: Any, location: str) -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key in FORBIDDEN_INPUT_KEYS:
                errors.append(f"{location}: forbidden classification-target key {key!r}")
            errors.extend(walk_forbidden(child, f"{location}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(walk_forbidden(child, f"{location}[{index}]"))
    return errors


def evaluation_contract(fixtures: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected = [item for item in fixtures if item["dataset_split"] == "evaluation"]
    return [
        {
            "fixture_id": item["fixture_id"],
            "fixture_kind": item["fixture_kind"],
            "dataset_split": item["dataset_split"],
            "split_assignment_reason": item["split_assignment_reason"],
            "ground_truth": item["ground_truth"],
            "observation": item["observation"],
            "expectations": item["expectations"],
        }
        for item in sorted(selected, key=lambda value: value["fixture_id"])
    ]


def validate_manifest() -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest = load_json(ROOT / "fixtures/device-corpus/manifest.json")
    schema = load_json(ROOT / "fixtures/device-corpus/schema.json")
    fixtures = manifest.get("fixtures", [])
    assert_true(manifest.get("status") == "approved", "corpus manifest is not approved")
    assert_true(isinstance(fixtures, list) and len(fixtures) == 30, "corpus must contain 30 fixtures")
    assert_true(
        dict(Counter(item["dataset_split"] for item in fixtures)) == EXPECTED_SPLITS,
        "frozen 14/12/4 split changed",
    )
    active = [item for item in fixtures if item["status"] == "active"]
    planned = [item for item in fixtures if item["status"] == "planned"]
    assert_true(
        dict(Counter(item["dataset_split"] for item in active)) == EXPECTED_ACTIVE,
        "active fixtures changed during evaluation preparation",
    )
    assert_true(
        len(planned) == 12 and all(item["dataset_split"] == "evaluation" for item in planned),
        "evaluation fixtures must remain planned before first replay",
    )
    synthetic = {
        item["fixture_id"]
        for item in planned
        if item["fixture_kind"] == "synthetic"
    }
    sanitized = {
        item["fixture_id"]
        for item in planned
        if item["fixture_kind"] == "sanitized_real"
    }
    assert_true(synthetic == EXPECTED_SYNTHETIC_IDS, "synthetic evaluation fixture inventory changed")
    assert_true(sanitized == EXPECTED_REAL_IDS, "sanitized-real evaluation fixture inventory changed")

    if importlib.util.find_spec("jsonschema") is not None:
        import jsonschema

        jsonschema.validate(manifest, schema)
        passed("evaluation-prepared manifest validates against JSON Schema")
    else:
        passed("evaluation-prepared manifest semantic validation passed without optional jsonschema")

    passed("all 12 evaluation fixtures remain planned and the 14/12/4 split is frozen")
    return manifest, planned


def validate_prepared_inputs(planned: list[dict[str, Any]]) -> dict[str, str]:
    prepared_root = ROOT / "fixtures/device-corpus/evaluation/prepared"
    disk_files = {
        path.resolve()
        for path in prepared_root.rglob("*.json")
        if path.is_file()
    }
    expected_paths: set[Path] = set()
    input_hashes: dict[str, str] = {}

    for fixture in planned:
        fixture_id = fixture["fixture_id"]
        if fixture["fixture_kind"] == "sanitized_real":
            assert_true(fixture.get("source_artifacts") == [], f"{fixture_id} must not contain fabricated real evidence")
            assert_true(fixture.get("normalized_evidence_path") is None, f"{fixture_id} must remain without normalized evidence")
            assert_true(fixture["provenance"].get("recorded_at") is None, f"{fixture_id} real capture timestamp must remain unset")
            continue

        sources = fixture.get("source_artifacts", [])
        normalized = fixture.get("normalized_evidence_path")
        assert_true(len(sources) == 1, f"{fixture_id} must have one prepared source artifact")
        assert_true(isinstance(normalized, str), f"{fixture_id} lacks prepared normalized evidence")
        assert_true(
            fixture["provenance"].get("recorded_at") == FIXED_TIME,
            f"{fixture_id} preparation timestamp is not fixed",
        )
        assert_true(
            "not consulted" in str(fixture["provenance"].get("notes", "")),
            f"{fixture_id} provenance does not record the no-result boundary",
        )

        source_relative = sources[0]
        source_path = confined(source_relative, prepared_root)
        normalized_path = confined(normalized, prepared_root)
        assert_true(source_path.is_file(), f"missing prepared source: {source_relative}")
        assert_true(normalized_path.is_file(), f"missing prepared normalized input: {normalized}")
        expected_paths.update({source_path, normalized_path})

        source = load_json(source_path)
        normalized_data = load_json(normalized_path)
        assert_true(source.get("schema_version") == "netsniper-corpus-source-v1", f"{fixture_id} source schema mismatch")
        assert_true(source.get("fixture_id") == fixture_id, f"{fixture_id} source fixture ID mismatch")
        assert_true(source.get("fixture_kind") == "synthetic", f"{fixture_id} source kind mismatch")
        assert_true(source.get("source_type") == "designed_host_observation", f"{fixture_id} source type mismatch")
        assert_true(
            source.get("evaluation_use") == "sealed_holdout_input_not_replayed_during_preparation",
            f"{fixture_id} source lacks evaluation-use boundary",
        )
        assert_true(normalized_data.get("schema_version") == "netsniper-corpus-input-v1", f"{fixture_id} normalized schema mismatch")
        assert_true(normalized_data.get("fixture_id") == fixture_id, f"{fixture_id} normalized fixture ID mismatch")
        assert_true(normalized_data.get("mode") == "classification", f"{fixture_id} normalized mode mismatch")
        assert_true(
            source.get("synthetic_observation") == normalized_data.get("host_record"),
            f"{fixture_id} source and normalized host records differ",
        )
        errors = walk_forbidden(normalized_data.get("host_record"), normalized)
        assert_true(not errors, "; ".join(errors))

        for relative, path in ((source_relative, source_path), (normalized, normalized_path)):
            input_hashes[relative] = sha256_file(path)

    assert_true(len(expected_paths) == 18, "exactly 18 synthetic evaluation files must be prepared")
    assert_true(disk_files == expected_paths, "prepared evaluation tree contains unreferenced or missing JSON files")
    passed("nine synthetic evaluation fixtures are prepared without target leakage")
    passed("three sanitized-real fixtures remain genuine-capture blockers with no fabricated artifacts")
    return dict(sorted(input_hashes.items()))


def validate_seal(manifest: dict[str, Any], input_hashes: dict[str, str]) -> None:
    seal_path = ROOT / "fixtures/device-corpus/evaluation/seal.json"
    seal = load_json(seal_path)
    assert_true(seal.get("schema_version") == SEAL_VERSION, "evaluation seal version mismatch")
    assert_true(seal.get("state") == "synthetic_prepared_sanitized_real_pending", "evaluation seal state mismatch")
    assert_true(seal.get("prepared_at") == FIXED_TIME, "evaluation seal timestamp mismatch")
    assert_true(seal.get("classifier_candidate_commit") == BASE_COMMIT, "candidate commit seal mismatch")
    assert_true(seal.get("evaluation_holdout_frozen_at") == FREEZE_COMMIT, "holdout freeze commit mismatch")
    assert_true(seal.get("evaluation_tuning_prohibited") is True, "evaluation tuning prohibition missing")
    assert_true(seal.get("first_evaluation_replay_executed") is False, "evaluation replay is incorrectly marked executed")
    assert_true(seal.get("statistical_claims_permitted") is False, "starter corpus must not permit statistical claims")
    assert_true(set(seal.get("prepared_synthetic_fixture_ids", [])) == EXPECTED_SYNTHETIC_IDS, "seal synthetic fixture inventory mismatch")
    assert_true(set(seal.get("pending_sanitized_real_fixture_ids", [])) == EXPECTED_REAL_IDS, "seal pending real fixture inventory mismatch")
    assert_true(seal.get("prepared_input_files") == input_hashes, "prepared input hashes do not match seal")
    expected_input_index = sha256_bytes(canonical_bytes(input_hashes))
    assert_true(seal.get("prepared_inputs_index_sha256") == expected_input_index, "prepared input index hash mismatch")

    contract_hash = sha256_bytes(canonical_bytes(evaluation_contract(manifest["fixtures"])))
    assert_true(seal.get("evaluation_contract_sha256") == contract_hash, "evaluation ground-truth/expectation contract changed")

    runtime = seal.get("runtime_fingerprints", {})
    assert_true(isinstance(runtime, dict) and runtime, "runtime fingerprint seal is empty")
    current_runtime: dict[str, str] = {}
    for relative in sorted(runtime):
        path = confined(relative)
        assert_true(path.is_file(), f"sealed runtime file is missing: {relative}")
        current_runtime[relative] = sha256_file(path)
    assert_true(runtime == current_runtime, "classifier/runtime files changed after evaluation preparation seal")

    expected_seal_id = sha256_bytes(
        canonical_bytes(
            {
                "commit": BASE_COMMIT,
                "freeze": FREEZE_COMMIT,
                "contract": contract_hash,
                "inputs": expected_input_index,
            }
        )
    )
    assert_true(seal.get("seal_id") == expected_seal_id, "evaluation seal ID mismatch")
    blockers = set(seal.get("execution_blockers", []))
    expected_blockers = {
        f"{fixture_id}:missing_genuine_sanitized_capture"
        for fixture_id in EXPECTED_REAL_IDS
    }
    assert_true(blockers == expected_blockers, "evaluation execution blockers mismatch")
    passed("candidate runtime, frozen expectations, and prepared inputs match the evaluation seal")


def validate_no_results() -> None:
    results = ROOT / "fixtures/device-corpus/evaluation/results"
    assert_true(not results.exists(), "evaluation results exist before genuine real fixtures are captured")
    forbidden = list((ROOT / "fixtures/device-corpus/evaluation").rglob("*result*.json"))
    assert_true(not forbidden, "evaluation result-like files exist before first authorized replay")
    passed("no evaluation replay results exist and execution remains blocked")


def validate_integration() -> None:
    shell = (ROOT / "tools/validate_v2_1_stage1_2_all.sh").read_text(encoding="utf-8")
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    docs = (ROOT / "docs/v2.1-evaluation-corpus-preparation.md").read_text(encoding="utf-8")
    assert_true("validate_v2_1_evaluation_preparation.py" in shell, "complete gate omits evaluation preparation validator")
    assert_true("validate_v2_1_evaluation_preparation.py" in ci, "CI syntax list omits evaluation preparation validator")
    assert_true("nine synthetic" in docs.lower() and "three sanitized-real" in docs.lower(), "evaluation preparation documentation lacks fixture counts")
    assert_true("must not" in docs.lower() and "tune" in docs.lower(), "documentation lacks no-tuning boundary")
    passed("evaluation preparation seal is wired into CI, the complete gate, and documentation")


def main() -> int:
    manifest, planned = validate_manifest()
    input_hashes = validate_prepared_inputs(planned)
    validate_seal(manifest, input_hashes)
    validate_no_results()
    validate_integration()
    passed("NetSniper v2.1 sealed evaluation corpus preparation validator complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
