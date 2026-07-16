#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE_COMMIT = "f8b006038bc889266960875c10e765ec0e93ab04"
PREVIOUS_CANDIDATE_COMMIT = "a760fc7e125a223181cf44c63a151c3eebcbe460"
CANDIDATE_BASE_COMMIT = "809b23432348b6d0dc861948532cb4d5de21da78"
FREEZE_COMMIT = "a4c027c9ab5f2fd1e7484b2ae9f8a76b10988c03"
EXPECTED_REAL_IDS = {
    "sanitized-real-home-router-01",
    "sanitized-real-printer-01",
    "sanitized-real-client-endpoint-01",
}


def fail(message: str) -> None:
    raise SystemExit(f"[FAIL] {message}")


def passed(message: str) -> None:
    print(f"[PASS] {message}")


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def git_bytes(commit: str, relative: str) -> bytes:
    completed = subprocess.run(
        ["git", "show", f"{commit}:{relative}"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        fail(f"cannot read {relative} from candidate commit {commit}: {completed.stderr.decode(errors='replace').strip()}")
    return completed.stdout


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


def main() -> int:
    seal_path = ROOT / "fixtures/device-corpus/evaluation/seal.json"
    seal = json.loads(seal_path.read_text(encoding="utf-8"))

    assert_true(seal.get("state") == "synthetic_prepared_sanitized_real_candidate_sealed", "candidate seal state mismatch")
    assert_true(seal.get("classifier_candidate_commit") == CANDIDATE_COMMIT, "candidate commit mismatch")
    assert_true(seal.get("candidate_resealed_at_commit") == CANDIDATE_COMMIT, "candidate reseal provenance mismatch")
    assert_true(seal.get("previous_classifier_candidate_commit") == PREVIOUS_CANDIDATE_COMMIT, "previous candidate mismatch")
    assert_true(seal.get("candidate_base_commit") == CANDIDATE_BASE_COMMIT, "candidate base mismatch")
    assert_true(seal.get("candidate_reseal_required") is False, "candidate still requires reseal")
    assert_true(seal.get("evaluation_holdout_frozen_at") == FREEZE_COMMIT, "evaluation freeze commit mismatch")
    assert_true(seal.get("first_evaluation_replay_executed") is False, "evaluation replay was marked executed")
    assert_true(seal.get("statistical_claims_permitted") is False, "statistical claims were enabled")

    exists = subprocess.run(
        ["git", "cat-file", "-e", f"{CANDIDATE_COMMIT}^{{commit}}"],
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    assert_true(exists.returncode == 0, "candidate commit is absent from repository history")

    runtime = seal.get("runtime_fingerprints", {})
    assert_true(isinstance(runtime, dict) and runtime, "runtime fingerprint map is empty")
    for relative, expected in sorted(runtime.items()):
        path = ROOT / relative
        assert_true(path.is_file(), f"runtime file missing: {relative}")
        assert_true(sha256_file(path) == expected, f"current runtime hash mismatch: {relative}")
        assert_true(sha256_bytes(git_bytes(CANDIDATE_COMMIT, relative)) == expected, f"candidate commit runtime hash mismatch: {relative}")
    runtime_index = sha256_bytes(canonical_bytes(runtime))
    assert_true(seal.get("candidate_runtime_index_sha256") == runtime_index, "runtime index mismatch")
    passed("current runtime and candidate-commit runtime match every sealed fingerprint")

    prepared = seal.get("prepared_input_files", {})
    assert_true(isinstance(prepared, dict) and prepared, "prepared input fingerprint map is empty")
    for relative, expected in sorted(prepared.items()):
        path = ROOT / relative
        assert_true(path.is_file(), f"prepared input missing: {relative}")
        assert_true(sha256_file(path) == expected, f"current prepared input hash mismatch: {relative}")
        assert_true(sha256_bytes(git_bytes(CANDIDATE_COMMIT, relative)) == expected, f"candidate commit prepared input hash mismatch: {relative}")
    input_index = sha256_bytes(canonical_bytes(prepared))
    assert_true(seal.get("prepared_inputs_index_sha256") == input_index, "prepared input index mismatch")
    passed("prepared evaluation inputs are unchanged from the candidate commit")

    manifest = json.loads((ROOT / "fixtures/device-corpus/manifest.json").read_text(encoding="utf-8"))
    candidate_manifest = json.loads(git_bytes(CANDIDATE_COMMIT, "fixtures/device-corpus/manifest.json"))
    contract_hash = sha256_bytes(canonical_bytes(evaluation_contract(manifest["fixtures"])))
    candidate_contract_hash = sha256_bytes(canonical_bytes(evaluation_contract(candidate_manifest["fixtures"])))
    assert_true(contract_hash == candidate_contract_hash, "evaluation contract differs from candidate commit")
    assert_true(seal.get("evaluation_contract_sha256") == contract_hash, "sealed evaluation contract hash mismatch")
    passed("frozen evaluation ground truth and expectations match the candidate commit")

    expected_seal_id = sha256_bytes(canonical_bytes({
        "candidate_commit": CANDIDATE_COMMIT,
        "previous_candidate": PREVIOUS_CANDIDATE_COMMIT,
        "base_commit": CANDIDATE_BASE_COMMIT,
        "freeze": FREEZE_COMMIT,
        "contract": contract_hash,
        "inputs": input_index,
        "runtime": runtime_index,
        "state": "candidate_sealed",
    }))
    assert_true(seal.get("seal_id") == expected_seal_id, "candidate seal ID mismatch")

    blockers = set(seal.get("execution_blockers", []))
    expected_blockers = {f"{fixture_id}:missing_genuine_sanitized_capture" for fixture_id in EXPECTED_REAL_IDS}
    assert_true(blockers == expected_blockers, "execution blockers do not match missing genuine captures")
    assert_true("classifier_candidate_reseal_required" not in blockers, "stale reseal blocker remains")
    assert_true(not (ROOT / "fixtures/device-corpus/evaluation/results").exists(), "evaluation results exist before authorized replay")
    assert_true(not list((ROOT / "fixtures/device-corpus/evaluation").rglob("*result*.json")), "result-like evaluation files exist")
    passed("candidate reseal is complete while evaluation replay remains blocked")

    shell = (ROOT / "tools/validate_v2_1_stage1_2_all.sh").read_text(encoding="utf-8")
    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    docs = (ROOT / "docs/v2.1-evaluation-candidate-reseal.md").read_text(encoding="utf-8")
    assert_true("validate_v2_1_evaluation_candidate_reseal.py" in shell, "complete gate omits candidate reseal validator")
    assert_true("validate_v2_1_evaluation_candidate_reseal.py" in ci, "CI omits candidate reseal validator")
    assert_true(CANDIDATE_COMMIT in docs, "candidate reseal documentation omits candidate commit")
    assert_true("does not execute" in docs.lower(), "candidate reseal documentation lacks no-replay boundary")
    passed("candidate reseal validator is wired into CI, the complete gate, and documentation")

    passed("NetSniper v2.1 evaluation candidate reseal validator complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
