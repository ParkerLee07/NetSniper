#!/usr/bin/env python3
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"[FAIL] {message}")


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def main() -> int:
    shell = text("netsniper.sh")
    readme = text("README.md")
    changelog = text("CHANGELOG.md")
    checklist = text("docs/V2_1_RELEASE_CHECKLIST.md")
    gates_doc = text("docs/v2.1-accuracy-and-calibration-gates.md")
    normalized_gates_doc = re.sub(r"\s+", " ", gates_doc)
    ci = text(".github/workflows/ci.yml")
    release_gate = text("tools/validate_v2_1_release_gate.sh")
    stage_validator = text("tools/validate_v2_1_stage1_2.py")
    v20_all = text("tools/validate_v2_0_all.sh")
    manifest = text("tools/validate_v2_0_manifest_v3.sh")
    status = text("tools/validate_v2_0_status_contract.sh")

    require('SCANNER_VERSION="v2.1.0"' in shell, "SCANNER_VERSION is not finalized as v2.1.0")
    require("v2.1.0-dev" not in shell, "runtime still contains v2.1.0-dev")
    require("# NETSNIPER ENGINE v2.1.0" in shell, "engine header is not finalized")

    expected_release = (
        "Current release: **NetSniper v2.1.0 — "
        "Evidence-Calibrated Device Intelligence**"
    )
    require(expected_release in readme, "README current release does not point to v2.1.0")
    require("## v2.1.0 Highlights" in readme, "README v2.1.0 highlights are missing")
    require("./tools/validate_v2_1_release_gate.sh" in readme, "README does not name the v2.1 release gate")
    require("After separate approval to stage and commit" in readme, "README does not place the clean-tree gate after commit approval")
    require("clean committed feature branch" in readme, "README does not describe the clean-tree release-gate requirement")
    require("Before committing, merging, tagging, or publishing" not in readme, "README retains the impossible pre-commit clean-tree sequence")
    require("## v2.1.0 - 2026-07-17" in changelog, "CHANGELOG v2.1.0 entry is missing")

    for marker in (
        "separate explicit approval",
        "Pre-commit review",
        "After separate approval to stage and commit",
        "staging and committing",
        "pushing the feature branch",
        "opening a pull request",
        "merging a pull request",
        "creating or moving the `v2.1.0` tag",
        "publishing the GitHub Release",
    ):
        require(marker in checklist, f"release checklist is missing {marker!r}")
    require("opening or merging a pull request" not in checklist, "release checklist combines separate pull-request approvals")

    require("validate_v2_1_release_gate.sh" in gates_doc, "accuracy-gates doc does not point to the release gate")
    for marker in (
        "not a measured real-world accuracy percentage",
        "does not justify a public percentage-accuracy, precision, recall, or calibration claim",
        "must not convert test pass rates into claims about population-level classification accuracy",
        "reviewed without unsupported statistical claims",
        "release-finalization commit requires prior operator approval",
        "Passing the gate does not authorize a push, merge, tag, or GitHub Release",
    ):
        require(
            marker in normalized_gates_doc,
            f"accuracy or release boundary is missing {marker!r}",
        )

    release_ci_step = "      - name: Run NetSniper v2.1.0 release gate\n        if: ${{ github.ref_name == 'main' || github.ref_name == 'feature/v2.1-evidence-calibration' || github.head_ref == 'main' || github.head_ref == 'feature/v2.1-evidence-calibration' }}\n        run: ./tools/validate_v2_1_release_gate.sh\n"
    general_ci_step = "      - name: Run NetSniper v2.1 behavioral and compatibility gate\n        if: ${{ github.ref_name != 'main' && github.ref_name != 'feature/v2.1-evidence-calibration' && github.head_ref != 'main' && github.head_ref != 'feature/v2.1-evidence-calibration' }}\n        run: ./tools/validate_v2_1_stage1_2_all.sh\n"
    require(ci.count("./tools/validate_v2_1_release_gate.sh") == 1, "CI must call the release gate exactly once")
    require(ci.count("./tools/validate_v2_1_stage1_2_all.sh") == 1, "CI must call the general behavioral gate exactly once")
    require(release_ci_step in ci, "CI release-gate step is not restricted to approved release sources")
    require(general_ci_step in ci, "CI general-gate step is not restricted to non-release sources")
    require(ci.count("if: ${{") == 2, "CI must contain exactly two routed validation conditions")
    require("python3 -m py_compile \
" in ci, "CI Python syntax command is not multiline")
    require("python3 -m py_compile             " not in ci, "CI Python syntax command is collapsed")
    require("tools/validate_v2_1_release_metadata.py" in ci, "CI Python syntax inventory omits release metadata validator")
    require("tools/validate_v2_1_empirical_calibration.py" in ci, "CI Python syntax inventory omits empirical calibration validator")
    require("tools/validate_v2_1_deltaaegis_enrichment.py" in ci, "CI Python syntax inventory omits DeltaAegis enrichment validator")

    require(release_gate.count("./tools/validate_v2_1_stage1_2_all.sh") == 1, "release gate must compose the complete behavioral gate exactly once")
    require(release_gate.count("tools/validate_v2_1_release_metadata.py") == 2, "release gate must syntax-check and execute the metadata validator once each")
    require("git status --porcelain" in release_gate, "release gate does not enforce repository cleanliness")
    require('source_ref="$(git branch --show-current)"' in release_gate, "release gate does not resolve the local source branch")
    require("GITHUB_HEAD_REF" in release_gate, "release gate does not accept GitHub pull-request source identity")
    require("GITHUB_REF_NAME" in release_gate, "release gate lacks a detached-checkout source fallback")
    require('case "$source_ref" in' in release_gate, "release gate does not validate the resolved source ref")

    require('SCANNER_VERSION="v2.1.0"' in stage_validator, "v2.1 contract validator still expects a development version")
    require("v2.1.0-dev" not in stage_validator, "v2.1 contract validator retains development-version expectations")

    for name, source in (
        ("v2.0 complete gate", v20_all),
        ("v2.0 manifest contract", manifest),
        ("v2.0 status contract", status),
    ):
        require("v2.1.0" in source, f"{name} does not accept finalized v2.1.0")

    require(not re.search(r"Current release:.*v2\.0\.0", readme), "README still identifies v2.0.0 as current")

    print("[PASS] finalized v2.1.0 runtime version")
    print("[PASS] README, CHANGELOG, checklist, and validation documentation")
    print("[PASS] readable CI with mutually exclusive release and general validation routing")
    print("[PASS] v2.1 contract and v2.0 compatibility version boundaries")
    print("[PASS] NetSniper v2.1.0 release metadata validator complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
