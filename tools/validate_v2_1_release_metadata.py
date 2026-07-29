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
    ci = text(".github/workflows/ci.yml")
    release_gate = text("tools/validate_v2_1_release_gate.sh")
    stage_validator = text("tools/validate_v2_1_stage1_2.py")
    capabilities = text("netsniper_core/capabilities.py")
    hotfix_validator = text("tools/validate_v2_1_bundle_integrity_hotfix.py")
    hotfix_wrapper = text("tools/validate_v2_1_bundle_integrity_hotfix_all.sh")
    finalizer = text("tools/finalize_v2_1_bundle_integrity.py")
    v20_all = text("tools/validate_v2_0_all.sh")
    manifest = text("tools/validate_v2_0_manifest_v3.sh")
    status = text("tools/validate_v2_0_status_contract.sh")

    require('SCANNER_VERSION="v2.1.1"' in shell, "runtime version is not v2.1.1")
    require("# NETSNIPER ENGINE v2.1.1" in shell, "engine header is not v2.1.1")
    require("finalize_v2_1_bundle_integrity.py" in shell, "runtime finalizer is not wired")
    require(
        'excluded = {"manifest.json", "capability_manifest.json"}' in capabilities,
        "bundle_quality.json remains excluded from the capability inventory",
    )

    require(
        "Current release: **NetSniper v2.1.1 — Bundle Integrity Hotfix**" in readme,
        "README current release is not v2.1.1",
    )
    require("## v2.1.1 Highlights" in readme, "README v2.1.1 highlights are missing")
    require("`v2.1.1` tag" in readme, "README does not name the v2.1.1 tag")
    require("## v2.1.1 - 2026-07-29" in changelog, "CHANGELOG v2.1.1 entry is missing")
    require("Final scanner version: `v2.1.1`" in checklist, "maintenance checklist version mismatch")
    require("creating the annotated `v2.1.1` tag" in checklist, "maintenance tag hold is missing")
    require(
        "NetSniper v2.1.1 maintenance release candidates" in gates_doc,
        "accuracy-gates document does not identify the maintenance release",
    )

    require('SCANNER_VERSION="v2.1.1"' in stage_validator, "stage validator version mismatch")
    require('"v2.1.1"' in hotfix_validator, "hotfix fixtures do not use v2.1.1")
    require("bundle_quality.json tampering is rejected" in hotfix_validator, "tamper regression is missing")
    require("archive_deltaaegis_bundle" in hotfix_validator, "actual archive-path regression is missing")
    require("validate_v2_1_bundle_integrity_hotfix.py" in hotfix_wrapper, "hotfix wrapper is incomplete")
    require("validate_outer_manifest_integrity" in finalizer, "final integrity verifier is missing")
    require("bundle_quality.json" in finalizer, "finalizer does not require bundle quality")

    require(ci.count("./tools/validate_v2_1_release_gate.sh") == 1, "CI must call the release gate once")
    require(ci.count("./tools/validate_v2_1_stage1_2_all.sh") == 1, "CI must call the general gate once")
    require("Run NetSniper v2.1.1 release gate" in ci, "CI release step is not v2.1.1")
    require(
        ci.count("hotfix/v2.1.1-bundle-quality-integrity") == 4,
        "CI hotfix routing is incomplete",
    )
    for path in (
        "tools/finalize_v2_1_bundle_integrity.py",
        "tools/validate_v2_1_bundle_integrity_hotfix.py",
        "tools/validate_v2_1_release_metadata.py",
    ):
        require(path in ci, f"CI syntax inventory omits {path}")

    require("git status --porcelain" in release_gate, "release gate does not enforce cleanliness")
    require(
        "hotfix/v2.1.1-bundle-quality-integrity|main" in release_gate,
        "release gate source boundary is incorrect",
    )
    require(
        release_gate.count("./tools/validate_v2_1_bundle_integrity_hotfix_all.sh") == 1,
        "release gate must call the hotfix gate once",
    )
    require(
        release_gate.count("./tools/validate_v2_1_stage1_2_all.sh") == 1,
        "release gate must call the complete compatibility gate once",
    )
    require(
        release_gate.count("tools/validate_v2_1_release_metadata.py") == 2,
        "release gate must syntax-check and execute metadata validation",
    )

    for name, source in (
        ("v2.0 complete gate", v20_all),
        ("v2.0 manifest contract", manifest),
        ("v2.0 status contract", status),
    ):
        require("v2.1.1" in source, f"{name} does not accept v2.1.1")

    require(not re.search(r"Current release:.*v2\.1\.0", readme), "README still identifies v2.1.0 as current")

    print("[PASS] finalized v2.1.1 runtime and bundle-integrity wiring")
    print("[PASS] README, CHANGELOG, maintenance checklist, and release boundaries")
    print("[PASS] CI and clean-tree release-gate routing")
    print("[PASS] v2.1 and v2.0 compatibility version boundaries")
    print("[PASS] NetSniper v2.1.1 release metadata validator complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
