#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netsniper_core.capabilities import build_capability_manifest
from netsniper_core.contracts import load_json, write_json


class BundleIntegrityError(ValueError):
    """Raised when a finalized bundle is not fully integrity-bound."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BundleIntegrityError(f"{label} must be a JSON object")
    return value


def require_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BundleIntegrityError(f"{label} must be a non-empty string")
    return value.strip()


def require_count(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise BundleIntegrityError(f"{label} must be a non-negative integer")
    return value


def artifact_records_by_path(
    capability: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    artifacts = capability.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise BundleIntegrityError(
            "capability_manifest.artifacts must be a non-empty list"
        )

    by_path: dict[str, dict[str, Any]] = {}
    artifact_ids: set[str] = set()
    for index, record in enumerate(artifacts):
        if not isinstance(record, dict):
            raise BundleIntegrityError(
                f"artifact record {index} must be an object"
            )
        relative = require_text(
            record.get("path"),
            f"artifact record {index} path",
        )
        artifact_id = require_text(
            record.get("artifact_id"),
            f"artifact record {index} artifact_id",
        )
        if relative in by_path:
            raise BundleIntegrityError(f"duplicate artifact path: {relative}")
        if artifact_id in artifact_ids:
            raise BundleIntegrityError(f"duplicate artifact_id: {artifact_id}")
        by_path[relative] = record
        artifact_ids.add(artifact_id)
    return by_path


def validate_outer_manifest_integrity(
    bundle_dir: Path,
    manifest: dict[str, Any],
    capability: dict[str, Any],
) -> list[str]:
    files = require_mapping(manifest.get("files"), "manifest.files")
    by_path = artifact_records_by_path(capability)
    verified: list[str] = []

    for key, value in sorted(files.items()):
        if value is None:
            continue
        relative = require_text(value, f"manifest.files.{key}")
        if relative == "capability_manifest.json":
            continue

        artifact_path = bundle_dir / relative
        if not artifact_path.is_file():
            raise BundleIntegrityError(
                f"outer-manifest artifact is missing: {relative}"
            )

        record = by_path.get(relative)
        if record is None:
            raise BundleIntegrityError(
                f"outer-manifest artifact is not integrity-bound: {relative}"
            )

        expected_size = record.get("size_bytes")
        if isinstance(expected_size, bool) or not isinstance(expected_size, int):
            raise BundleIntegrityError(
                f"artifact has invalid size_bytes: {relative}"
            )
        actual_size = artifact_path.stat().st_size
        if expected_size != actual_size:
            raise BundleIntegrityError(
                f"artifact size mismatch for {relative}: "
                f"expected={expected_size} actual={actual_size}"
            )

        expected_hash = str(record.get("sha256") or "").strip().lower()
        if (
            len(expected_hash) != 64
            or any(
                character not in "0123456789abcdef"
                for character in expected_hash
            )
        ):
            raise BundleIntegrityError(
                f"artifact has invalid sha256: {relative}"
            )

        actual_hash = sha256_file(artifact_path)
        if expected_hash != actual_hash:
            raise BundleIntegrityError(
                f"artifact sha256 mismatch for {relative}: "
                f"expected={expected_hash} actual={actual_hash}"
            )
        verified.append(relative)

    quality_record = by_path.get("bundle_quality.json")
    if quality_record is None:
        raise BundleIntegrityError(
            "bundle_quality.json is absent from the capability artifact inventory"
        )
    if quality_record.get("required") is not True:
        raise BundleIntegrityError(
            "bundle_quality.json must be marked as a required artifact"
        )

    return verified


def finalize_bundle_integrity(bundle_dir: Path) -> dict[str, Any]:
    bundle_dir = bundle_dir.resolve()
    manifest_path = bundle_dir / "manifest.json"
    capability_path = bundle_dir / "capability_manifest.json"
    quality_path = bundle_dir / "bundle_quality.json"

    if not manifest_path.is_file():
        raise BundleIntegrityError("manifest.json is missing")
    if not capability_path.is_file():
        raise BundleIntegrityError("capability_manifest.json is missing")
    if not quality_path.is_file():
        raise BundleIntegrityError("bundle_quality.json is missing")

    manifest = require_mapping(load_json(manifest_path), "manifest")
    previous = require_mapping(
        load_json(capability_path),
        "capability manifest",
    )

    sensor = require_mapping(previous.get("sensor"), "capability sensor")
    target_record = require_mapping(
        previous.get("target"),
        "capability target",
    )
    execution = require_mapping(
        previous.get("execution"),
        "capability execution",
    )
    inventory = require_mapping(
        previous.get("inventory"),
        "capability inventory",
    )

    requested_profile = (
        manifest.get("requested_profile")
        or manifest.get("scan_profile_requested")
        or execution.get("scan_profile")
    )
    effective_profile = (
        manifest.get("effective_profile")
        or manifest.get("scan_profile_effective")
        or execution.get("scan_profile")
    )

    finalized = build_capability_manifest(
        bundle_dir,
        run_id=require_text(
            previous.get("run_id") or manifest.get("scan_id"),
            "run_id",
        ),
        scanner_version=require_text(
            sensor.get("netsniper_version") or manifest.get("scanner_version"),
            "scanner version",
        ),
        source_commit=require_text(
            sensor.get("source_commit"),
            "source commit",
        ),
        target=require_text(
            target_record.get("normalized_scope")
            or target_record.get("requested_scope")
            or manifest.get("network_scope")
            or manifest.get("target"),
            "target scope",
        ),
        requested_profile=require_text(
            requested_profile,
            "requested profile",
        ),
        effective_profile=require_text(
            effective_profile,
            "effective profile",
        ),
        started_at=require_text(
            execution.get("started_at"),
            "execution.started_at",
        ),
        completed_at=require_text(
            execution.get("completed_at"),
            "execution.completed_at",
        ),
        configuration_fingerprint=require_text(
            execution.get("configuration_fingerprint"),
            "execution.configuration_fingerprint",
        ),
        privilege_context=require_text(
            execution.get("privilege_context"),
            "execution.privilege_context",
        ),
        discovered_count=require_count(
            inventory.get("discovered_host_count"),
            "inventory.discovered_host_count",
        ),
        emitted_count=require_count(
            inventory.get("emitted_host_count"),
            "inventory.emitted_host_count",
        ),
    )
    finalized["integrity"]["bundle_finalized"] = True
    finalized["integrity"]["manifest_complete"] = True

    verified = validate_outer_manifest_integrity(
        bundle_dir,
        manifest,
        finalized,
    )
    write_json(capability_path, finalized)

    return {
        "schema_version": (
            "netsniper-v2.1-bundle-integrity-finalization-v1"
        ),
        "bundle_dir": str(bundle_dir),
        "verified_artifact_count": len(verified),
        "verified_artifacts": verified,
        "bundle_quality_integrity_bound": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Refresh the NetSniper v2.1 capability inventory after bundle "
            "quality and outer-manifest finalization."
        )
    )
    parser.add_argument("--bundle-dir", required=True)
    args = parser.parse_args()

    try:
        result = finalize_bundle_integrity(Path(args.bundle_dir))
    except (BundleIntegrityError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(
            f"bundle integrity finalization failed: {exc}",
            file=sys.stderr,
        )
        return 1

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
