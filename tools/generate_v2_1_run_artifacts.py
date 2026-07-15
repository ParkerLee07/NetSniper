#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netsniper_core.capabilities import build_capability_manifest
from netsniper_core.contracts import load_json, write_json
from netsniper_core.pipeline import enrich_bundle_analysis, write_quality_reports


def count_hosts(path: Path) -> int:
    return len([line for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()])


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate mandatory NetSniper v2.1 bundle artifacts.")
    parser.add_argument("--bundle-dir", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--scanner-version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--requested-profile", required=True)
    parser.add_argument("--effective-profile", required=True)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--completed-at", required=True)
    parser.add_argument("--configuration-fingerprint", required=True)
    parser.add_argument("--privilege-context", choices=["privileged", "unprivileged", "unknown"], default="unknown")
    parser.add_argument("--profiles", default=str(ROOT / "classification/evidence_profiles.json"))
    args = parser.parse_args()

    bundle_dir = Path(args.bundle_dir).resolve()
    analysis_path = bundle_dir / "analysis.json"
    hosts_path = bundle_dir / "hosts.txt"
    if not analysis_path.is_file() or not hosts_path.is_file():
        raise SystemExit("analysis.json and hosts.txt are required")

    analysis = load_json(analysis_path)
    profiles = load_json(Path(args.profiles))
    if not isinstance(profiles, dict):
        raise SystemExit("profiles must be a JSON object")
    discovered = count_hosts(hosts_path)
    emitted = len(analysis) if isinstance(analysis, list) else 0

    preliminary = build_capability_manifest(
        bundle_dir,
        run_id=args.run_id,
        scanner_version=args.scanner_version,
        source_commit=args.source_commit,
        target=args.target,
        requested_profile=args.requested_profile,
        effective_profile=args.effective_profile,
        started_at=args.started_at,
        completed_at=args.completed_at,
        configuration_fingerprint=args.configuration_fingerprint,
        privilege_context=args.privilege_context,
        discovered_count=discovered,
        emitted_count=emitted,
    )

    enriched, classifications, summary = enrich_bundle_analysis(analysis, bundle_dir, profiles, preliminary)
    write_json(bundle_dir / "analysis.enriched.json", enriched)
    write_json(bundle_dir / "host_classifications.json", classifications)
    write_quality_reports(bundle_dir, summary, classifications)

    final_capability = build_capability_manifest(
        bundle_dir,
        run_id=args.run_id,
        scanner_version=args.scanner_version,
        source_commit=args.source_commit,
        target=args.target,
        requested_profile=args.requested_profile,
        effective_profile=args.effective_profile,
        started_at=args.started_at,
        completed_at=args.completed_at,
        configuration_fingerprint=args.configuration_fingerprint,
        privilege_context=args.privilege_context,
        discovered_count=discovered,
        emitted_count=len(classifications),
    )
    final_capability["integrity"]["bundle_finalized"] = True
    final_capability["integrity"]["manifest_complete"] = True
    write_json(bundle_dir / "capability_manifest.json", final_capability)

    if discovered != len(classifications):
        raise SystemExit(f"host inventory mismatch: discovered={discovered}, classified={len(classifications)}")
    if not final_capability["integrity"]["host_inventory_preserved"]:
        raise SystemExit("capability manifest does not preserve full inventory")

    print(
        json.dumps(
            {
                "host_count": len(classifications),
                "execution_status": final_capability["execution"]["status"],
                "capability_manifest": str(bundle_dir / "capability_manifest.json"),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
