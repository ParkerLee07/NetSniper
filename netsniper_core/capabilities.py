from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .contracts import (
    CAPABILITY_SCHEMA_VERSION,
    CLASSIFIER_VERSION,
    EVIDENCE_PROFILE_VERSION,
    HOST_CLASSIFICATION_SCHEMA_VERSION,
    TAXONOMY_VERSION,
)


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _tool_version(name: str) -> str:
    executable = shutil.which(name)
    if not executable:
        return "unavailable"
    commands = {
        "nmap": [executable, "--version"],
        "jq": [executable, "--version"],
        "ip": [executable, "-Version"],
        "python3": [executable, "--version"],
    }
    try:
        completed = subprocess.run(
            commands.get(name, [executable, "--version"]),
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    text = (completed.stdout or completed.stderr).strip().splitlines()
    return text[0][:200] if text else "unknown"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _artifact_kind(path: Path) -> str:
    if path.suffix == ".xml":
        return "nmap_xml"
    if path.suffix == ".gnmap":
        return "nmap_gnmap"
    if path.suffix == ".nmap":
        return "nmap_text"
    if path.suffix == ".json":
        return "json"
    if path.suffix == ".md":
        return "markdown"
    if path.name == "neighbors.txt":
        return "neighbor_table"
    return "text"


def _artifact_id(path: Path) -> str:
    return "".join(character if character.isalnum() else "_" for character in path.name.lower()).strip("_")


def build_capability_manifest(
    bundle_dir: Path,
    *,
    run_id: str,
    scanner_version: str,
    source_commit: str,
    target: str,
    requested_profile: str,
    effective_profile: str,
    started_at: str,
    completed_at: str,
    configuration_fingerprint: str,
    privilege_context: str,
    discovered_count: int,
    emitted_count: int,
) -> dict[str, Any]:
    requested_collectors = ["discovery", "tcp_services", "passive_neighbors"]
    if effective_profile == "accurate":
        requested_collectors.extend(["os_detection", "udp_lite"])

    collector_specs = {
        "discovery": ("discovery.xml", "nmap"),
        "tcp_services": ("services.xml", "nmap"),
        "passive_neighbors": ("neighbors.txt", "ip"),
        "os_detection": ("os_detection.xml", "nmap"),
        "udp_lite": ("udp_lite.xml", "nmap"),
    }

    collectors: list[dict[str, Any]] = []
    partial_reasons: list[str] = []
    for collector_id, (filename, tool_name) in collector_specs.items():
        requested = collector_id in requested_collectors
        path = bundle_dir / filename
        if requested and path.is_file() and (path.stat().st_size > 0 or filename == "neighbors.txt"):
            status = "completed"
            reason_code = None
            message = ""
        elif requested:
            status = "unavailable"
            reason_code = "no_results"
            message = f"Requested collector did not produce {filename}."
            partial_reasons.append(reason_code)
        else:
            status = "skipped"
            reason_code = "disabled_by_profile"
            message = f"Collector is not enabled by the {effective_profile} profile."
        record: dict[str, Any] = {
            "collector_id": collector_id,
            "requested": requested,
            "status": status,
            "started_at": started_at if status == "completed" else None,
            "completed_at": completed_at if status == "completed" else None,
            "tool_name": tool_name if shutil.which(tool_name) else None,
            "tool_version": _tool_version(tool_name) if shutil.which(tool_name) else None,
            "artifact_refs": [_artifact_id(path)] if status == "completed" else [],
            "message": message,
        }
        if reason_code:
            record["reason_code"] = reason_code
        collectors.append(record)

    artifacts: list[dict[str, Any]] = []
    excluded = {"manifest.json", "capability_manifest.json"}
    for path in sorted(bundle_dir.iterdir()):
        if not path.is_file() or path.name in excluded or path.name.endswith(".tmp"):
            continue
        artifacts.append(
            {
                "artifact_id": _artifact_id(path),
                "kind": _artifact_kind(path),
                "path": path.name,
                "sha256": _sha256(path),
                "size_bytes": path.stat().st_size,
                "required": path.name in {
                    "discovery.xml",
                    "services.xml",
                    "analysis.json",
                    "analysis.enriched.json",
                    "hosts.txt",
                    "host_classifications.json",
                    "classification_quality.json",
                    "bundle_quality.json",
                },
                "status": "present",
            }
        )

    omitted = max(0, discovered_count - emitted_count)
    execution_status = "partial" if partial_reasons else "complete"
    if discovered_count < 0 or emitted_count < 0:
        execution_status = "failed"

    source_commit = source_commit.strip().lower()
    if not source_commit or any(character not in "0123456789abcdef" for character in source_commit):
        source_commit = "0000000"
    if not configuration_fingerprint or len(configuration_fingerprint) != 64:
        configuration_fingerprint = hashlib.sha256(
            f"{requested_profile}|{effective_profile}|{target}".encode("utf-8")
        ).hexdigest()

    return {
        "schema_version": CAPABILITY_SCHEMA_VERSION,
        "generated_at": _iso_now(),
        "run_id": run_id,
        "sensor": {
            "netsniper_version": scanner_version,
            "source_commit": source_commit,
            "bundle_schema_version": "netsniper-run-v3",
            "classifier_version": CLASSIFIER_VERSION,
            "taxonomy_version": TAXONOMY_VERSION,
            "evidence_profile_version": EVIDENCE_PROFILE_VERSION,
            "host_classification_schema_version": HOST_CLASSIFICATION_SCHEMA_VERSION,
        },
        "target": {
            "requested_scope": target,
            "normalized_scope": target,
            "private_scope_enforced": True,
        },
        "execution": {
            "scan_profile": effective_profile,
            "status": execution_status,
            "started_at": started_at,
            "completed_at": completed_at,
            "privilege_context": privilege_context,
            "discovery_methods": ["arp", "icmp", "tcp_syn"] if privilege_context == "privileged" else ["icmp", "tcp_connect"],
            "partial_reasons": sorted(set(partial_reasons)),
            "configuration_fingerprint": configuration_fingerprint,
            "tools": [
                {"name": "python3", "version": platform.python_version()},
                {"name": "nmap", "version": _tool_version("nmap")},
                {"name": "jq", "version": _tool_version("jq")},
            ],
        },
        "collectors": collectors,
        "inventory": {
            "discovered_host_count": discovered_count,
            "emitted_host_count": emitted_count,
            "omitted_host_count": omitted,
        },
        "artifacts": artifacts,
        "integrity": {
            "bundle_finalized": False,
            "manifest_complete": False,
            "host_inventory_preserved": omitted == 0,
            "hashes_verified": True,
        },
    }
