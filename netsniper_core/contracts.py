from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CAPABILITY_SCHEMA_VERSION = "netsniper-capability-manifest-v1"
HOST_CLASSIFICATION_SCHEMA_VERSION = "netsniper-host-classification-v2"
CLASSIFIER_VERSION = "netsniper-classifier-v2"
TAXONOMY_VERSION = "netsniper-device-taxonomy-v2"
EVIDENCE_PROFILE_VERSION = "netsniper-evidence-profiles-v2"
OUTER_BUNDLE_SCHEMA_VERSION = "netsniper-run-v3"
LEGACY_BUNDLE_SCHEMA_VERSION = "netsniper-run-v2"

FAMILIES = {
    "network_infrastructure",
    "compute_host",
    "client_endpoint",
    "printer",
    "surveillance_device",
    "storage_appliance",
    "voice_device",
    "power_device",
    "iot_embedded",
    "unknown",
}

ROLES = {
    "gateway",
    "wireless_access_point",
    "managed_switch",
    "security_gateway",
    "domain_controller",
    "dns_server",
    "web_server",
    "web_application_host",
    "database_server",
    "container_host",
    "container_orchestrator",
    "hypervisor",
    "file_server",
    "nas_service",
    "print_service",
    "camera",
    "network_video_recorder",
    "voip_endpoint",
    "pbx",
    "ups_monitor",
    "mail_server",
    "development_admin_interface",
}

PLATFORMS = {
    "windows",
    "linux",
    "macos",
    "ios",
    "android",
    "network_os",
    "embedded",
    "unknown",
}

DECISIONS = {"classified", "possible", "review", "unknown"}

UNCERTAINTY_REASONS = {
    "no_classification_evidence",
    "insufficient_evidence_diversity",
    "port_only_evidence",
    "vendor_only_evidence",
    "hostname_only_evidence",
    "collector_unavailable",
    "collector_failed",
    "partial_scan",
    "strong_contradiction",
    "candidate_scores_too_close",
    "family_not_inferable_from_role",
    "identity_instability",
    "unsupported_signature",
    "legacy_projection_only",
}


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"missing JSON file: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {path}: {exc}") from exc


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def confidence_band(confidence: int) -> str:
    confidence = max(0, min(100, int(confidence)))
    if confidence >= 90:
        return "high"
    if confidence >= 70:
        return "strong"
    if confidence >= 40:
        return "possible"
    if confidence >= 1:
        return "weak"
    return "none"


def decision_for(
    confidence: int,
    *,
    minimum_possible: int = 40,
    minimum_classified: int = 70,
) -> str:
    confidence = max(0, min(100, int(confidence)))
    if confidence >= int(minimum_classified):
        return "classified"
    if confidence >= int(minimum_possible):
        return "possible"
    if confidence >= 1:
        return "review"
    return "unknown"
