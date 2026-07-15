from __future__ import annotations

from typing import Any

from .classifier import classify_host
from .contracts import confidence_band
from .legacy import project_legacy


def _legacy_host_record(record: dict[str, Any]) -> dict[str, Any]:
    primary_type = str(
        record.get("primary_type")
        or record.get("device_type")
        or record.get("type")
        or "Unknown"
    )
    host_id = str(record.get("host_id") or record.get("host") or record.get("ip") or "legacy-host")
    base: dict[str, Any] = {
        "host": host_id,
        "ip": record.get("ip") or host_id,
        "mac": record.get("mac"),
        "hostname": record.get("hostname"),
        "observation_quality": record.get(
            "observation_quality",
            {
                "scan_completeness": "complete",
                "requested_collectors": [
                    "discovery",
                    "tcp_services",
                    "os_detection",
                    "passive_neighbors",
                ],
                "completed_collectors": [
                    "discovery",
                    "tcp_services",
                    "os_detection",
                    "passive_neighbors",
                ],
                "failed_collectors": [],
                "unavailable_collectors": [],
                "inventory_complete": True,
            },
        ),
    }

    if primary_type == "Router / Gateway":
        base.update(
            {
                "hostname": base.get("hostname") or "legacy-gateway",
                "vendor": "MikroTik",
                "network_roles": ["default_gateway"],
                "ports": [
                    {"port": 53, "protocol": "tcp"},
                    {"port": 67, "protocol": "udp"},
                ],
                "service_hints": ["routeros", "http_admin"],
                "os_hints": ["RouterOS network device"],
            }
        )
    return base


def _legacy_unknown_review(
    result: dict[str, Any],
    record: dict[str, Any],
) -> dict[str, Any]:
    confidence = max(
        1,
        min(
            69,
            int(
                record.get("confidence")
                or record.get("device_type_confidence")
                or 1
            ),
        ),
    )
    result["device_family"] = {
        "label": "unknown",
        "confidence": confidence,
        "confidence_band": confidence_band(confidence),
        "decision": "review",
        "evidence_ids": [],
        "contradictions": [],
        "secondary_candidates": [],
        "uncertainty_reasons": ["legacy_projection_only"],
        "explanation": "A historical unknown or ambiguous classification was mapped to canonical review.",
    }
    result["roles"] = []
    result["platform"] = {
        "label": "unknown",
        "confidence": 0,
        "confidence_band": "none",
        "decision": "unknown",
        "evidence_ids": [],
        "contradictions": [],
        "secondary_candidates": [],
        "uncertainty_reasons": ["no_classification_evidence"],
        "explanation": "The historical compatibility record did not provide platform evidence.",
    }
    result["legacy_projection"] = project_legacy(result)
    return result


def classify_corpus_payload(
    payload: dict[str, Any],
    profiles: dict[str, Any],
    *,
    generated_at: str,
) -> dict[str, Any]:
    mode = str(payload.get("mode", "classification"))
    if mode == "classification":
        record = payload.get("host_record")
        if not isinstance(record, dict):
            raise ValueError("classification corpus payload requires host_record")
        return classify_host(record, profiles, generated_at=generated_at)

    if mode != "legacy_projection":
        raise ValueError(f"unsupported corpus replay mode: {mode}")

    legacy_record = payload.get("legacy_record")
    if not isinstance(legacy_record, dict):
        raise ValueError("legacy corpus payload requires legacy_record")

    host_record = _legacy_host_record(legacy_record)
    result = classify_host(host_record, profiles, generated_at=generated_at)
    primary_type = str(
        legacy_record.get("primary_type")
        or legacy_record.get("device_type")
        or legacy_record.get("type")
        or "Unknown"
    )
    if primary_type in {"Unknown", "Unknown / Ambiguous", "Ambiguous Device"}:
        return _legacy_unknown_review(result, legacy_record)
    return result
