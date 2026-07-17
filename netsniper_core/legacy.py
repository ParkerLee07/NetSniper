from __future__ import annotations

from typing import Any

FAMILY_LABELS = {
    "network_infrastructure": "Router / Gateway",
    "compute_host": "Linux Server",
    "client_endpoint": "Client Device",
    "printer": "Network Printer / MFP",
    "surveillance_device": "IP Camera / NVR",
    "storage_appliance": "NAS / Storage Appliance",
    "voice_device": "VoIP Phone / PBX",
    "power_device": "UPS / Power Device",
    "iot_embedded": "IoT / Embedded Device",
    "unknown": "Unknown",
}

ROLE_PRIORITY = [
    ("domain_controller", "Active Directory / Domain Controller"),
    ("container_orchestrator", "Container Infrastructure"),
    ("container_host", "Container Infrastructure"),
    ("database_server", "Database Server"),
    ("network_video_recorder", "IP Camera / NVR"),
    ("camera", "IP Camera / NVR"),
    ("print_service", "Network Printer / MFP"),
    ("nas_service", "NAS / Storage Appliance"),
    ("file_server", "NAS / File Server"),
    ("security_gateway", "Security Appliance"),
    ("managed_switch", "Managed Switch / Network Infrastructure"),
    ("wireless_access_point", "Wireless Access Point"),
    ("gateway", "Router / Gateway"),
    ("hypervisor", "Hypervisor / Virtualization Host"),
    ("pbx", "VoIP Phone / PBX"),
    ("voip_endpoint", "VoIP Phone / PBX"),
    ("ups_monitor", "UPS / Power Device"),
    ("mail_server", "Mail Server"),
    ("development_admin_interface", "Development / Admin Interface"),
    ("web_server", "Web Server / Web Application Host"),
    ("web_application_host", "Web Server / Web Application Host"),
]


def _legacy_band(confidence: int) -> str:
    if confidence >= 90:
        return "high"
    if confidence >= 70:
        return "strong"
    if confidence >= 40:
        return "possible"
    if confidence >= 1:
        return "weak"
    return "unknown"


def _strong_contradiction_present(
    family: dict[str, Any],
    roles: list[dict[str, Any]],
    platform: dict[str, Any],
) -> bool:
    axis_results = [family, platform, *roles]
    return any(
        item.get("contradictions")
        or "strong_contradiction" in item.get("uncertainty_reasons", [])
        for item in axis_results
    )


def _role_choice(
    roles: list[dict[str, Any]],
    decisions: set[str],
) -> tuple[str, dict[str, Any]] | None:
    role_by_label = {
        role.get("label"): role
        for role in roles
        if role.get("decision") in decisions
    }
    return next(
        (
            (legacy_label, role_by_label[canonical])
            for canonical, legacy_label in ROLE_PRIORITY
            if canonical in role_by_label
        ),
        None,
    )


def _family_primary_type(
    family: dict[str, Any],
    platform: dict[str, Any],
) -> str:
    family_label = str(family.get("label", "unknown"))
    primary_type = FAMILY_LABELS.get(family_label, "Unknown")
    if family_label == "compute_host":
        if platform.get("label") == "windows":
            return "Windows Server"
        if platform.get("label") == "linux":
            return "Linux Server"
    elif family_label == "client_endpoint":
        if platform.get("label") == "windows":
            return "Windows Workstation"
        if platform.get("label") == "linux":
            return "Linux Workstation"
        if platform.get("label") in {"ios", "android"}:
            return "Unknown"
    return primary_type


def project_legacy(result: dict[str, Any]) -> dict[str, Any]:
    family = result["device_family"]
    roles = result.get("roles", [])
    platform = result.get("platform", {})

    strong_contradiction = _strong_contradiction_present(
        family,
        roles,
        platform,
    )

    if strong_contradiction:
        primary_type = "Ambiguous Device"
        decision = "contradiction_review"
        confidence = max(
            [
                int(family.get("confidence", 0)),
                int(platform.get("confidence", 0)),
                *[int(role.get("confidence", 0)) for role in roles],
            ]
        )
    else:
        chosen = _role_choice(roles, {"classified"})
        if chosen:
            primary_type, chosen_result = chosen
            confidence = int(chosen_result.get("confidence", 0))
            decision = "classified"
        elif family.get("decision") == "classified":
            primary_type = _family_primary_type(family, platform)
            confidence = int(family.get("confidence", 0))
            decision = "classified"
        else:
            chosen = _role_choice(roles, {"possible"})
            if chosen:
                primary_type, chosen_result = chosen
                confidence = int(chosen_result.get("confidence", 0))
                decision = "possible"
            elif family.get("decision") == "possible":
                primary_type = _family_primary_type(family, platform)
                confidence = int(family.get("confidence", 0))
                decision = "possible"
            else:
                chosen = _role_choice(roles, {"review"})
                if str(family.get("label", "unknown")) == "unknown" and (
                    chosen or family.get("decision") == "review"
                ):
                    primary_type = "Unknown / Ambiguous"
                    confidence = max(
                        int(family.get("confidence", 0)),
                        int(chosen[1].get("confidence", 0)) if chosen else 0,
                    )
                    decision = "review"
                elif chosen:
                    primary_type, chosen_result = chosen
                    confidence = int(chosen_result.get("confidence", 0))
                    decision = "review"
                elif family.get("decision") == "review":
                    primary_type = _family_primary_type(family, platform)
                    confidence = int(family.get("confidence", 0))
                    decision = "review"
                elif platform.get("decision") == "review":
                    primary_type = "Unknown / Ambiguous"
                    confidence = int(platform.get("confidence", 0))
                    decision = "review"
                else:
                    primary_type = "Unknown"
                    confidence = 0
                    decision = "unknown"

        if decision == "review" and str(family.get("label", "unknown")) == "unknown":
            if not _role_choice(roles, {"review"}):
                primary_type = "Unknown / Ambiguous"

    candidates: list[dict[str, Any]] = []
    for role in sorted(
        roles,
        key=lambda item: int(item.get("confidence", 0)),
        reverse=True,
    ):
        label = next(
            (
                legacy
                for canonical, legacy in ROLE_PRIORITY
                if canonical == role.get("label")
            ),
            None,
        )
        if label and label != primary_type:
            candidates.append(
                {
                    "device_type": label,
                    "confidence": int(role.get("confidence", 0)),
                }
            )
    if family.get("label") != "unknown":
        label = FAMILY_LABELS.get(
            str(family.get("label")),
            "Unknown",
        )
        if label != primary_type:
            candidates.append(
                {
                    "device_type": label,
                    "confidence": int(family.get("confidence", 0)),
                }
            )

    contradictions = list(family.get("contradictions", []))
    contradictions.extend(platform.get("contradictions", []))
    for role in roles:
        contradictions.extend(role.get("contradictions", []))

    reasons = list(family.get("uncertainty_reasons", []))
    reasons.extend(platform.get("uncertainty_reasons", []))
    for role in roles:
        reasons.extend(role.get("uncertainty_reasons", []))

    return {
        "primary_type": primary_type,
        "device_type": primary_type,
        "device_type_confidence": confidence,
        "confidence": confidence,
        "confidence_label": _legacy_band(confidence),
        "decision": (
            decision
            if decision
            in {
                "classified",
                "possible",
                "unknown",
                "review",
                "contradiction_review",
            }
            else "unknown"
        ),
        "secondary_candidates": candidates[:5],
        "contradictions": contradictions,
        "calibration_reason": (
            "; ".join(dict.fromkeys(reasons))
            or "Derived from the authoritative v2.1 multi-axis classification."
        ),
    }


def compatibility_classification(result: dict[str, Any]) -> dict[str, Any]:
    legacy = result["legacy_projection"]
    return {
        "schema_version": "netsniper-classification-v1",
        "source": "netsniper-v2.1",
        "type": legacy["primary_type"],
        "primary_type": legacy["primary_type"],
        "confidence": legacy["confidence"],
        "confidence_label": legacy["confidence_label"],
        "confidence_band": legacy["confidence_label"],
        "calibrated_decision": result["device_family"]["decision"],
        "decision": legacy["decision"],
        "method": "authoritative_multi_axis_v2_1",
        "siem_action": "contradiction_review" if legacy["decision"] == "contradiction_review" else "display_only",
        "calibration_reason": legacy["calibration_reason"],
        "validation_state": "conflicted" if legacy["contradictions"] else "supported",
        "contradiction_count": len(legacy["contradictions"]),
        "evidence": result.get("evidence", []),
        "validators": [],
        "validator_summary": {
            "total": 0,
            "confirmed": 0,
            "inconclusive": 0,
            "refuted": 0,
            "not_applicable": 0,
            "error": 0,
            "names": [],
        },
        "contradictions": legacy["contradictions"],
        "candidates": legacy["secondary_candidates"],
        "secondary_candidates": legacy["secondary_candidates"],
    }

# NETSNIPER_DELTAAEGIS_ENRICHMENT_V1
# Additive wrapper keeps historical projection logic unchanged.
from functools import wraps as _deltaaegis_wraps
from .deltaaegis_enrichment import enrich_legacy_projection as _enrich_deltaaegis_projection

_original_compatibility_classification = compatibility_classification

@_deltaaegis_wraps(_original_compatibility_classification)
def compatibility_classification(result):
    legacy = _original_compatibility_classification(result)
    return _enrich_deltaaegis_projection(legacy, result)
