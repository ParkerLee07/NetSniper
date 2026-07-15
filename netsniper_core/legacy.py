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


def _review_context(
    family: dict[str, Any],
    roles: list[dict[str, Any]],
    platform: dict[str, Any],
) -> tuple[bool, bool]:
    axis_results = [family, platform, *roles]
    review = any(item.get("decision") == "review" for item in axis_results)
    strong_contradiction = any(
        item.get("contradictions")
        or "strong_contradiction" in item.get("uncertainty_reasons", [])
        for item in axis_results
    )
    return review, strong_contradiction


def _leading_review_label(
    family: dict[str, Any],
    roles: list[dict[str, Any]],
) -> tuple[str, int]:
    family_label = str(family.get("label", "unknown"))
    family_confidence = int(family.get("confidence", 0))

    if family_label != "unknown":
        return FAMILY_LABELS.get(family_label, "Unknown"), family_confidence

    role_by_label = {
        role.get("label"): role
        for role in roles
        if role.get("decision") in {"classified", "possible", "review"}
    }
    chosen = next(
        (
            (legacy_label, role_by_label[canonical])
            for canonical, legacy_label in ROLE_PRIORITY
            if canonical in role_by_label
        ),
        None,
    )
    if chosen:
        label, role = chosen
        return label, int(role.get("confidence", 0))

    return "Unknown / Ambiguous", family_confidence


def project_legacy(result: dict[str, Any]) -> dict[str, Any]:
    family = result["device_family"]
    roles = result.get("roles", [])
    platform = result.get("platform", {})

    review, strong_contradiction = _review_context(
        family,
        roles,
        platform,
    )

    if review:
        confidence = max(
            [
                int(family.get("confidence", 0)),
                int(platform.get("confidence", 0)),
                *[
                    int(role.get("confidence", 0))
                    for role in roles
                ],
            ]
        )

        if strong_contradiction:
            primary_type = "Ambiguous Device"
            decision = "contradiction_review"
        elif str(family.get("label", "unknown")) == "unknown":
            primary_type = "Unknown / Ambiguous"
            decision = "review"
        else:
            primary_type, leading_confidence = _leading_review_label(
                family,
                roles,
            )
            confidence = max(confidence, leading_confidence)
            decision = "review"
    else:
        role_by_label = {
            role.get("label"): role
            for role in roles
            if role.get("decision") == "classified"
        }
        chosen = next(
            (
                (legacy_label, role_by_label[canonical])
                for canonical, legacy_label in ROLE_PRIORITY
                if canonical in role_by_label
            ),
            None,
        )
        if chosen:
            primary_type, chosen_result = chosen
            confidence = int(chosen_result.get("confidence", 0))
            decision = str(chosen_result.get("decision", "unknown"))
        else:
            family_label = str(family.get("label", "unknown"))
            primary_type = FAMILY_LABELS.get(family_label, "Unknown")
            confidence = int(family.get("confidence", 0))
            decision = str(family.get("decision", "unknown"))
            if family_label == "compute_host":
                if platform.get("label") == "windows":
                    primary_type = "Windows Server"
                elif platform.get("label") == "linux":
                    primary_type = "Linux Server"
            elif family_label == "client_endpoint":
                if platform.get("label") == "windows":
                    primary_type = "Windows Workstation"
                elif platform.get("label") == "linux":
                    primary_type = "Linux Workstation"

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
