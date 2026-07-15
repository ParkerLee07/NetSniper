from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .contracts import (
    CLASSIFIER_VERSION,
    EVIDENCE_PROFILE_VERSION,
    HOST_CLASSIFICATION_SCHEMA_VERSION,
    TAXONOMY_VERSION,
    confidence_band,
    decision_for,
)
from .evidence import build_evidence, match_rule, source_group
from .legacy import project_legacy
from .normalization import normalize_host_record

RELIABILITY_WEIGHT = {"low": 1, "medium": 2, "high": 3}


def _collector_for(source: str) -> str:
    if source in {"port", "service", "product", "http_title"}:
        return "tcp_services"
    if source == "os":
        return "os_detection"
    if source == "vendor":
        return "passive_neighbors"
    return "discovery"


def _confidence_cap(matches: list[dict[str, Any]], raw: int) -> tuple[int, list[str]]:
    confidence = max(0, min(100, raw))
    reasons: list[str] = []
    if not matches:
        return 0, ["no_classification_evidence"]

    groups = {item["source_group"] for item in matches}
    sources = {item["source"] for item in matches}
    reliabilities = [item["reliability"] for item in matches]
    high_count = reliabilities.count("high")
    medium_count = reliabilities.count("medium")

    if sources == {"port"}:
        confidence = min(confidence, 39)
        reasons.append("port_only_evidence")
    elif sources == {"vendor"}:
        confidence = min(confidence, 39)
        reasons.append("vendor_only_evidence")
    elif sources == {"hostname"}:
        confidence = min(confidence, 39)
        reasons.append("hostname_only_evidence")

    if len(groups) == 1:
        if high_count:
            unique = any(bool(item.get("unique_identifying")) for item in matches)
            confidence = min(confidence, 100 if unique else 69)
        elif medium_count:
            confidence = min(confidence, 49)
        else:
            confidence = min(confidence, 39)
        reasons.append("insufficient_evidence_diversity")

    if confidence >= 70 and len(groups) < 2 and not any(bool(item.get("unique_identifying")) for item in matches):
        confidence = 69
        if "insufficient_evidence_diversity" not in reasons:
            reasons.append("insufficient_evidence_diversity")

    if confidence >= 90:
        corroborated = high_count >= 2 or (high_count >= 1 and len(groups) >= 3)
        if not corroborated:
            confidence = 89

    return confidence, reasons


def _score_profile(
    profile: dict[str, Any],
    observed: dict[str, list[str]],
    generated_at: str,
) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    raw = 0
    axis = str(profile["axis"])
    label = str(profile["label"])

    for rule in profile.get("positive_evidence", []):
        matched = match_rule(rule, observed)
        if matched is None:
            continue
        points = int(rule.get("points", 0))
        raw += points
        match = {
            "rule_id": str(rule.get("id", "rule")),
            "source": str(rule.get("source", "other")),
            "source_group": source_group(rule),
            "reliability": str(rule.get("reliability", "low")),
            "points": points,
            "unique_identifying": bool(rule.get("unique_identifying", False)),
            "matched_value": matched,
        }
        matches.append(match)
        evidence.append(
            build_evidence(
                axis,
                label,
                rule,
                matched,
                _collector_for(match["source"]),
                generated_at,
            )
        )

    confidence, uncertainty = _confidence_cap(matches, raw)
    return {
        "axis": axis,
        "label": label,
        "raw_confidence": min(100, raw),
        "confidence": confidence,
        "decision": decision_for(confidence),
        "matches": matches,
        "evidence": evidence,
        "uncertainty_reasons": uncertainty,
        "contradictions": [],
        "contradicts": list(profile.get("contradicts", [])),
        "explanation": str(profile.get("description", f"Evidence score for {label}.")),
    }


def _apply_pairwise_contradictions(candidates: list[dict[str, Any]]) -> None:
    by_label = {item["label"]: item for item in candidates}
    for candidate in candidates:
        conflicts = []
        for label in candidate.get("contradicts", []):
            other = by_label.get(label)
            if other and int(other.get("raw_confidence", 0)) >= 70:
                conflicts.append(other)
        if not conflicts:
            continue
        ids = [item["evidence_id"] for item in candidate["evidence"]]
        for other in conflicts:
            ids.extend(item["evidence_id"] for item in other["evidence"])
        candidate["contradictions"].append(
            {
                "contradiction_id": f"{candidate['label']}-conflict",
                "severity": "strong",
                "reason": "Strong evidence supports a conflicting classification candidate.",
                "evidence_ids": list(dict.fromkeys(ids)),
                "penalty": 50,
            }
        )
        candidate["confidence"] = min(69, max(0, int(candidate["confidence"]) - 50))
        candidate["decision"] = "review"
        candidate["uncertainty_reasons"] = list(
            dict.fromkeys(candidate["uncertainty_reasons"] + ["strong_contradiction"])
        )


def _candidate_view(candidate: dict[str, Any]) -> dict[str, Any]:
    return {
        "label": candidate["label"],
        "confidence": int(candidate["confidence"]),
        "decision": candidate["decision"],
    }


def _axis_result(
    candidates: list[dict[str, Any]],
    unknown_label: str,
    *,
    force_review_on_close: bool = True,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    active = [item for item in candidates if int(item["confidence"]) > 0]
    active.sort(
        key=lambda item: (
            int(item["confidence"]),
            int(item["raw_confidence"]),
            sum(RELIABILITY_WEIGHT.get(match["reliability"], 0) for match in item["matches"]),
            item["label"],
        ),
        reverse=True,
    )
    if not active:
        return (
            {
                "label": unknown_label,
                "confidence": 0,
                "confidence_band": "none",
                "decision": "unknown",
                "evidence_ids": [],
                "contradictions": [],
                "secondary_candidates": [],
                "uncertainty_reasons": ["no_classification_evidence"],
                "explanation": "No defensible evidence supports this axis.",
            },
            [],
        )

    winner = active[0]
    reasons = list(winner["uncertainty_reasons"])
    decision = winner["decision"]
    if force_review_on_close and len(active) > 1:
        second = active[1]
        if int(second["confidence"]) >= 40 and abs(int(winner["confidence"]) - int(second["confidence"])) <= 9:
            decision = "review"
            reasons.append("candidate_scores_too_close")
    if winner["contradictions"]:
        decision = "review"
        reasons.append("strong_contradiction")

    result = {
        "label": winner["label"],
        "confidence": int(winner["confidence"]),
        "confidence_band": confidence_band(int(winner["confidence"])),
        "decision": decision,
        "evidence_ids": [item["evidence_id"] for item in winner["evidence"]],
        "contradictions": winner["contradictions"],
        "secondary_candidates": [_candidate_view(item) for item in active[1:6]],
        "uncertainty_reasons": list(dict.fromkeys(reasons)),
        "explanation": winner["explanation"],
    }
    return result, active


def _role_results(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    active = [item for item in candidates if int(item["confidence"]) > 0]
    active.sort(key=lambda item: (int(item["confidence"]), item["label"]), reverse=True)
    output: list[dict[str, Any]] = []
    for candidate in active:
        decision = candidate["decision"]
        reasons = list(candidate["uncertainty_reasons"])
        if candidate["contradictions"]:
            decision = "review"
            reasons.append("strong_contradiction")
        other = [item for item in active if item is not candidate]
        output.append(
            {
                "label": candidate["label"],
                "confidence": int(candidate["confidence"]),
                "confidence_band": confidence_band(int(candidate["confidence"])),
                "decision": decision,
                "evidence_ids": [item["evidence_id"] for item in candidate["evidence"]],
                "contradictions": candidate["contradictions"],
                "secondary_candidates": [_candidate_view(item) for item in other[:5]],
                "uncertainty_reasons": list(dict.fromkeys(reasons)),
                "explanation": candidate["explanation"],
            }
        )
    return output


def _identity_result(normalized: dict[str, Any], generated_at: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    identity = normalized.get("identity", {})
    observed_keys: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    confidence = 0
    reasons: list[str] = []

    ip = identity.get("ip")
    mac = identity.get("mac")
    hostname = identity.get("hostname")
    local_mac = bool(identity.get("local_mac"))

    if ip:
        observed_keys.append({"kind": "ip", "value": str(ip), "stable": False})
        confidence += 20
    if mac:
        stable = not local_mac
        observed_keys.append({"kind": "local_mac" if local_mac else "mac", "value": str(mac), "stable": stable})
        confidence += 55 if stable else 20
        evidence.append(
            {
                "evidence_id": "identity-mac",
                "affected_axes": ["identity"],
                "source_type": "neighbor_table",
                "collector_id": "passive_neighbors",
                "reliability": "high" if stable else "low",
                "effect": "positive" if stable else "context",
                "observed_at": generated_at,
                "summary": "A stable MAC address was observed." if stable else "A locally administered or unstable MAC address was observed.",
                "normalized_value": {"mac": str(mac), "stable": stable},
                "raw_reference": "neighbors.txt",
            }
        )
        if not stable:
            reasons.append("identity_instability")
    if hostname:
        observed_keys.append({"kind": "hostname", "value": str(hostname), "stable": False})
        confidence += 20
        evidence.append(
            {
                "evidence_id": "identity-hostname",
                "affected_axes": ["identity"],
                "source_type": "hostname_pattern",
                "collector_id": "discovery",
                "reliability": "medium",
                "effect": "context",
                "observed_at": generated_at,
                "summary": "A hostname was observed.",
                "normalized_value": {"hostname": str(hostname)},
                "raw_reference": "discovery.xml",
            }
        )

    confidence = min(100, confidence)
    if mac and not local_mac and hostname:
        decision = "stable"
    elif mac and not local_mac:
        decision = "stable"
    elif observed_keys:
        decision = "provisional"
    else:
        decision = "unknown"
        reasons.append("identity_instability")

    return (
        {
            "decision": decision,
            "confidence": confidence,
            "observed_keys": observed_keys,
            "evidence_ids": [item["evidence_id"] for item in evidence],
            "uncertainty_reasons": list(dict.fromkeys(reasons)),
        },
        evidence,
    )


def _observation_quality(normalized: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    supplied = normalized.get("observation_quality", {})
    requested = list(supplied.get("requested_collectors", ["discovery", "tcp_services"]))
    completed = list(supplied.get("completed_collectors", requested))
    failed = list(supplied.get("failed_collectors", []))
    unavailable = list(supplied.get("unavailable_collectors", []))
    completeness = str(supplied.get("scan_completeness", "complete"))
    inventory_complete = bool(supplied.get("inventory_complete", True))
    reasons = list(supplied.get("reasons", []))
    missing: list[dict[str, Any]] = []

    for collector_id in failed:
        missing.append(
            {
                "collector_id": collector_id,
                "status": "failed",
                "reason_code": "execution_error",
                "affected_axes": ["device_family", "role", "platform", "observation"],
                "detail": "The requested collector failed.",
            }
        )
    for collector_id in unavailable:
        missing.append(
            {
                "collector_id": collector_id,
                "status": "unavailable",
                "reason_code": "dependency_unavailable",
                "affected_axes": ["device_family", "role", "platform", "observation"],
                "detail": "The requested collector was unavailable.",
            }
        )

    if failed or unavailable:
        completeness = "partial" if completeness != "failed" else "failed"
    score = int(round(100 * len(set(completed)) / max(1, len(set(requested)))))
    negative_allowed = completeness == "complete" and inventory_complete and not failed and not unavailable

    return (
        {
            "scan_completeness": completeness,
            "coverage_score": max(0, min(100, score)),
            "requested_collectors": list(dict.fromkeys(requested)),
            "completed_collectors": list(dict.fromkeys(completed)),
            "failed_collectors": list(dict.fromkeys(failed)),
            "unavailable_collectors": list(dict.fromkeys(unavailable)),
            "inventory_complete": inventory_complete,
            "negative_evidence_allowed": negative_allowed,
            "reasons": list(dict.fromkeys(reasons)),
        },
        missing,
    )


def classify_host(
    record: dict[str, Any],
    profiles_data: dict[str, Any],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    generated_at = generated_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    normalized = normalize_host_record(record)
    observed = normalized["observed"]
    profiles = profiles_data.get("axis_profiles", [])
    if not isinstance(profiles, list):
        raise ValueError("evidence profiles are missing axis_profiles")

    candidates = [_score_profile(profile, observed, generated_at) for profile in profiles]
    for axis in {"device_family", "role", "platform"}:
        _apply_pairwise_contradictions([item for item in candidates if item["axis"] == axis])

    family_candidates = [item for item in candidates if item["axis"] == "device_family"]
    role_candidates = [item for item in candidates if item["axis"] == "role"]
    platform_candidates = [item for item in candidates if item["axis"] == "platform"]

    family, _ = _axis_result(family_candidates, "unknown")
    roles = _role_results(role_candidates)
    platform, _ = _axis_result(platform_candidates, "unknown")

    if family["label"] == "unknown" and any(role["decision"] == "classified" for role in roles):
        family["uncertainty_reasons"] = list(
            dict.fromkeys(family["uncertainty_reasons"] + ["family_not_inferable_from_role"])
        )

    observation_quality, missing_evidence = _observation_quality(normalized)
    if observation_quality["scan_completeness"] != "complete":
        for axis_result in [family, platform, *roles]:
            axis_result["uncertainty_reasons"] = list(
                dict.fromkeys(axis_result["uncertainty_reasons"] + ["partial_scan"])
            )

    identity, identity_evidence = _identity_result(normalized, generated_at)
    evidence: list[dict[str, Any]] = identity_evidence[:]
    for candidate in candidates:
        evidence.extend(candidate["evidence"])
    unique_evidence: dict[str, dict[str, Any]] = {}
    for item in evidence:
        existing = unique_evidence.get(item["evidence_id"])
        if existing:
            existing["affected_axes"] = list(dict.fromkeys(existing["affected_axes"] + item["affected_axes"]))
        else:
            unique_evidence[item["evidence_id"]] = item

    result: dict[str, Any] = {
        "schema_version": HOST_CLASSIFICATION_SCHEMA_VERSION,
        "classifier_version": CLASSIFIER_VERSION,
        "taxonomy_version": TAXONOMY_VERSION,
        "evidence_profile_version": EVIDENCE_PROFILE_VERSION,
        "host_id": normalized["host_id"],
        "generated_at": generated_at,
        "identity": identity,
        "device_family": family,
        "roles": roles,
        "platform": platform,
        "observation_quality": observation_quality,
        "evidence": list(unique_evidence.values()),
        "missing_evidence": missing_evidence,
        "legacy_projection": {},
    }
    result["legacy_projection"] = project_legacy(result)
    return result
