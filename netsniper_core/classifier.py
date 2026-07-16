from __future__ import annotations

from datetime import datetime, timezone
import re
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


def _policy_int(policy: dict[str, Any], key: str, default: int) -> int:
    try:
        return int(policy.get(key, default))
    except (TypeError, ValueError):
        return default


def _confidence_cap(
    matches: list[dict[str, Any]],
    raw: int,
    policy: dict[str, Any],
) -> tuple[int, list[str]]:
    maximum = _policy_int(policy, "max_confidence", 100)
    possible_minimum = _policy_int(policy, "minimum_possible_score", 40)
    classified_minimum = _policy_int(policy, "minimum_classified_score", 70)
    high_minimum = _policy_int(policy, "minimum_high_score", 90)
    port_only_cap = _policy_int(policy, "port_only_cap", possible_minimum - 1)
    vendor_only_cap = _policy_int(policy, "vendor_only_cap", possible_minimum - 1)
    hostname_only_cap = _policy_int(policy, "hostname_only_cap", possible_minimum - 1)
    single_medium_cap = _policy_int(policy, "single_medium_source_cap", 49)
    single_high_cap = _policy_int(policy, "single_high_source_cap", classified_minimum - 1)

    confidence = max(0, min(maximum, raw))
    reasons: list[str] = []
    if not matches:
        return 0, ["no_classification_evidence"]

    groups = {item.get("independence_group", item["source_group"]) for item in matches}
    sources = {item["source"] for item in matches}
    reliabilities = [item["reliability"] for item in matches]
    high_count = reliabilities.count("high")
    medium_count = reliabilities.count("medium")

    if sources == {"port"}:
        confidence = min(confidence, port_only_cap)
        reasons.append("port_only_evidence")
    elif sources == {"vendor"}:
        confidence = min(confidence, vendor_only_cap)
        reasons.append("vendor_only_evidence")
    elif sources == {"hostname"}:
        confidence = min(confidence, hostname_only_cap)
        reasons.append("hostname_only_evidence")

    if len(groups) == 1:
        if high_count:
            unique = any(bool(item.get("unique_identifying")) for item in matches)
            confidence = min(confidence, maximum if unique else single_high_cap)
        elif medium_count:
            confidence = min(confidence, single_medium_cap)
        else:
            confidence = min(confidence, possible_minimum - 1)
        reasons.append("insufficient_evidence_diversity")

    if (
        confidence >= classified_minimum
        and len(groups) < 2
        and not any(bool(item.get("unique_identifying")) for item in matches)
    ):
        confidence = classified_minimum - 1
        if "insufficient_evidence_diversity" not in reasons:
            reasons.append("insufficient_evidence_diversity")

    if confidence >= high_minimum:
        corroborated = high_count >= 2 or (high_count >= 1 and len(groups) >= 3)
        if not corroborated:
            confidence = high_minimum - 1

    return max(0, min(maximum, confidence)), reasons



def _management_marker_matches(
    guard: dict[str, Any],
    observed: dict[str, list[str]],
) -> list[str]:
    patterns = guard.get("management_patterns", {})
    if not isinstance(patterns, dict):
        return []
    fields = guard.get("management_observed_fields", [])
    if not isinstance(fields, list):
        return []
    matches: list[str] = []
    for field in fields:
        pattern = str(patterns.get(str(field), "")).strip()
        if not pattern:
            continue
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error:
            continue
        for value in observed.get(str(field), []):
            text = str(value).strip()
            if text and regex.search(text):
                matches.append(text)
    return list(dict.fromkeys(matches))


def _apply_profile_guard(
    profile: dict[str, Any],
    observed: dict[str, list[str]],
    matches: list[dict[str, Any]],
    confidence: int,
    uncertainty: list[str],
    policy: dict[str, Any],
) -> tuple[int, list[str], list[str]]:
    guard = profile.get("classification_guard", {})
    if not isinstance(guard, dict) or guard.get("kind") != "embedded_admin_web_server_boundary":
        return confidence, uncertainty, []

    reasons = list(uncertainty)
    classified_minimum = _policy_int(policy, "minimum_classified_score", 70)
    independence_groups = {
        str(item.get("independence_group") or item.get("source_group") or "other")
        for item in matches
    }
    required_groups = {
        str(item)
        for item in guard.get("minimum_classified_independence_groups", [])
        if str(item)
    }
    if confidence >= classified_minimum and not required_groups.issubset(independence_groups):
        confidence = classified_minimum - 1
        reasons.append("insufficient_evidence_diversity")

    management_matches = _management_marker_matches(guard, observed)
    if management_matches:
        cap_key = str(guard.get("management_cap_policy_key", "embedded_admin_web_server_cap"))
        cap = _policy_int(policy, cap_key, 39)
        confidence = min(confidence, cap)
        reasons.append(str(guard.get("management_uncertainty_reason", "embedded_admin_interface")))

    return confidence, list(dict.fromkeys(reasons)), management_matches


def _score_profile(
    profile: dict[str, Any],
    observed: dict[str, list[str]],
    generated_at: str,
    policy: dict[str, Any],
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
            "independence_group": str(rule.get("independence_group") or source_group(rule)),
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

    confidence, uncertainty = _confidence_cap(matches, raw, policy)
    confidence, uncertainty, management_matches = _apply_profile_guard(
        profile,
        observed,
        matches,
        confidence,
        uncertainty,
        policy,
    )
    possible_minimum = _policy_int(policy, "minimum_possible_score", 40)
    classified_minimum = _policy_int(policy, "minimum_classified_score", 70)
    maximum = _policy_int(policy, "max_confidence", 100)
    return {
        "axis": axis,
        "label": label,
        "raw_confidence": min(maximum, raw),
        "confidence": confidence,
        "decision": decision_for(
            confidence,
            minimum_possible=possible_minimum,
            minimum_classified=classified_minimum,
        ),
        "matches": matches,
        "management_matches": management_matches,
        "evidence": evidence,
        "uncertainty_reasons": uncertainty,
        "contradictions": [],
        "contradicts": list(profile.get("contradicts", [])),
        "explanation": str(profile.get("description", f"Evidence score for {label}.")),
    }



def _apply_embedded_admin_candidate_boundary(
    candidates: list[dict[str, Any]],
    profiles: list[dict[str, Any]],
    policy: dict[str, Any],
) -> None:
    web_candidate = next(
        (
            item
            for item in candidates
            if item.get("axis") == "role" and item.get("label") == "web_server"
        ),
        None,
    )
    web_profile = next(
        (
            item
            for item in profiles
            if item.get("axis") == "role" and item.get("label") == "web_server"
        ),
        None,
    )
    if not web_candidate or not web_profile:
        return
    guard = web_profile.get("classification_guard", {})
    if not isinstance(guard, dict) or guard.get("kind") != "embedded_admin_web_server_boundary":
        return

    threshold = _policy_int(
        guard,
        "minimum_appliance_context_confidence",
        40,
    )
    appliance_families = {
        str(item) for item in guard.get("appliance_family_labels", [])
    }
    appliance_roles = {
        str(item) for item in guard.get("appliance_role_labels", [])
    }
    context = [
        item
        for item in candidates
        if item is not web_candidate
        and int(item.get("confidence", 0)) >= threshold
        and (
            (item.get("axis") == "device_family" and item.get("label") in appliance_families)
            or (item.get("axis") == "role" and item.get("label") in appliance_roles)
        )
    ]
    if not context:
        return

    cap_key = str(guard.get("management_cap_policy_key", "embedded_admin_web_server_cap"))
    cap = _policy_int(policy, cap_key, 39)
    web_candidate["confidence"] = min(int(web_candidate.get("confidence", 0)), cap)
    web_candidate["decision"] = decision_for(
        int(web_candidate["confidence"]),
        minimum_possible=_policy_int(policy, "minimum_possible_score", 40),
        minimum_classified=_policy_int(policy, "minimum_classified_score", 70),
    )
    reason = str(guard.get("management_uncertainty_reason", "embedded_admin_interface"))
    web_candidate["uncertainty_reasons"] = list(
        dict.fromkeys(web_candidate.get("uncertainty_reasons", []) + [reason])
    )
    web_candidate["management_context"] = [
        {
            "axis": str(item.get("axis")),
            "label": str(item.get("label")),
            "confidence": int(item.get("confidence", 0)),
        }
        for item in sorted(
            context,
            key=lambda value: (
                str(value.get("axis")),
                str(value.get("label")),
            ),
        )
    ]


def _apply_pairwise_contradictions(
    candidates: list[dict[str, Any]],
    policy: dict[str, Any],
) -> None:
    by_label = {item["label"]: item for item in candidates}
    classified_minimum = _policy_int(policy, "minimum_classified_score", 70)
    penalty = _policy_int(policy, "strong_contradiction_penalty", 50)
    for candidate in candidates:
        conflicts = []
        for label in candidate.get("contradicts", []):
            other = by_label.get(label)
            if other and int(other.get("raw_confidence", 0)) >= classified_minimum:
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
                "penalty": penalty,
            }
        )
        candidate["confidence"] = min(
            classified_minimum - 1,
            max(0, int(candidate["confidence"]) - penalty),
        )
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
    possible_minimum: int,
    close_candidate_delta: int,
    force_review_on_close: bool = True,
    suppress_hostname_only_below_possible: bool = False,
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

    winner_sources = {
        str(match.get("source", "other"))
        for match in winner.get("matches", [])
    }
    if (
        suppress_hostname_only_below_possible
        and int(winner["confidence"]) < possible_minimum
        and winner_sources == {"hostname"}
    ):
        return (
            {
                "label": unknown_label,
                "confidence": 0,
                "confidence_band": "none",
                "decision": "unknown",
                "evidence_ids": [],
                "contradictions": [],
                "secondary_candidates": [
                    _candidate_view(item)
                    for item in active[:5]
                ],
                "uncertainty_reasons": list(dict.fromkeys(reasons)),
                "explanation": (
                    "Only sub-threshold hostname evidence supports a platform "
                    "candidate; the canonical platform remains unknown."
                ),
            },
            active,
        )
    if force_review_on_close and len(active) > 1:
        second = active[1]
        if (
            int(second["confidence"]) >= possible_minimum
            and abs(int(winner["confidence"]) - int(second["confidence"])) <= close_candidate_delta
        ):
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
    policy = profiles_data.get("scoring_policy", {})
    if not isinstance(profiles, list):
        raise ValueError("evidence profiles are missing axis_profiles")
    if not isinstance(policy, dict):
        raise ValueError("evidence profiles are missing scoring_policy")

    possible_minimum = _policy_int(policy, "minimum_possible_score", 40)
    close_candidate_delta = _policy_int(policy, "close_candidate_delta", 9)

    candidates = [
        _score_profile(profile, observed, generated_at, policy)
        for profile in profiles
    ]
    _apply_embedded_admin_candidate_boundary(candidates, profiles, policy)
    for axis in {"device_family", "role", "platform"}:
        _apply_pairwise_contradictions(
            [item for item in candidates if item["axis"] == axis],
            policy,
        )

    family_candidates = [item for item in candidates if item["axis"] == "device_family"]
    role_candidates = [item for item in candidates if item["axis"] == "role"]
    platform_candidates = [item for item in candidates if item["axis"] == "platform"]

    family, _ = _axis_result(
        family_candidates,
        "unknown",
        possible_minimum=possible_minimum,
        close_candidate_delta=close_candidate_delta,
    )
    roles = _role_results(role_candidates)
    platform, _ = _axis_result(
        platform_candidates,
        "unknown",
        possible_minimum=possible_minimum,
        close_candidate_delta=close_candidate_delta,
        suppress_hostname_only_below_possible=True,
    )

    if family["label"] == "unknown" and any(
        role["decision"] in {"classified", "possible", "review"}
        for role in roles
    ):
        family["uncertainty_reasons"] = list(
            dict.fromkeys(family["uncertainty_reasons"] + ["family_not_inferable_from_role"])
        )

    observation_quality, missing_evidence = _observation_quality(normalized)
    quality_uncertainty: list[str] = []
    if observation_quality["scan_completeness"] != "complete":
        quality_uncertainty.append("partial_scan")
    if observation_quality["failed_collectors"]:
        quality_uncertainty.append("collector_failed")
    if observation_quality["unavailable_collectors"]:
        quality_uncertainty.append("collector_unavailable")
    if quality_uncertainty:
        for axis_result in [family, platform, *roles]:
            axis_result["uncertainty_reasons"] = list(
                dict.fromkeys(
                    axis_result["uncertainty_reasons"]
                    + quality_uncertainty
                )
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
