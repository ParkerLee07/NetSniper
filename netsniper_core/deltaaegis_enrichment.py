#!/usr/bin/env python3
"""Additive DeltaAegis-facing context for NetSniper v2.1."""

from __future__ import annotations

import hashlib
import json
from typing import Any

SCHEMA_VERSION = "netsniper-deltaaegis-evidence-context-v1"


def _strings(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return list(dict.fromkeys(
        str(value).strip() for value in values if str(value).strip()
    ))


def _axis_view(axis: Any) -> dict[str, Any]:
    if not isinstance(axis, dict):
        axis = {}
    contradictions = axis.get("contradictions", [])
    secondary = axis.get("secondary_candidates", [])
    return {
        "label": str(axis.get("label", "unknown")),
        "confidence": int(axis.get("confidence", 0) or 0),
        "confidence_band": str(axis.get("confidence_band", "none")),
        "decision": str(axis.get("decision", "unknown")),
        "evidence_ids": _strings(axis.get("evidence_ids", [])),
        "contradictions": contradictions if isinstance(contradictions, list) else [],
        "secondary_candidates": secondary if isinstance(secondary, list) else [],
        "uncertainty_reasons": _strings(axis.get("uncertainty_reasons", [])),
        "explanation": str(axis.get("explanation", "")).strip(),
    }


def _identity_view(result: dict[str, Any]) -> dict[str, Any]:
    identity = result.get("identity", {})
    if not isinstance(identity, dict):
        identity = {}
    observed = []
    for item in identity.get("observed_keys", []):
        if isinstance(item, dict):
            observed.append({
                "kind": str(item.get("kind", "unknown")),
                "stable": bool(item.get("stable", False)),
            })
    return {
        "decision": str(identity.get("decision", "unknown")),
        "confidence": int(identity.get("confidence", 0) or 0),
        "observed_key_kinds": observed,
        "evidence_ids": _strings(identity.get("evidence_ids", [])),
        "uncertainty_reasons": _strings(identity.get("uncertainty_reasons", [])),
    }


def _quality_view(result: dict[str, Any]) -> dict[str, Any]:
    quality = result.get("observation_quality", {})
    if not isinstance(quality, dict):
        quality = {}
    return {
        "scan_completeness": str(quality.get("scan_completeness", "unknown")),
        "coverage_score": int(quality.get("coverage_score", 0) or 0),
        "inventory_complete": bool(quality.get("inventory_complete", False)),
        "negative_evidence_allowed": bool(quality.get("negative_evidence_allowed", False)),
        "requested_collectors": _strings(quality.get("requested_collectors", [])),
        "completed_collectors": _strings(quality.get("completed_collectors", [])),
        "failed_collectors": _strings(quality.get("failed_collectors", [])),
        "unavailable_collectors": _strings(quality.get("unavailable_collectors", [])),
        "reasons": _strings(quality.get("reasons", [])),
    }


def _role_views(result: dict[str, Any]) -> list[dict[str, Any]]:
    roles = result.get("roles", [])
    if not isinstance(roles, list):
        return []
    output = [_axis_view(item) for item in roles if isinstance(item, dict)]
    output.sort(key=lambda item: (-item["confidence"], item["label"]))
    return output


def _network_roles(result: dict[str, Any]) -> list[str]:
    observed = result.get("observed", {})
    if not isinstance(observed, dict):
        observed = {}
    return _strings(result.get("network_roles", observed.get("network_roles", [])))


def _operator_disposition(
    axes: list[tuple[str, dict[str, Any]]],
    quality: dict[str, Any],
) -> str:
    decisions = {axis["decision"] for _, axis in axes}
    contradictions = sum(len(axis["contradictions"]) for _, axis in axes)
    if contradictions or "review" in decisions:
        return "review"
    if not quality["inventory_complete"] or quality["failed_collectors"]:
        return "observe"
    if "classified" in decisions or "possible" in decisions:
        return "accepted_observation"
    return "unknown"


def _fingerprint(context: dict[str, Any]) -> str:
    stable = {
        "identity": context["identity"],
        "axes": context["axes"],
        "network_roles": context["network_roles"],
        "observation_quality": context["observation_quality"],
        "operator_disposition": context["operator_disposition"],
    }
    encoded = json.dumps(
        stable, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def build_deltaaegis_context(result: dict[str, Any]) -> dict[str, Any]:
    axes = [
        ("device_family", _axis_view(result.get("device_family", {}))),
        ("platform", _axis_view(result.get("platform", {}))),
    ]
    axes.extend((f"role:{item['label']}", item) for item in _role_views(result))
    quality = _quality_view(result)

    evidence_ids: list[str] = []
    uncertainty: list[str] = []
    contradictions: list[Any] = []
    explanations: list[dict[str, str]] = []

    for axis_name, axis in axes:
        evidence_ids.extend(axis["evidence_ids"])
        uncertainty.extend(axis["uncertainty_reasons"])
        contradictions.extend(axis["contradictions"])
        if axis["explanation"]:
            explanations.append({"axis": axis_name, "text": axis["explanation"]})

    context = {
        "schema_version": SCHEMA_VERSION,
        "source_schema_version": str(result.get("schema_version", "")),
        "classifier_version": str(result.get("classifier_version", "")),
        "taxonomy_version": str(result.get("taxonomy_version", "")),
        "evidence_profile_version": str(result.get("evidence_profile_version", "")),
        "identity": _identity_view(result),
        "axes": {name: axis for name, axis in axes},
        "network_roles": _network_roles(result),
        "observation_quality": quality,
        "operator_disposition": _operator_disposition(axes, quality),
        "evidence_ids": list(dict.fromkeys(evidence_ids)),
        "uncertainty_reasons": list(dict.fromkeys(uncertainty)),
        "contradictions": contradictions,
        "explanations": explanations,
    }
    context["semantic_fingerprint"] = _fingerprint(context)
    return context


def enrich_legacy_projection(
    legacy: dict[str, Any],
    result: dict[str, Any],
) -> dict[str, Any]:
    output = dict(legacy)
    context = build_deltaaegis_context(result)
    output["deltaaegis_context"] = context
    output["evidence_ids"] = context["evidence_ids"]
    output["uncertainty_reasons"] = context["uncertainty_reasons"]
    output["network_roles"] = context["network_roles"]
    output["operator_disposition"] = context["operator_disposition"]
    output["semantic_fingerprint"] = context["semantic_fingerprint"]
    output.setdefault(
        "explanation",
        " ".join(item["text"] for item in context["explanations"]).strip(),
    )
    return output
