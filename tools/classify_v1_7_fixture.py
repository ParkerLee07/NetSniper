#!/usr/bin/env python3
"""
NetSniper v1.7 fixture classifier.

This is an isolated test harness for the v1.7 device-intelligence rules.
It does not scan the network and does not modify NetSniper live analysis output.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


SOURCE_TO_OBSERVED_FIELD = {
    "port": "open_ports",
    "service": "service_hints",
    "vendor": "vendor_hints",
    "http_title": "http_titles",
    "hostname": "hostname_hints",
    "network_role": "network_roles",
}


def load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"Missing file: {path}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}")


def normalized_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return [str(value).strip() for value in values if str(value).strip()]


def match_rule(source: str, pattern: str, observed: dict[str, Any]) -> str | None:
    field = SOURCE_TO_OBSERVED_FIELD.get(source)
    if not field:
        return None

    candidates = normalized_list(observed.get(field, []))

    if source in {"port", "network_role"}:
        allowed = {part.strip().lower() for part in pattern.split("|") if part.strip()}
        for candidate in candidates:
            if candidate.lower() in allowed:
                return candidate
        return None

    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error:
        return None

    for candidate in candidates:
        if regex.search(candidate):
            return candidate

    return None


def confidence_band(confidence: int) -> str:
    if confidence >= 90:
        return "high"
    if confidence >= 70:
        return "strong"
    if confidence >= 40:
        return "possible"
    if confidence >= 1:
        return "weak"
    return "unknown"


def default_decision(confidence: int) -> str:
    if confidence >= 70:
        return "classified"
    if confidence >= 1:
        return "possible"
    return "unknown"


def score_profiles(profiles_data: dict[str, Any], observed: dict[str, Any]) -> list[dict[str, Any]]:
    scored: list[dict[str, Any]] = []

    for profile in profiles_data.get("profiles", []):
        evidence: list[dict[str, Any]] = []
        raw_score = 0

        for rule in profile.get("positive_evidence", []):
            source = str(rule.get("source", ""))
            pattern = str(rule.get("value", ""))
            matched_value = match_rule(source, pattern, observed)

            if matched_value is None:
                continue

            points = int(rule.get("points", 0))
            raw_score += points

            evidence.append(
                {
                    "candidate": profile.get("primary_type"),
                    "id": rule.get("id"),
                    "source": source,
                    "value": pattern,
                    "matched_value": matched_value,
                    "reliability": rule.get("reliability"),
                    "points": points,
                    "reason": rule.get("reason"),
                }
            )

        scored.append(
            {
                "primary_type": profile.get("primary_type"),
                "category": profile.get("category"),
                "default_siem_action": profile.get("default_siem_action", "display_only"),
                "raw_score": raw_score,
                "raw_confidence": min(100, raw_score),
                "evidence": evidence,
                "profile": profile,
            }
        )

    return scored


def raw_confidence_for(scored: list[dict[str, Any]], primary_type: str) -> int:
    for item in scored:
        if item.get("primary_type") == primary_type:
            return int(item.get("raw_confidence", 0))
    return 0


def derive_signals(scored: list[dict[str, Any]]) -> dict[str, bool]:
    ad = raw_confidence_for(scored, "Active Directory / Domain Controller") >= 70
    db = raw_confidence_for(scored, "Database Server") >= 70
    container = raw_confidence_for(scored, "Container Infrastructure") >= 70
    printer = raw_confidence_for(scored, "Network Printer / MFP") >= 70
    camera = raw_confidence_for(scored, "IP Camera / NVR") >= 70

    infrastructure_conflict = ad or db or container

    return {
        "active_directory_domain_controller": ad,
        "database_server_role": db,
        "container_infrastructure_role": container,
        "printer_specific_services_only": printer and not infrastructure_conflict,
        "camera_specific_services_only": camera and not infrastructure_conflict,
    }


def apply_contradictions(scored: list[dict[str, Any]], signals: dict[str, bool]) -> list[dict[str, Any]]:
    adjusted: list[dict[str, Any]] = []

    for item in scored:
        contradictions: list[dict[str, Any]] = []
        penalty_total = 0

        for rule in item.get("profile", {}).get("contradictions", []):
            contradiction_id = str(rule.get("id", ""))
            if not signals.get(contradiction_id, False):
                continue

            penalty = int(rule.get("penalty", 0))
            penalty_total += penalty
            contradictions.append(
                {
                    "id": contradiction_id,
                    "penalty": penalty,
                    "reason": rule.get("reason"),
                }
            )

        confidence = max(0, min(100, int(item.get("raw_confidence", 0)) - penalty_total))

        output = dict(item)
        output["contradictions"] = contradictions
        output["contradiction_penalty"] = penalty_total
        output["confidence"] = confidence
        output["confidence_band"] = confidence_band(confidence)
        output["decision"] = default_decision(confidence)

        if contradictions:
            output["siem_action"] = "contradiction_review"
        elif confidence < 70 and confidence > 0:
            output["siem_action"] = "review_queue"
        elif confidence == 0:
            output["siem_action"] = "display_only"
        else:
            output["siem_action"] = item.get("default_siem_action", "display_only")

        adjusted.append(output)

    return adjusted


def force_ambiguous_if_conflicting(adjusted: list[dict[str, Any]], fixture_id: str) -> dict[str, Any] | None:
    strong_raw = [
        item for item in adjusted
        if int(item.get("raw_confidence", 0)) >= 70
        and item.get("primary_type") not in {"Unknown", "Ambiguous Device"}
    ]

    contradiction_items = [
        item for item in adjusted
        if item.get("contradictions")
    ]

    if len(strong_raw) < 2 or not contradiction_items:
        return None

    strong_raw_sorted = sorted(
        strong_raw,
        key=lambda item: (int(item.get("raw_confidence", 0)), int(item.get("confidence", 0))),
        reverse=True,
    )

    contradictions: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []

    for item in strong_raw_sorted[:3]:
        evidence.extend(item.get("evidence", []))
        contradictions.extend(item.get("contradictions", []))

    confidence = min(69, max(int(item.get("confidence", 0)) for item in strong_raw_sorted))

    return {
        "schema_version": "netsniper-classification-result-v1",
        "fixture_id": fixture_id,
        "primary_type": "Ambiguous Device",
        "category": "Unknown / Ambiguous",
        "confidence": confidence,
        "confidence_band": confidence_band(confidence),
        "decision": "contradiction_review",
        "siem_action": "contradiction_review",
        "evidence": evidence,
        "contradictions": contradictions,
        "secondary_candidates": [
            {
                "primary_type": item.get("primary_type"),
                "category": item.get("category"),
                "raw_confidence": item.get("raw_confidence"),
                "confidence": item.get("confidence"),
                "confidence_band": item.get("confidence_band"),
                "decision": item.get("decision"),
                "siem_action": item.get("siem_action"),
                "evidence_count": len(item.get("evidence", [])),
                "contradiction_count": len(item.get("contradictions", [])),
            }
            for item in strong_raw_sorted[:5]
        ],
        "explanation": "Multiple strong but conflicting classification candidates were detected.",
    }


def choose_result(adjusted: list[dict[str, Any]], fixture_id: str) -> dict[str, Any]:
    forced = force_ambiguous_if_conflicting(adjusted, fixture_id)
    if forced is not None:
        return forced

    candidates = [
        item for item in adjusted
        if int(item.get("confidence", 0)) > 0
        and item.get("primary_type") not in {"Unknown", "Ambiguous Device"}
    ]

    if not candidates:
        return {
            "schema_version": "netsniper-classification-result-v1",
            "fixture_id": fixture_id,
            "primary_type": "Unknown",
            "category": "Unknown / Ambiguous",
            "confidence": 0,
            "confidence_band": "unknown",
            "decision": "unknown",
            "siem_action": "display_only",
            "evidence": [],
            "contradictions": [],
            "secondary_candidates": [],
            "explanation": "No meaningful classification evidence was detected.",
        }

    candidates_sorted = sorted(
        candidates,
        key=lambda item: (
            int(item.get("confidence", 0)),
            int(item.get("raw_confidence", 0)),
            len(item.get("evidence", [])),
        ),
        reverse=True,
    )

    winner = candidates_sorted[0]

    return {
        "schema_version": "netsniper-classification-result-v1",
        "fixture_id": fixture_id,
        "primary_type": winner.get("primary_type"),
        "category": winner.get("category"),
        "confidence": winner.get("confidence"),
        "confidence_band": winner.get("confidence_band"),
        "decision": winner.get("decision"),
        "siem_action": winner.get("siem_action"),
        "evidence": winner.get("evidence", []),
        "contradictions": winner.get("contradictions", []),
        "secondary_candidates": [
            {
                "primary_type": item.get("primary_type"),
                "category": item.get("category"),
                "raw_confidence": item.get("raw_confidence"),
                "confidence": item.get("confidence"),
                "confidence_band": item.get("confidence_band"),
                "decision": item.get("decision"),
                "siem_action": item.get("siem_action"),
                "evidence_count": len(item.get("evidence", [])),
                "contradiction_count": len(item.get("contradictions", [])),
            }
            for item in candidates_sorted[1:6]
        ],
        "explanation": f"Selected {winner.get('primary_type')} based on the highest adjusted confidence.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Classify a NetSniper v1.7 synthetic fixture.")
    parser.add_argument("--fixture", required=True, help="Path to fixture JSON")
    parser.add_argument("--profiles", default="classification/evidence_profiles.json", help="Path to evidence profiles JSON")
    args = parser.parse_args()

    fixture = load_json(Path(args.fixture))
    profiles = load_json(Path(args.profiles))

    observed = fixture.get("observed", {})
    fixture_id = str(fixture.get("fixture_id", Path(args.fixture).stem))

    scored = score_profiles(profiles, observed)
    signals = derive_signals(scored)
    adjusted = apply_contradictions(scored, signals)
    result = choose_result(adjusted, fixture_id)

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
