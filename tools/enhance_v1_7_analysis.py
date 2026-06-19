#!/usr/bin/env python3
"""
NetSniper v1.7 analysis enhancer.

Reads an existing NetSniper-style analysis JSON file, normalizes each host,
classifies each host with the v1.7 evidence engine, and writes an enriched
copy to a new output file.

This script does not scan the network and does not overwrite the input file.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from classify_v1_7_host import classify_host_record
from normalize_v1_7_host import normalize_host_record


KNOWN_HOST_PATHS = [
    ("hosts",),
    ("devices",),
    ("assets",),
    ("results",),
    ("analysis", "hosts"),
    ("data", "hosts"),
    ("network", "hosts"),
]


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"Missing file: {path}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def get_path(root: dict[str, Any], path: tuple[str, ...]) -> Any:
    current: Any = root
    for part in path:
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def set_path(root: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    current: Any = root
    for part in path[:-1]:
        current = current.setdefault(part, {})
    current[path[-1]] = value


def find_hosts(data: Any) -> tuple[tuple[str, ...] | None, list[Any]]:
    if isinstance(data, list):
        return None, data

    if not isinstance(data, dict):
        raise SystemExit("Expected analysis JSON to be an object or a list of host records")

    for path in KNOWN_HOST_PATHS:
        value = get_path(data, path)
        if isinstance(value, list):
            return path, value

    raise SystemExit(
        "Could not find host list. Expected one of: "
        + ", ".join(".".join(path) for path in KNOWN_HOST_PATHS)
        + ", or a root-level JSON array."
    )


def confidence_label(confidence: int) -> str:
    if confidence >= 70:
        return "classified"
    if confidence >= 40:
        return "possible"
    if confidence >= 1:
        return "weak"
    return "unknown"


def compatibility_classification(result: dict[str, Any]) -> dict[str, Any]:
    confidence = int(result.get("confidence", 0))

    return {
        "schema_version": "netsniper-classification-v1",
        "source": "netsniper-v1.7",
        "primary_type": result.get("primary_type", "Unknown"),
        "type": result.get("primary_type", "Unknown"),
        "category": result.get("category", "Unknown / Ambiguous"),
        "confidence": confidence,
        "confidence_label": confidence_label(confidence),
        "confidence_band": result.get("confidence_band", "unknown"),
        "decision": result.get("decision", "unknown"),
        "method": "weighted_evidence_v1_7",
        "siem_action": result.get("siem_action", "display_only"),
        "evidence": result.get("evidence", []),
        "contradictions": result.get("contradictions", []),
        "secondary_candidates": result.get("secondary_candidates", []),
        "explanation": result.get("explanation", ""),
        "observed_summary": result.get("observed_summary", {}),
    }


def enrich_host(host: Any, profiles: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(host, dict):
        host = {"raw_host_record": host}

    enriched = copy.deepcopy(host)

    normalized = normalize_host_record(enriched)
    classification_result = classify_host_record(normalized, profiles)
    compatible = compatibility_classification(classification_result)

    if "classification" in enriched:
        enriched["classification_previous"] = enriched["classification"]

    enriched["classification"] = compatible
    enriched["classification_v1_7"] = classification_result
    enriched["classification_observed_v1_7"] = normalized.get("observed", {})
    enriched["device_type"] = compatible["primary_type"]
    enriched["device_type_confidence"] = compatible["confidence"]

    return enriched


def summarize(enriched_hosts: list[dict[str, Any]]) -> dict[str, Any]:
    decision_counts: Counter[str] = Counter()
    action_counts: Counter[str] = Counter()
    type_counts: Counter[str] = Counter()
    band_counts: Counter[str] = Counter()

    contradiction_hosts = 0
    classified_hosts = 0
    possible_hosts = 0
    unknown_hosts = 0

    for host in enriched_hosts:
        classification = host.get("classification", {})
        decision = str(classification.get("decision", "unknown"))
        action = str(classification.get("siem_action", "display_only"))
        primary_type = str(classification.get("primary_type", "Unknown"))
        band = str(classification.get("confidence_band", "unknown"))
        contradictions = classification.get("contradictions", [])

        decision_counts[decision] += 1
        action_counts[action] += 1
        type_counts[primary_type] += 1
        band_counts[band] += 1

        if contradictions:
            contradiction_hosts += 1

        if decision == "classified":
            classified_hosts += 1
        elif decision in {"possible", "contradiction_review"}:
            possible_hosts += 1
        else:
            unknown_hosts += 1

    return {
        "schema_version": "netsniper-v1.7-enrichment-summary-v1",
        "enhanced_at": datetime.now(timezone.utc).isoformat(),
        "host_count": len(enriched_hosts),
        "classified_count": classified_hosts,
        "possible_or_review_count": possible_hosts,
        "unknown_count": unknown_hosts,
        "contradiction_host_count": contradiction_hosts,
        "decision_counts": dict(sorted(decision_counts.items())),
        "siem_action_counts": dict(sorted(action_counts.items())),
        "confidence_band_counts": dict(sorted(band_counts.items())),
        "top_device_types": dict(type_counts.most_common(10)),
    }


def enhance_analysis(data: Any, profiles: dict[str, Any]) -> Any:
    host_path, hosts = find_hosts(data)

    enriched_hosts = [enrich_host(host, profiles) for host in hosts]
    summary = summarize(enriched_hosts)

    if isinstance(data, list):
        return {
            "schema_version": "netsniper-analysis-enriched-v1",
            "hosts": enriched_hosts,
            "netsniper_v1_7_enrichment": summary,
        }

    output = copy.deepcopy(data)

    if host_path is None:
        output["hosts"] = enriched_hosts
    else:
        set_path(output, host_path, enriched_hosts)

    output["netsniper_v1_7_enrichment"] = summary

    return output


def main() -> int:
    parser = argparse.ArgumentParser(description="Enrich a NetSniper analysis JSON file with v1.7 classification.")
    parser.add_argument("--analysis", required=True, help="Input analysis JSON file")
    parser.add_argument("--output", required=True, help="Output enriched analysis JSON file")
    parser.add_argument(
        "--profiles",
        default="classification/evidence_profiles.json",
        help="Path to v1.7 evidence profiles JSON",
    )
    args = parser.parse_args()

    analysis_path = Path(args.analysis)
    output_path = Path(args.output)

    data = load_json(analysis_path)
    profiles = load_json(Path(args.profiles))

    enriched = enhance_analysis(data, profiles)
    write_json(output_path, enriched)

    summary = enriched.get("netsniper_v1_7_enrichment", {}) if isinstance(enriched, dict) else {}
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
