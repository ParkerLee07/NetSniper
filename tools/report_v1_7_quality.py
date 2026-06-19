#!/usr/bin/env python3
"""
NetSniper v1.7 quality report.

Generates release-gate metrics for v1.7 device intelligence:
- classified count
- possible/review count
- unknown count
- contradiction count
- top device types
- confidence-band distribution
- SIEM action distribution
- false-confidence review candidates
- sample explanations per class
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from enhance_v1_7_analysis import enhance_analysis, find_hosts, load_json


def host_identity(host: dict[str, Any]) -> str:
    return str(
        host.get("ip")
        or host.get("ip_address")
        or host.get("address")
        or host.get("target")
        or host.get("target_ip")
        or host.get("host_ip")
        or host.get("host_id")
        or host.get("classification_v1_7", {}).get("host_id")
        or "unknown"
    )


def host_hostname(host: dict[str, Any]) -> str:
    return str(host.get("hostname") or host.get("host_name") or "-")


def is_enriched(data: Any) -> bool:
    if not isinstance(data, dict):
        return False

    if "netsniper_v1_7_enrichment" not in data:
        return False

    try:
        _, hosts = find_hosts(data)
    except SystemExit:
        return False

    if not hosts:
        return True

    return isinstance(hosts[0], dict) and isinstance(hosts[0].get("classification"), dict)


def ensure_enriched(data: Any, profiles: dict[str, Any]) -> Any:
    if is_enriched(data):
        return data
    return enhance_analysis(data, profiles)


def evidence_ids(classification: dict[str, Any]) -> list[str]:
    ids: list[str] = []

    for item in classification.get("evidence", []):
        if isinstance(item, dict):
            value = item.get("id")
            if value:
                ids.append(str(value))

    return ids


def evidence_reliability_set(classification: dict[str, Any]) -> set[str]:
    values: set[str] = set()

    for item in classification.get("evidence", []):
        if isinstance(item, dict):
            reliability = item.get("reliability")
            if reliability:
                values.add(str(reliability))

    return values


def false_confidence_reason(host: dict[str, Any]) -> str | None:
    c = host.get("classification", {})
    confidence = int(c.get("confidence", 0) or 0)
    decision = str(c.get("decision", "unknown"))
    primary_type = str(c.get("primary_type", "Unknown"))
    evidence = c.get("evidence", [])
    reliabilities = evidence_reliability_set(c)

    if decision != "classified" or confidence < 70:
        return None

    if not evidence:
        return "classified with no evidence"

    if len(evidence) == 1:
        return "classified from only one evidence item"

    if reliabilities and reliabilities.issubset({"low"}):
        return "classified using only low-reliability evidence"

    if primary_type == "Web Server / Web Application Host" and confidence >= 70:
        return "generic web classification reached high confidence"

    return None


def build_report(enriched: Any) -> dict[str, Any]:
    _, hosts_raw = find_hosts(enriched)
    hosts = [host for host in hosts_raw if isinstance(host, dict)]

    decision_counts: Counter[str] = Counter()
    action_counts: Counter[str] = Counter()
    type_counts: Counter[str] = Counter()
    band_counts: Counter[str] = Counter()

    classified = 0
    possible_or_review = 0
    unknown = 0
    contradiction_hosts = 0

    review_queue: list[dict[str, Any]] = []
    contradiction_review: list[dict[str, Any]] = []
    false_confidence_candidates: list[dict[str, Any]] = []
    unknown_with_exposed_services: list[dict[str, Any]] = []
    sample_by_type: dict[str, dict[str, Any]] = {}

    for host in hosts:
        c = host.get("classification", {})
        primary_type = str(c.get("primary_type", "Unknown"))
        confidence = int(c.get("confidence", 0) or 0)
        band = str(c.get("confidence_band", "unknown"))
        decision = str(c.get("decision", "unknown"))
        action = str(c.get("siem_action", "display_only"))
        contradictions = c.get("contradictions", [])
        observed = host.get("classification_observed_v1_7", {})
        observed_ports = observed.get("open_ports", []) if isinstance(observed, dict) else []

        identity = host_identity(host)
        hostname = host_hostname(host)
        eids = evidence_ids(c)

        decision_counts[decision] += 1
        action_counts[action] += 1
        type_counts[primary_type] += 1
        band_counts[band] += 1

        if decision == "classified":
            classified += 1
        elif decision in {"possible", "contradiction_review"}:
            possible_or_review += 1
        else:
            unknown += 1

        if contradictions:
            contradiction_hosts += 1

        row = {
            "identity": identity,
            "hostname": hostname,
            "primary_type": primary_type,
            "confidence": confidence,
            "confidence_band": band,
            "decision": decision,
            "siem_action": action,
            "evidence_count": len(c.get("evidence", [])),
            "contradiction_count": len(contradictions),
            "evidence_ids": eids,
        }

        if action in {"review_queue", "contradiction_review"} or decision in {"possible", "contradiction_review"}:
            review_queue.append(row)

        if action == "contradiction_review" or contradictions:
            contradiction_review.append(row)

        reason = false_confidence_reason(host)
        if reason:
            flagged = dict(row)
            flagged["reason"] = reason
            false_confidence_candidates.append(flagged)

        if primary_type == "Unknown" and observed_ports:
            unknown_with_exposed_services.append(
                {
                    "identity": identity,
                    "hostname": hostname,
                    "open_ports": observed_ports,
                    "service_hints": observed.get("service_hints", []),
                }
            )

        if primary_type not in sample_by_type and primary_type != "Unknown":
            sample_by_type[primary_type] = {
                "identity": identity,
                "hostname": hostname,
                "confidence": confidence,
                "confidence_band": band,
                "decision": decision,
                "siem_action": action,
                "evidence": c.get("evidence", [])[:5],
                "contradictions": contradictions[:5],
                "explanation": c.get("explanation", ""),
            }

    return {
        "schema_version": "netsniper-v1.7-quality-report-v1",
        "host_count": len(hosts),
        "classified_count": classified,
        "possible_or_review_count": possible_or_review,
        "unknown_count": unknown,
        "contradiction_host_count": contradiction_hosts,
        "decision_counts": dict(sorted(decision_counts.items())),
        "siem_action_counts": dict(sorted(action_counts.items())),
        "confidence_band_counts": dict(sorted(band_counts.items())),
        "top_device_types": dict(type_counts.most_common(15)),
        "false_confidence_candidate_count": len(false_confidence_candidates),
        "false_confidence_candidates": false_confidence_candidates[:25],
        "review_queue_count": len(review_queue),
        "review_queue_sample": review_queue[:25],
        "contradiction_review_count": len(contradiction_review),
        "contradiction_review_sample": contradiction_review[:25],
        "unknown_with_exposed_services_count": len(unknown_with_exposed_services),
        "unknown_with_exposed_services_sample": unknown_with_exposed_services[:25],
        "sample_explanations_by_type": sample_by_type,
    }


def markdown_table(rows: list[dict[str, Any]], columns: list[str]) -> str:
    if not rows:
        return "_None._\n"

    lines = []
    lines.append("| " + " | ".join(columns) + " |")
    lines.append("| " + " | ".join(["---"] * len(columns)) + " |")

    for row in rows:
        values = []
        for column in columns:
            value = row.get(column, "")
            if isinstance(value, list):
                value = ", ".join(str(item) for item in value)
            values.append(str(value).replace("|", "\\|"))
        lines.append("| " + " | ".join(values) + " |")

    return "\n".join(lines) + "\n"


def write_markdown(path: Path, report: dict[str, Any]) -> None:
    lines: list[str] = []

    lines.append("# NetSniper v1.7 Quality Report\n")
    lines.append("## Summary\n")
    lines.append(f"- Hosts: {report['host_count']}")
    lines.append(f"- Classified: {report['classified_count']}")
    lines.append(f"- Possible / Review: {report['possible_or_review_count']}")
    lines.append(f"- Unknown: {report['unknown_count']}")
    lines.append(f"- Contradiction hosts: {report['contradiction_host_count']}")
    lines.append(f"- False-confidence candidates: {report['false_confidence_candidate_count']}\n")

    lines.append("## Confidence Bands\n")
    for key, value in report["confidence_band_counts"].items():
        lines.append(f"- {key}: {value}")
    lines.append("")

    lines.append("## Top Device Types\n")
    for key, value in report["top_device_types"].items():
        lines.append(f"- {key}: {value}")
    lines.append("")

    lines.append("## Review Queue Sample\n")
    lines.append(
        markdown_table(
            report["review_queue_sample"],
            ["identity", "hostname", "primary_type", "confidence", "confidence_band", "decision", "siem_action", "evidence_count"],
        )
    )

    lines.append("## Contradiction Review Sample\n")
    lines.append(
        markdown_table(
            report["contradiction_review_sample"],
            ["identity", "hostname", "primary_type", "confidence", "decision", "siem_action", "contradiction_count"],
        )
    )

    lines.append("## False-Confidence Review Candidates\n")
    lines.append(
        markdown_table(
            report["false_confidence_candidates"],
            ["identity", "hostname", "primary_type", "confidence", "confidence_band", "reason", "evidence_count"],
        )
    )

    lines.append("## Unknown Hosts With Exposed Services\n")
    lines.append(
        markdown_table(
            report["unknown_with_exposed_services_sample"],
            ["identity", "hostname", "open_ports", "service_hints"],
        )
    )

    lines.append("## Sample Explanations By Type\n")
    for primary_type, sample in report["sample_explanations_by_type"].items():
        lines.append(f"### {primary_type}\n")
        lines.append(f"- Host: {sample['identity']}")
        lines.append(f"- Confidence: {sample['confidence']} ({sample['confidence_band']})")
        lines.append(f"- Decision: {sample['decision']}")
        lines.append(f"- SIEM action: {sample['siem_action']}")
        lines.append(f"- Explanation: {sample.get('explanation', '')}")
        lines.append("- Evidence:")
        for item in sample.get("evidence", []):
            lines.append(
                f"  - {item.get('id')}: +{item.get('points')} "
                f"({item.get('reliability')}) — {item.get('reason')}"
            )
        lines.append("")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate NetSniper v1.7 classification quality report.")
    parser.add_argument("--analysis", required=True, help="Raw or enriched analysis JSON")
    parser.add_argument("--output-json", help="Path to write quality report JSON")
    parser.add_argument("--output-md", help="Path to write quality report Markdown")
    parser.add_argument(
        "--profiles",
        default="classification/evidence_profiles.json",
        help="Path to v1.7 evidence profiles JSON",
    )
    args = parser.parse_args()

    data = load_json(Path(args.analysis))
    profiles = load_json(Path(args.profiles))

    enriched = ensure_enriched(data, profiles)
    report = build_report(enriched)

    if args.output_json:
        Path(args.output_json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output_json).write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    if args.output_md:
        write_markdown(Path(args.output_md), report)

    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
