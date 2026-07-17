from __future__ import annotations

import copy
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .classifier import classify_host
from .contracts import write_json
from .legacy import compatibility_classification
from .normalization import merge_host_records, normalize_host_record, parse_nmap_xml


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _find_hosts(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item if isinstance(item, dict) else {"raw_host_record": item} for item in data]
    if isinstance(data, dict):
        for key in ("hosts", "devices", "assets", "results"):
            value = data.get(key)
            if isinstance(value, list):
                return [item if isinstance(item, dict) else {"raw_host_record": item} for item in value]
    raise ValueError("analysis JSON does not contain a supported host list")


def _neighbor_map(path: Path) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    if not path.is_file():
        return output
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if not parts:
            continue
        ip = parts[0]
        mac = None
        if "lladdr" in parts:
            index = parts.index("lladdr")
            if index + 1 < len(parts):
                mac = parts[index + 1]
        if mac:
            first_octet = int(mac.split(":", 1)[0], 16)
            output[ip] = {"ip": ip, "host": ip, "mac": mac, "local_mac": bool(first_octet & 0x02)}
    return output


def _observation_quality(capability: dict[str, Any] | None) -> dict[str, Any]:
    if not capability:
        return {
            "scan_completeness": "complete",
            "requested_collectors": ["discovery", "tcp_services"],
            "completed_collectors": ["discovery", "tcp_services"],
            "failed_collectors": [],
            "unavailable_collectors": [],
            "inventory_complete": True,
            "reasons": [],
        }
    requested = [item["collector_id"] for item in capability.get("collectors", []) if item.get("requested")]
    completed = [item["collector_id"] for item in capability.get("collectors", []) if item.get("status") == "completed"]
    failed = [item["collector_id"] for item in capability.get("collectors", []) if item.get("status") == "failed"]
    unavailable = [item["collector_id"] for item in capability.get("collectors", []) if item.get("status") == "unavailable"]
    return {
        "scan_completeness": capability.get("execution", {}).get("status", "complete"),
        "requested_collectors": requested,
        "completed_collectors": completed,
        "failed_collectors": failed,
        "unavailable_collectors": unavailable,
        "inventory_complete": bool(capability.get("integrity", {}).get("host_inventory_preserved", False)),
        "reasons": list(capability.get("execution", {}).get("partial_reasons", [])),
    }


def enrich_bundle_analysis(
    analysis: Any,
    bundle_dir: Path,
    profiles: dict[str, Any],
    capability: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    raw_hosts = _find_hosts(analysis)
    xml_maps = [
        parse_nmap_xml(bundle_dir / "discovery.xml"),
        parse_nmap_xml(bundle_dir / "services.xml"),
        parse_nmap_xml(bundle_dir / "os_detection.xml"),
        parse_nmap_xml(bundle_dir / "udp_lite.xml"),
    ]
    neighbors = _neighbor_map(bundle_dir / "neighbors.txt")
    quality = _observation_quality(capability)

    enriched_hosts: list[dict[str, Any]] = []
    classifications: list[dict[str, Any]] = []
    for raw in raw_hosts:
        host_id = str(raw.get("host") or raw.get("ip") or raw.get("host_id") or "unknown-host")
        merged = merge_host_records(copy.deepcopy(raw), raw.get("scan_observation") if isinstance(raw.get("scan_observation"), dict) else None)
        for xml_map in xml_maps:
            merged = merge_host_records(merged, xml_map.get(host_id))
        merged = merge_host_records(merged, neighbors.get(host_id))
        merged["observation_quality"] = quality
        classification = classify_host(merged, profiles)
        compatible = compatibility_classification(classification)

        enriched = copy.deepcopy(raw)
        enriched["host_id"] = classification["host_id"]
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", classification["host_id"]):
            enriched.setdefault("ip", classification["host_id"])
            enriched.setdefault("host", classification["host_id"])
        enriched["classification"] = compatible
        enriched["classification_v2_1"] = classification
        enriched["device_type"] = compatible["primary_type"]
        enriched["device_type_confidence"] = compatible["confidence"]
        enriched["classification_observed_v2_1"] = normalize_host_record(merged)["observed"]
        enriched_hosts.append(enriched)
        classifications.append(classification)

    decisions = Counter(item["device_family"]["decision"] for item in classifications)
    false_high = 0
    for item in classifications:
        axes = [item["device_family"], item["platform"], *item["roles"]]
        false_high += sum(
            1 for axis in axes
            if axis["confidence"] >= 90 and axis["decision"] in {"review", "unknown"}
        )

    summary = {
        "schema_version": "netsniper-v2.1-enrichment-summary-v1",
        "enhanced_at": _iso_now(),
        "host_count": len(enriched_hosts),
        "classified_count": decisions.get("classified", 0),
        "possible_or_review_count": decisions.get("possible", 0) + decisions.get("review", 0),
        "unknown_count": decisions.get("unknown", 0),
        "decision_counts": dict(sorted(decisions.items())),
        "false_confidence_candidate_count": false_high,
        "host_inventory_preserved": bool(capability.get("integrity", {}).get("host_inventory_preserved", True)) if capability else True,
    }
    return (
        {
            "schema_version": "netsniper-analysis-enriched-v2",
            "hosts": enriched_hosts,
            "netsniper_v2_1_enrichment": summary,
        },
        classifications,
        summary,
    )


def write_quality_reports(bundle_dir: Path, summary: dict[str, Any], classifications: list[dict[str, Any]]) -> None:
    role_counts = Counter()
    family_counts = Counter()
    review_queue_count = 0
    unknown_exposed = 0
    for item in classifications:
        family_counts[item["device_family"]["label"]] += 1
        for role in item["roles"]:
            role_counts[role["label"]] += 1
        if item["device_family"]["decision"] == "review" or any(role["decision"] == "review" for role in item["roles"]):
            review_queue_count += 1
        if item["device_family"]["label"] == "unknown" and item["evidence"]:
            unknown_exposed += 1

    report = {
        "schema_version": "netsniper-v2.1-classification-quality-v1",
        "generated_at": _iso_now(),
        "host_count": summary["host_count"],
        "classified_count": summary["classified_count"],
        "possible_or_review_count": summary["possible_or_review_count"],
        "unknown_count": summary["unknown_count"],
        "contradiction_host_count": sum(1 for item in classifications if item["device_family"]["contradictions"]),
        "false_confidence_candidate_count": summary["false_confidence_candidate_count"],
        "review_queue_count": review_queue_count,
        "unknown_with_exposed_services_count": unknown_exposed,
        "top_device_types": dict(family_counts.most_common(10)),
        "top_roles": dict(role_counts.most_common(10)),
        "confidence_band_counts": dict(Counter(item["device_family"]["confidence_band"] for item in classifications)),
        "decision_counts": summary["decision_counts"],
        "host_inventory_preserved": summary["host_inventory_preserved"],
    }
    write_json(bundle_dir / "classification_quality.json", report)
    lines = [
        "# NetSniper v2.1 Classification Quality",
        "",
        f"- Hosts: {report['host_count']}",
        f"- Classified families: {report['classified_count']}",
        f"- Possible or review: {report['possible_or_review_count']}",
        f"- Unknown: {report['unknown_count']}",
        f"- False high-confidence candidates: {report['false_confidence_candidate_count']}",
        f"- Full inventory preserved: {str(report['host_inventory_preserved']).lower()}",
        "",
    ]
    (bundle_dir / "classification_quality.md").write_text("\n".join(lines), encoding="utf-8")
