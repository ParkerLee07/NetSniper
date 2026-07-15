from __future__ import annotations

import re
from typing import Any

SOURCE_FIELDS = {
    "port": "open_ports",
    "service": "service_hints",
    "product": "service_hints",
    "vendor": "vendor_hints",
    "http_title": "http_titles",
    "hostname": "hostname_hints",
    "network_role": "network_roles",
    "os": "os_hints",
}


def match_rule(rule: dict[str, Any], observed: dict[str, list[str]]) -> str | None:
    source = str(rule.get("source", ""))
    field = SOURCE_FIELDS.get(source)
    if not field:
        return None
    values = [str(value) for value in observed.get(field, [])]
    pattern = str(rule.get("value", ""))
    if source in {"port", "network_role"}:
        allowed = {part.strip().casefold() for part in pattern.split("|") if part.strip()}
        return next((value for value in values if value.casefold() in allowed), None)
    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error:
        return None
    return next((value for value in values if regex.search(value)), None)


def source_group(rule: dict[str, Any]) -> str:
    return str(rule.get("source_group") or rule.get("source") or "other")


def evidence_id(axis: str, label: str, rule_id: str) -> str:
    safe = re.sub(r"[^a-z0-9_-]+", "-", f"{axis}-{label}-{rule_id}".lower()).strip("-")
    return safe or "evidence"


def build_evidence(
    axis: str,
    label: str,
    rule: dict[str, Any],
    matched_value: str,
    collector_id: str,
    observed_at: str,
) -> dict[str, Any]:
    rule_id = str(rule.get("id", "rule"))
    source = str(rule.get("source", "other"))
    source_type = {
        "port": "port_presence",
        "service": "service_fingerprint",
        "product": "product_fingerprint",
        "vendor": "mac_vendor",
        "http_title": "http_metadata",
        "hostname": "hostname_pattern",
        "network_role": "other",
        "os": "os_fingerprint",
    }.get(source, "other")
    return {
        "evidence_id": evidence_id(axis, label, rule_id),
        "affected_axes": [axis],
        "source_type": source_type,
        "collector_id": collector_id,
        "reliability": str(rule.get("reliability", "low")),
        "effect": "positive",
        "observed_at": observed_at,
        "summary": str(rule.get("reason", f"Matched {source} evidence for {label}.")),
        "normalized_value": {
            "rule_id": rule_id,
            "matched_value": matched_value,
            "points": int(rule.get("points", 0)),
            "source_group": source_group(rule),
            "independence_group": str(rule.get("independence_group") or source_group(rule)),
        },
        "raw_reference": None,
    }
