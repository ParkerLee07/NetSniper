#!/usr/bin/env python3
"""
NetSniper v1.7 reusable host classifier.

This consumes a normalized host record and applies the v1.7 evidence profiles.
It does not scan the network and does not modify existing NetSniper outputs.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from classify_v1_7_fixture import (
    apply_contradictions,
    choose_result,
    derive_signals,
    load_json,
    score_profiles,
)


EXPECTED_OBSERVED_FIELDS = [
    "open_ports",
    "service_hints",
    "vendor_hints",
    "http_titles",
    "hostname_hints",
    "network_roles",
]


def ensure_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def extract_observed(host_record: dict[str, Any]) -> tuple[str, dict[str, list[str]]]:
    host_id = str(
        host_record.get("host_id")
        or host_record.get("ip")
        or host_record.get("address")
        or host_record.get("hostname")
        or "unknown-host"
    )

    if isinstance(host_record.get("observed"), dict):
        raw_observed = host_record["observed"]
    else:
        raw_observed = host_record

    observed: dict[str, list[str]] = {}

    for field in EXPECTED_OBSERVED_FIELDS:
        observed[field] = ensure_list(raw_observed.get(field))

    return host_id, observed


def classify_host_record(host_record: dict[str, Any], profiles: dict[str, Any]) -> dict[str, Any]:
    host_id, observed = extract_observed(host_record)

    scored = score_profiles(profiles, observed)
    signals = derive_signals(scored)
    adjusted = apply_contradictions(scored, signals)
    result = choose_result(adjusted, host_id)

    result.pop("fixture_id", None)
    result["host_id"] = host_id
    result["observed_summary"] = {
        "open_port_count": len(observed.get("open_ports", [])),
        "service_hint_count": len(observed.get("service_hints", [])),
        "vendor_hint_count": len(observed.get("vendor_hints", [])),
        "http_title_count": len(observed.get("http_titles", [])),
        "hostname_hint_count": len(observed.get("hostname_hints", [])),
        "network_role_count": len(observed.get("network_roles", [])),
    }

    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Classify a normalized NetSniper v1.7 host record.")
    parser.add_argument("--host-record", required=True, help="Path to normalized host record JSON")
    parser.add_argument(
        "--profiles",
        default="classification/evidence_profiles.json",
        help="Path to v1.7 evidence profiles JSON",
    )
    args = parser.parse_args()

    host_record = load_json(Path(args.host_record))
    profiles = load_json(Path(args.profiles))

    result = classify_host_record(host_record, profiles)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
