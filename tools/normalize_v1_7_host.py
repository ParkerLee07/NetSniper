#!/usr/bin/env python3
"""
NetSniper v1.7 host normalizer.

This converts a current/raw NetSniper host record into the v1.7 observed format
used by the reusable classifier.

It is intentionally tolerant because older NetSniper records may use different
field names for ports, services, vendors, hostnames, and titles.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


OBSERVED_FIELDS = [
    "open_ports",
    "service_hints",
    "vendor_hints",
    "http_titles",
    "hostname_hints",
    "network_roles",
]


PORT_KEYS = [
    "port",
    "portid",
    "port_id",
    "number",
    "port_number",
]

PROTO_KEYS = [
    "protocol",
    "proto",
    "transport",
]

SERVICE_KEYS = [
    "service",
    "service_name",
    "name",
    "product",
    "version",
    "banner",
    "service_product",
    "service_version",
    "fingerprint",
]

HTTP_TITLE_KEYS = [
    "http_title",
    "title",
    "web_title",
    "page_title",
]

VENDOR_KEYS = [
    "vendor",
    "vendor_hint",
    "vendor_hints",
    "mac_vendor",
    "oui_vendor",
    "manufacturer",
    "device_vendor",
]

HOSTNAME_KEYS = [
    "hostname",
    "host_name",
    "name",
    "dns_name",
    "fqdn",
    "hostnames",
]

NETWORK_ROLE_KEYS = [
    "network_role",
    "network_roles",
    "role",
    "roles",
]


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"Missing file: {path}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: {exc}")

    if not isinstance(data, dict):
        raise SystemExit(f"Expected a JSON object in {path}")

    return data


def add_value(values: list[str], value: Any) -> None:
    if value is None:
        return

    if isinstance(value, list):
        for item in value:
            add_value(values, item)
        return

    if isinstance(value, dict):
        for item in value.values():
            add_value(values, item)
        return

    text = str(value).strip()
    if not text or text.lower() in {"none", "null", "unknown"}:
        return

    values.append(text)


def dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []

    for value in values:
        key = value.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        output.append(value.strip())

    return output


def first_present(record: dict[str, Any], keys: list[str]) -> Any:
    for key in keys:
        if key in record and record[key] not in (None, "", []):
            return record[key]
    return None


def host_id_from(record: dict[str, Any]) -> str:
    for key in [
        "host_id",
        "ip",
        "ip_address",
        "address",
        "host",
        "hostname",
        "name",
        "mac",
        "mac_address",
    ]:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    return "unknown-host"


def normalize_port_text(value: Any, default_proto: str = "tcp") -> str | None:
    if value is None:
        return None

    text = str(value).strip().lower()
    if not text:
        return None

    # Already normalized: tcp/80
    match = re.fullmatch(r"(tcp|udp)/(\d{1,5})", text)
    if match:
        port = int(match.group(2))
        if 1 <= port <= 65535:
            return f"{match.group(1)}/{port}"
        return None

    # Nmap-ish: 80/tcp
    match = re.fullmatch(r"(\d{1,5})/(tcp|udp)", text)
    if match:
        port = int(match.group(1))
        if 1 <= port <= 65535:
            return f"{match.group(2)}/{port}"
        return None

    # Bare number: 80
    match = re.fullmatch(r"\d{1,5}", text)
    if match:
        port = int(text)
        proto = default_proto.lower() if default_proto else "tcp"
        if proto not in {"tcp", "udp"}:
            proto = "tcp"
        if 1 <= port <= 65535:
            return f"{proto}/{port}"

    return None


def state_is_open(entry: dict[str, Any]) -> bool:
    state = str(entry.get("state", entry.get("status", "open"))).strip().lower()
    return state in {"open", "open|filtered", "up", "reachable", ""}


def extract_port_from_entry(entry: dict[str, Any]) -> str | None:
    proto = str(first_present(entry, PROTO_KEYS) or "tcp").strip().lower()
    if proto not in {"tcp", "udp"}:
        proto = "tcp"

    port_value = first_present(entry, PORT_KEYS)
    return normalize_port_text(port_value, proto)


def collect_from_entry(entry: dict[str, Any], observed: dict[str, list[str]]) -> None:
    if not state_is_open(entry):
        return

    port = extract_port_from_entry(entry)
    if port:
        observed["open_ports"].append(port)

    for key in SERVICE_KEYS:
        if key in entry:
            add_value(observed["service_hints"], entry[key])

    for key in HTTP_TITLE_KEYS:
        if key in entry:
            add_value(observed["http_titles"], entry[key])

    for key in VENDOR_KEYS:
        if key in entry:
            add_value(observed["vendor_hints"], entry[key])


def collect_list_of_ports(value: Any, observed: dict[str, list[str]]) -> None:
    if not isinstance(value, list):
        return

    for item in value:
        if isinstance(item, dict):
            collect_from_entry(item, observed)
        else:
            port = normalize_port_text(item)
            if port:
                observed["open_ports"].append(port)


def normalize_observed_passthrough(raw_observed: dict[str, Any]) -> dict[str, list[str]]:
    observed = {field: [] for field in OBSERVED_FIELDS}

    for field in OBSERVED_FIELDS:
        add_value(observed[field], raw_observed.get(field))

    for field in OBSERVED_FIELDS:
        observed[field] = dedupe(observed[field])

    return observed


def normalize_host_record(record: dict[str, Any]) -> dict[str, Any]:
    host_id = host_id_from(record)

    if isinstance(record.get("observed"), dict):
        observed = normalize_observed_passthrough(record["observed"])
    else:
        observed = {field: [] for field in OBSERVED_FIELDS}

        # Common direct fields.
        collect_list_of_ports(record.get("open_ports"), observed)
        collect_list_of_ports(record.get("ports"), observed)
        collect_list_of_ports(record.get("services"), observed)

        # Some NetSniper-style outputs may store TCP and UDP separately.
        collect_list_of_ports(record.get("tcp_ports"), observed)
        collect_list_of_ports(record.get("udp_ports"), observed)

        # Direct hint fields.
        for key in SERVICE_KEYS:
            if key in record and key != "name":
                add_value(observed["service_hints"], record[key])

        for key in HTTP_TITLE_KEYS:
            if key in record:
                add_value(observed["http_titles"], record[key])

        for key in VENDOR_KEYS:
            if key in record:
                add_value(observed["vendor_hints"], record[key])

        for key in HOSTNAME_KEYS:
            if key in record:
                add_value(observed["hostname_hints"], record[key])

        for key in NETWORK_ROLE_KEYS:
            if key in record:
                add_value(observed["network_roles"], record[key])

        # Boolean gateway hints.
        if record.get("is_gateway") is True or record.get("default_gateway") is True:
            observed["network_roles"].append("default_gateway")

        # Helpful fallback: if a hostname was used as host_id, preserve it.
        if host_id != "unknown-host" and not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host_id):
            observed["hostname_hints"].append(host_id)

        for field in OBSERVED_FIELDS:
            observed[field] = dedupe(observed[field])

    return {
        "schema_version": "netsniper-normalized-host-v1",
        "host_id": host_id,
        "observed": observed,
        "observed_summary": {
            "open_port_count": len(observed["open_ports"]),
            "service_hint_count": len(observed["service_hints"]),
            "vendor_hint_count": len(observed["vendor_hints"]),
            "http_title_count": len(observed["http_titles"]),
            "hostname_hint_count": len(observed["hostname_hints"]),
            "network_role_count": len(observed["network_roles"]),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize a NetSniper host record for v1.7 classification.")
    parser.add_argument("--host-record", required=True, help="Path to a host record JSON file")
    args = parser.parse_args()

    record = load_json(Path(args.host_record))
    normalized = normalize_host_record(record)

    print(json.dumps(normalized, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
