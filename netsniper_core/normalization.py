from __future__ import annotations

import ipaddress
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Iterable

OBSERVED_FIELDS = (
    "open_ports",
    "service_hints",
    "vendor_hints",
    "http_titles",
    "hostname_hints",
    "network_roles",
    "os_hints",
)


def _dedupe(values: Iterable[Any]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for raw in values:
        text = str(raw).strip()
        key = text.casefold()
        if not text or key in {"none", "null", "unknown"} or key in seen:
            continue
        seen.add(key)
        output.append(text)
    return output


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _normalize_port(value: Any, protocol: str = "tcp") -> str | None:
    text = str(value).strip().lower()
    match = re.fullmatch(r"(tcp|udp)/(\d{1,5})", text)
    if match:
        port = int(match.group(2))
        return f"{match.group(1)}/{port}" if 1 <= port <= 65535 else None
    match = re.fullmatch(r"(\d{1,5})/(tcp|udp)", text)
    if match:
        port = int(match.group(1))
        return f"{match.group(2)}/{port}" if 1 <= port <= 65535 else None
    if text.isdigit():
        port = int(text)
        protocol = protocol if protocol in {"tcp", "udp"} else "tcp"
        return f"{protocol}/{port}" if 1 <= port <= 65535 else None
    return None


def _host_id(record: dict[str, Any]) -> str:
    for key in (
        "host_id", "host", "ip", "ip_address", "address", "addr", "hostname", "mac", "mac_address"
    ):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "unknown-host"


def normalize_host_record(record: dict[str, Any]) -> dict[str, Any]:
    observed = {field: [] for field in OBSERVED_FIELDS}
    raw_observed = record.get("observed") if isinstance(record.get("observed"), dict) else record

    for field in OBSERVED_FIELDS:
        observed[field].extend(_as_list(raw_observed.get(field)))

    for key in ("ports", "open_ports", "tcp_ports", "udp_ports", "findings"):
        value = raw_observed.get(key)
        for item in _as_list(value):
            if isinstance(item, dict):
                state = str(item.get("state", item.get("status", "open"))).lower()
                if state not in {"open", "open|filtered", "up", "reachable", ""}:
                    continue
                protocol = str(item.get("protocol", item.get("proto", "tcp"))).lower()
                port = _normalize_port(
                    item.get("port", item.get("portid", item.get("port_number", item.get("number", "")))),
                    protocol,
                )
                if port:
                    observed["open_ports"].append(port)
                for hint_key in (
                    "service", "service_name", "name", "product", "version", "banner", "description", "evidence"
                ):
                    observed["service_hints"].extend(_as_list(item.get(hint_key)))
                observed["http_titles"].extend(_as_list(item.get("http_title", item.get("title"))))
                observed["vendor_hints"].extend(_as_list(item.get("vendor", item.get("manufacturer"))))
            else:
                port = _normalize_port(item)
                if port:
                    observed["open_ports"].append(port)

    for key in ("hostname", "host_name", "dns_name", "fqdn", "hostnames"):
        observed["hostname_hints"].extend(_as_list(raw_observed.get(key)))
    for key in ("vendor", "mac_vendor", "oui_vendor", "manufacturer"):
        observed["vendor_hints"].extend(_as_list(raw_observed.get(key)))
    for key in ("os", "os_name", "os_guess", "platform", "os_hints"):
        observed["os_hints"].extend(_as_list(raw_observed.get(key)))
    for key in ("network_role", "network_roles", "role", "roles"):
        observed["network_roles"].extend(_as_list(raw_observed.get(key)))

    host_id = _host_id(record)
    if host_id != "unknown-host":
        try:
            ipaddress.ip_address(host_id)
        except ValueError:
            observed["hostname_hints"].append(host_id)

    for field in OBSERVED_FIELDS:
        observed[field] = _dedupe(observed[field])

    identity = {
        "ip": str(record.get("ip") or record.get("host") or "").strip() or None,
        "mac": str(record.get("mac") or record.get("mac_address") or "").strip() or None,
        "hostname": str(record.get("hostname") or "").strip() or None,
        "local_mac": bool(record.get("local_mac", False)),
    }

    observation = record.get("observation_quality") if isinstance(record.get("observation_quality"), dict) else {}

    return {
        "schema_version": "netsniper-normalized-host-v2",
        "host_id": host_id,
        "identity": identity,
        "observed": observed,
        "observation_quality": observation,
        "observed_summary": {f"{field}_count": len(observed[field]) for field in OBSERVED_FIELDS},
    }


def parse_gnmap_line(line: str) -> dict[str, Any] | None:
    host_match = re.search(r"\bHost:\s+([^\s]+)\s+\(([^)]*)\)", line)
    if not host_match or "Ports:" not in line:
        return None

    host = host_match.group(1).strip()
    hostname = host_match.group(2).strip()
    port_text = line.split("Ports:", 1)[1].split("Ignored State:", 1)[0].strip()
    ports: list[dict[str, Any]] = []

    for entry in port_text.split(","):
        entry = entry.strip()
        if not entry:
            continue
        parts = entry.split("/")
        if len(parts) < 3:
            continue
        port, state, protocol = parts[0:3]
        if state not in {"open", "open|filtered"}:
            continue
        service = parts[4].strip() if len(parts) > 4 else ""
        product = " ".join(part.strip() for part in parts[6:] if part.strip()) if len(parts) > 6 else ""
        item: dict[str, Any] = {
            "port": int(port) if port.isdigit() else port,
            "state": state,
            "protocol": protocol or "tcp",
        }
        if service:
            item["service"] = service
        if product:
            item["product"] = product
        ports.append(item)

    record: dict[str, Any] = {
        "host": host,
        "ip": host,
        "hostname": hostname or None,
        "ports": ports,
        "raw_gnmap_line": line.rstrip("\n"),
    }
    return record


def parse_nmap_xml(path: Path) -> dict[str, dict[str, Any]]:
    if not path.is_file() or path.stat().st_size == 0:
        return {}
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return {}

    output: dict[str, dict[str, Any]] = {}
    for host_node in root.findall("host"):
        status = host_node.find("status")
        if status is not None and status.get("state") != "up":
            continue
        ipv4 = None
        mac = None
        vendor = None
        for address in host_node.findall("address"):
            if address.get("addrtype") == "ipv4":
                ipv4 = address.get("addr")
            elif address.get("addrtype") == "mac":
                mac = address.get("addr")
                vendor = address.get("vendor")
        if not ipv4:
            continue
        item = output.setdefault(ipv4, {"ip": ipv4, "host": ipv4, "ports": [], "os_hints": []})
        if mac:
            item["mac"] = mac
        if vendor:
            item["vendor"] = vendor
        hostnames = [node.get("name", "") for node in host_node.findall("./hostnames/hostname") if node.get("name")]
        if hostnames:
            item["hostname"] = hostnames[0]
            item["hostname_hints"] = hostnames
        for port_node in host_node.findall("./ports/port"):
            state = port_node.find("state")
            if state is None or state.get("state") not in {"open", "open|filtered"}:
                continue
            service = port_node.find("service")
            port: dict[str, Any] = {
                "port": int(port_node.get("portid", "0")),
                "protocol": port_node.get("protocol", "tcp"),
                "state": state.get("state", "open"),
            }
            if service is not None:
                for key in ("name", "product", "version", "extrainfo", "ostype", "devicetype", "servicefp"):
                    if service.get(key):
                        mapped = "service" if key == "name" else key
                        port[mapped] = service.get(key)
            item["ports"].append(port)
        for osmatch in host_node.findall("./os/osmatch"):
            name = osmatch.get("name")
            if name:
                item["os_hints"].append(name)
        for osclass in host_node.findall("./os/osmatch/osclass"):
            details = " ".join(
                part for part in (
                    osclass.get("vendor"), osclass.get("osfamily"), osclass.get("osgen"), osclass.get("type")
                ) if part
            )
            if details:
                item["os_hints"].append(details)
    return output


def merge_host_records(*records: dict[str, Any] | None) -> dict[str, Any]:
    valid = [record for record in records if isinstance(record, dict)]
    if not valid:
        return {}
    output: dict[str, Any] = {}
    ports: list[Any] = []
    for record in valid:
        for key, value in record.items():
            if key == "ports":
                ports.extend(_as_list(value))
            elif value not in (None, "", [], {}):
                output[key] = value
    if ports:
        output["ports"] = ports
    return output
