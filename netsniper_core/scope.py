from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Iterable

RFC1918_IPV4_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
MINIMUM_PREFIX_LENGTH = 16


class ScopeValidationError(ValueError):
    """Raised when a target or emitted host inventory violates scan scope."""


def normalize_private_cidr(value: str, *, minimum_prefix: int = MINIMUM_PREFIX_LENGTH) -> str:
    raw = str(value or "").strip()
    if not raw:
        raise ScopeValidationError("target CIDR is required")
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError as exc:
        raise ScopeValidationError(f"invalid target CIDR: {raw}") from exc
    if network.version != 4:
        raise ScopeValidationError("only IPv4 CIDR targets are supported")
    if network.prefixlen < minimum_prefix:
        raise ScopeValidationError(
            f"target prefix /{network.prefixlen} is broader than the minimum /{minimum_prefix}"
        )
    if not any(network.subnet_of(allowed) for allowed in RFC1918_IPV4_NETWORKS):
        raise ScopeValidationError(
            "target must be contained within RFC1918 space (10/8, 172.16/12, or 192.168/16)"
        )
    return str(network)


def normalize_host(value: str) -> str:
    raw = str(value or "").strip()
    try:
        address = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise ScopeValidationError(f"invalid host address: {raw!r}") from exc
    if address.version != 4:
        raise ScopeValidationError(f"only IPv4 host addresses are supported: {raw}")
    return str(address)


def validate_host_inventory(network_value: str, hosts: Iterable[str]) -> list[str]:
    network = ipaddress.ip_network(normalize_private_cidr(network_value), strict=False)
    normalized: list[str] = []
    seen: set[str] = set()
    for value in hosts:
        if not str(value).strip():
            continue
        host = normalize_host(value)
        if ipaddress.ip_address(host) not in network:
            raise ScopeValidationError(f"host {host} is outside declared network scope {network}")
        if host not in seen:
            seen.add(host)
            normalized.append(host)
    if not normalized:
        raise ScopeValidationError("host inventory is empty")
    return normalized


def validate_host_inventory_file(network_value: str, path: Path) -> list[str]:
    if not path.is_file():
        raise ScopeValidationError(f"host inventory is missing: {path}")
    return validate_host_inventory(
        network_value,
        path.read_text(encoding="utf-8", errors="replace").splitlines(),
    )
