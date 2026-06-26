#!/usr/bin/env python3
"""
Plan NetSniper v1.9 scan commands from the scan profile contract.

This tool does not execute scans. It emits a machine-readable command plan so
validators can prove profile behavior before netsniper.sh runtime scan behavior
is changed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from resolve_v1_9_scan_profile import load_profiles, resolve_profile


CURATED_PORTS_TOKEN = "$TRUEAEGIS_PORTS"


def build_plan(profile: dict[str, Any]) -> dict[str, Any]:
    name = profile["name"]
    tcp_port_mode = profile["tcp_port_mode"]

    tcp_args: list[str] = []

    if profile.get("service_detection"):
        tcp_args.append("-sV")

    tcp_args.append(profile.get("nmap_timing", "-T4"))

    version_intensity = profile.get("version_intensity")
    if version_intensity is not None:
        tcp_args.extend(["--version-intensity", str(version_intensity)])

    if tcp_port_mode == "curated":
        tcp_args.extend(["-p", CURATED_PORTS_TOKEN])
    elif tcp_port_mode == "full":
        tcp_args.append("-p-")
    else:
        raise SystemExit(f"unsupported tcp_port_mode for {name}: {tcp_port_mode}")

    os_detection_args: list[str] = []
    if profile.get("os_detection"):
        os_detection_args.append("-O")

    udp_lite_args: list[str] = []
    if profile.get("udp_lite"):
        udp_lite_args.extend(["-sU", "-p", "53,67,68,123,137,161,1900,5353,5355"])

    return {
        "schema_version": "netsniper-scan-command-plan-v1",
        "profile": name,
        "manual_only": bool(profile.get("manual_only")),
        "deltaaegis_safe_default": bool(profile.get("deltaaegis_safe_default")),
        "tcp": {
            "enabled": True,
            "args": tcp_args,
            "port_mode": tcp_port_mode,
        },
        "os_detection": {
            "enabled": bool(profile.get("os_detection")),
            "evidence_only": bool(profile.get("os_detection_evidence_only", False)),
            "args": os_detection_args,
        },
        "udp_lite": {
            "enabled": bool(profile.get("udp_lite")),
            "args": udp_lite_args,
        },
        "safety": {
            "intrusive_scripts": bool(profile.get("intrusive_scripts")),
            "full_tcp": bool(profile.get("full_tcp")),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Plan NetSniper v1.9 scan command arguments.")
    parser.add_argument("profile", nargs="?", help="Profile name to plan.")
    parser.add_argument(
        "--profiles-file",
        default="config/scan_profiles.json",
        help="Path to scan profile contract JSON.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print the JSON plan.",
    )
    args = parser.parse_args()

    data = load_profiles(Path(args.profiles_file))
    profile = resolve_profile(data, args.profile)
    plan = build_plan(profile)

    if args.pretty:
        print(json.dumps(plan, indent=2, sort_keys=True))
    else:
        print(json.dumps(plan, sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
