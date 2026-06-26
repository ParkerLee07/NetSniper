#!/usr/bin/env python3
"""
Resolve and validate NetSniper v1.9 scan profiles.

This helper intentionally does not execute scans. It only validates the profile
contract so netsniper.sh can stay lightweight while avoiding duplicated JSON
parsing logic in Bash.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load_profiles(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"scan profile contract not found: {path}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"scan profile contract is invalid JSON: {exc}") from exc

    if data.get("schema_version") != "netsniper-scan-profiles-v1":
        raise SystemExit("unsupported scan profile schema")

    profiles = data.get("profiles")
    if not isinstance(profiles, list):
        raise SystemExit("scan profile contract missing profiles list")

    return data


def resolve_profile(data: dict[str, Any], requested: str | None) -> dict[str, Any]:
    default_name = data.get("default_profile", "balanced")
    name = (requested or default_name or "balanced").strip().lower()

    for profile in data.get("profiles", []):
        if str(profile.get("name", "")).lower() == name:
            return profile

    valid = ", ".join(sorted(str(profile.get("name")) for profile in data.get("profiles", [])))
    raise SystemExit(f"invalid scan profile '{requested}'. Valid profiles: {valid}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Resolve a NetSniper v1.9 scan profile.")
    parser.add_argument("profile", nargs="?", help="Profile name to resolve.")
    parser.add_argument(
        "--profiles-file",
        default="config/scan_profiles.json",
        help="Path to scan profile contract JSON.",
    )
    parser.add_argument(
        "--name-only",
        action="store_true",
        help="Print only the resolved profile name.",
    )
    args = parser.parse_args()

    data = load_profiles(Path(args.profiles_file))
    profile = resolve_profile(data, args.profile)

    if args.name_only:
        print(profile["name"])
    else:
        print(json.dumps(profile, sort_keys=True))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
