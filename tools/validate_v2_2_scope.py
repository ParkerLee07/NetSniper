#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netsniper_core.scope import ScopeValidationError, normalize_private_cidr, validate_host_inventory_file


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate NetSniper v2.2 RFC1918 target and host containment.")
    parser.add_argument("--network", required=True)
    parser.add_argument("--hosts")
    parser.add_argument("--rewrite-hosts", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        network = normalize_private_cidr(args.network)
        hosts: list[str] = []
        if args.hosts:
            path = Path(args.hosts)
            hosts = validate_host_inventory_file(network, path)
            if args.rewrite_hosts:
                path.write_text("\n".join(hosts) + "\n", encoding="utf-8")
    except ScopeValidationError as exc:
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        else:
            print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    payload = {"ok": True, "network": network, "host_count": len(hosts), "hosts": hosts}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
