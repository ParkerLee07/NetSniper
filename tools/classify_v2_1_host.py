#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from netsniper_core.classifier import classify_host
from netsniper_core.contracts import load_json


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the authoritative NetSniper v2.1 host classifier.")
    parser.add_argument("--host-record", required=True)
    parser.add_argument("--profiles", default=str(ROOT / "classification/evidence_profiles.json"))
    args = parser.parse_args()

    host = load_json(Path(args.host_record))
    profiles = load_json(Path(args.profiles))
    if not isinstance(host, dict) or not isinstance(profiles, dict):
        raise SystemExit("host record and profiles must be JSON objects")
    print(json.dumps(classify_host(host, profiles), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
