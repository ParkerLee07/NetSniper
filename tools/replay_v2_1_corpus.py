#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from netsniper_core.corpus_replay import FIXED_REPLAY_TIME, replay_corpus  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Replay active NetSniper v2.1 corpus fixtures deterministically."
    )
    parser.add_argument(
        "--repo",
        type=Path,
        default=ROOT,
        help="NetSniper repository root (default: script repository).",
    )
    parser.add_argument(
        "--split",
        action="append",
        choices=["development", "regression"],
        dest="splits",
        help="Limit replay to a split; may be supplied more than once.",
    )
    parser.add_argument(
        "--generated-at",
        default=FIXED_REPLAY_TIME,
        help="Fixed timestamp embedded in replay output.",
    )
    parser.add_argument("--output", type=Path, help="Write full replay JSON to this path.")
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Print only the replay summary rather than full fixture results.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = replay_corpus(
        args.repo,
        splits=set(args.splits) if args.splits else None,
        generated_at=args.generated_at,
    )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.summary_only:
        printable = {
            "schema_version": report["schema_version"],
            "generated_at": report["generated_at"],
            "selected_splits": report["selected_splits"],
            "split_counts": report["split_counts"],
            "metrics": report["metrics"],
            "passed": report["passed"],
            "failed_fixtures": [
                {
                    "fixture_id": item["fixture_id"],
                    "errors": item["errors"],
                }
                for item in report["fixtures"]
                if not item["passed"]
            ],
            "jsonschema_available": report["jsonschema_available"],
        }
        print(json.dumps(printable, indent=2))
    else:
        print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
