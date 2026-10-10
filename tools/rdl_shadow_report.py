#!/usr/bin/env python3
"""Summarize opt-in RDL v1/v2 shadow-comparison telemetry."""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.rdl.shadow import summarize_shadow_records


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", default=str(ROOT / "runtime" / "rdl_shadow_comparisons.jsonl"))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    summary = summarize_shadow_records(Path(args.path))
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print("comparisons={0} malformed={1}".format(summary["total"], summary["malformed"]))
        for status, count in summary["statuses"].items():
            print("{0}={1}".format(status, count))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
