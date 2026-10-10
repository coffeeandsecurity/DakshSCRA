#!/usr/bin/env python3
"""Conservatively translate an RDL v1 rule to an RDL v2 draft."""

import argparse
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from core.rdl.migration import migrate_v1_to_v2


def main(argv=None):
    parser = argparse.ArgumentParser(description="Create a reviewable RDL v2 draft from an RDL v1 rule.")
    parser.add_argument("path")
    parser.add_argument("--rule-id", required=True)
    parser.add_argument("--rule-version", type=int, default=1)
    args = parser.parse_args(argv)
    path = Path(args.path)
    output, diagnostics = migrate_v1_to_v2(path.read_text(encoding="utf-8"), args.rule_id, args.rule_version)
    sys.stdout.write(output)
    for item in diagnostics:
        sys.stderr.write("{0}:{1}: {2}: {3}\n".format(path, item.span.line, item.code, item.message))
    return 1 if any(item.severity.value == "error" for item in diagnostics) else 0


if __name__ == "__main__":
    sys.exit(main())
