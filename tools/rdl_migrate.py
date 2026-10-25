#!/usr/bin/env python3
"""Import legacy packs or translate Pattern Rule conditions to an RDL v2 draft."""

import argparse
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from core.rdl.migration import migrate_v1_to_v2


def main(argv=None):
    parser = argparse.ArgumentParser(description="Import XML/RDL v1 as Pattern Rules, or create a reviewable RDL v2 draft.")
    parser.add_argument("path")
    parser.add_argument("--rule-id")
    parser.add_argument('--pattern', action='store_true', help='Import an XML/RDL v1 pack into single-file Pattern Rules')
    parser.add_argument('--output', help='Empty destination .rules directory for Pattern Rules')
    parser.add_argument('--logic-root', help='Legacy scanning directory containing referenced logic files')
    parser.add_argument("--rule-version", type=int, default=1)
    args = parser.parse_args(argv)
    path = Path(args.path)
    if args.pattern:
        from core.pattern_rules import migrate_xml
        try:
            destination, count = migrate_xml(path, args.output, args.logic_root)
        except (OSError, ValueError) as exc:
            parser.error(str(exc))
        print(f'Pattern Rules: {count} rules imported into {destination}')
        return 0
    if not args.rule_id:
        parser.error('--rule-id is required when producing a Semantic RDL draft')
    source = path.read_text(encoding="utf-8")
    if path.suffix in {'.yaml', '.yml'}:
        from core.pattern_rules import load_rule, logic_source
        source = logic_source(load_rule(path))
        if not source:
            parser.error('A regex-only Pattern Rule has no contextual conditions to translate; a Semantic Rule requires its own modeled property')
    output, diagnostics = migrate_v1_to_v2(source, args.rule_id, args.rule_version)
    sys.stdout.write(output)
    for item in diagnostics:
        sys.stderr.write("{0}:{1}: {2}: {3}\n".format(path, item.span.line, item.code, item.message))
    return 1 if any(item.severity.value == "error" for item in diagnostics) else 0


if __name__ == "__main__":
    sys.exit(main())
