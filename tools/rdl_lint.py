#!/usr/bin/env python3
"""Validate RDL files without executing scanner rules."""

import argparse
import json
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from core.rdl import compile_rdl
from core.rdl.model import DiagnosticSeverity


def _paths(values):
    for value in values:
        path = Path(value)
        if path.is_dir():
            yield from sorted(p for p in path.rglob("*") if p.suffix in {".rdl", ".yaml", ".yml"})
        else:
            yield path


def main(argv=None):
    parser = argparse.ArgumentParser(description="Validate Pattern Rules and Semantic RDL source files.")
    parser.add_argument("paths", nargs="+", help="Pattern Rule YAML, RDL file, or directory")
    parser.add_argument("--json", action="store_true", dest="as_json", help="emit machine-readable JSON")
    args = parser.parse_args(argv)

    records = []
    error_count = 0
    identities = set()
    for path in _paths(args.paths):
        try:
            if path.suffix in {'.yaml', '.yml'}:
                from core.pattern_rules import load_rule, load_pack
                if path.name == '_pack.yaml':
                    load_pack(path.parent)
                    continue
                rule = load_rule(path)
                if rule['id'] in identities:
                    raise ValueError('Duplicate Pattern Rule identity: ' + rule['id'])
                identities.add(rule['id'])
                continue
            document = compile_rdl(path.read_text(encoding="utf-8"), str(path))
        except (OSError, ValueError) as exc:
            records.append({"path": str(path), "line": 1, "severity": "error", "code": "RDL000", "message": str(exc), "hint": ""})
            error_count += 1
            continue
        for diagnostic in document.diagnostics:
            if diagnostic.severity == DiagnosticSeverity.ERROR:
                error_count += 1
            records.append({
                "path": str(path),
                "line": diagnostic.span.line,
                "severity": diagnostic.severity.value,
                "code": diagnostic.code,
                "message": diagnostic.message,
                "hint": diagnostic.hint,
            })

    if args.as_json:
        print(json.dumps({"diagnostics": records, "errors": error_count}, indent=2))
    else:
        for item in records:
            print("{path}:{line}: {severity} {code}: {message}".format(**item))
            if item["hint"]:
                print("  hint: {0}".format(item["hint"]))
        print("RDL lint: {0} diagnostic(s), {1} error(s)".format(len(records), error_count))
    return 1 if error_count else 0


if __name__ == "__main__":
    sys.exit(main())
