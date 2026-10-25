#!/usr/bin/env python3
"""Refresh or check the README platform table against the scanner registries."""
import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.pattern_rules import resolve_pack
START = '<!-- supported-platforms:start -->'
END = '<!-- supported-platforms:end -->'


def platform_table(root=ROOT):
    scanning = root / 'rules/scanning'
    platforms = {}
    for node in ET.parse(scanning / 'rulesconfig.xml').getroot():
        name = (node.findtext('platform') or '').strip()
        path = scanning / 'platform' / (node.findtext('path') or '').strip().lstrip('/')
        if not name or name in platforms or not resolve_pack(path).exists():
            raise ValueError('Invalid or missing platform rule pack: {}'.format(name))
        platforms[name] = (path, set())
    for node in ET.parse(scanning / 'frameworkconfig.xml').getroot():
        name = (node.findtext('name') or '').strip()
        platform = (node.findtext('platform') or '').strip()
        rule_file = (node.findtext('rule_file') or '').strip()
        if platform not in platforms or not name or not rule_file:
            raise ValueError('Invalid framework mapping: {}'.format(name))
        path, frameworks = platforms[platform]
        # Some mobile registry entries reuse the platform pack under its own name.
        pack_exists = resolve_pack(path.parent / 'framework' / rule_file).exists() or path.name == rule_file
        if name in frameworks or not pack_exists:
            raise ValueError('Duplicate or missing framework rule pack: {}'.format(name))
        frameworks.add(name)
    lines = ['| Platform | Frameworks |', '|---|---|']
    for name, (_, frameworks) in platforms.items():
        lines.append('| {} | {} |'.format(name, ', '.join(sorted(frameworks)) or '-'))
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='fail if the table is out of date')
    args = parser.parse_args()
    readme = ROOT / 'README.md'
    try:
        text = readme.read_text(encoding='utf-8')
        if text.count(START) != 1 or text.count(END) != 1:
            raise ValueError('README must contain exactly one supported-platforms marker pair')
        before, rest = text.split(START)
        _, after = rest.split(END)
        updated = before + START + '\n' + platform_table() + '\n' + END + after
        if args.check and updated != text:
            raise ValueError('README platform table is stale. Run python3 tools/supported_platforms.py')
        if not args.check:
            readme.write_text(updated, encoding='utf-8')
    except (ValueError, OSError, ET.ParseError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print('README platform table {}'.format('verified' if args.check else 'updated'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
