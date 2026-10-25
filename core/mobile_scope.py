"""Native rule-pack overlays shared by mobile scan selections."""
import fnmatch
import json
from pathlib import Path
from core.pattern_rules import resolve_pack


def pattern_overlays(root, selected_pack, files, explicit_packs=()):
    """Yield each applicable native pack and file once; explicit selections own their scans."""
    root = Path(root).resolve()
    config = root/'rules/scanning/metadata/rdl/platform-overlays.json'
    overlays = json.loads(config.read_text())['entries']
    by_source = {}
    for entry in overlays:
        source = resolve_pack(root/entry['source_pack']).resolve()
        by_source.setdefault(source, []).append(entry)
    explicit = {resolve_pack(p).resolve() for p in explicit_packs}
    pending = [(resolve_pack(selected_pack).resolve(), tuple(files))]
    seen = set()
    grouped = {}
    while pending:
        source, candidates = pending.pop()
        for entry in by_source.get(source, []):
            target = resolve_pack(root/entry['target_pack']).resolve()
            eligible = []
            for filename in candidates:
                key = (target, str(filename))
                if key in seen or not any(fnmatch.fnmatch(Path(filename).name, pattern) for pattern in entry['patterns']):
                    continue
                seen.add(key)
                eligible.append(str(filename))
            if not eligible:
                continue
            pending.append((target, tuple(eligible)))
            if target not in explicit:
                grouped.setdefault(target, []).extend(eligible)
    yield from grouped.items()
