# Standard libraries
from pathlib import Path
from typing import Dict, Iterable, List
import re


def annotate_flows(flows: Iterable[Dict], *, platform: str, variant: str) -> List[Dict]:
    annotated: List[Dict] = []
    for flow in flows or []:
        if not isinstance(flow, dict):
            continue
        item = dict(flow)
        item.setdefault("platform", platform)
        item.setdefault("analysis_variant", variant)
        annotated.append(item)
    return annotated


def output_dir(base_root: str, platform: str) -> Path:
    return Path(base_root) / f"analysis/{platform}"


def rel_path(file_path: Path, source_root: Path) -> str:
    try:
        return str(file_path.relative_to(source_root)).replace("\\", "/")
    except ValueError:
        return str(file_path).replace("\\", "/")


def first_match_line(lines: List[str], pattern: re.Pattern, start: int = 1, end: int = 0) -> int:
    upper = end or len(lines)
    for idx in range(max(1, start), upper + 1):
        if pattern.search(lines[idx - 1]):
            return idx
    return 0


def line_text(lines: List[str], line_no: int, fallback: str) -> str:
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].strip()
    return fallback


def collect_files(source_root: Path, globs: Iterable[str]) -> List[Path]:
    files = set()
    for glob in globs or []:
        files.update(path for path in source_root.rglob(glob) if path.is_file())
    return sorted(files)


def flow(
    *,
    source_root: Path,
    file_path: Path,
    function: str,
    sink: str,
    description: str,
    explanation: str,
    path: List[Dict],
    confidence: str = "high",
    methods: List[str] = None,
    uris: List[str] = None,
    params: List[str] = None,
    attack_label: str = "",
    attack_reason: str = "",
    attack_example: str = "",
) -> Dict:
    rel = rel_path(file_path, source_root)
    for step in path:
        step["file"] = rel if step.get("file") is None else step["file"]
    sink_line = int(next((step.get("line", 1) for step in reversed(path) if step.get("role") == "sink"), 1))
    return {
        "file": rel,
        "line": sink_line,
        "function": function,
        "sink": sink,
        "description": description,
        "explanation": explanation,
        "path": path,
        "trace_status": "complete",
        "confidence": confidence,
        "xref": [],
        "input_surface": {
            "channel": "mobile-app",
            "methods": methods or [],
            "uris": uris or [],
            "params": params or [],
            "derived_params": [],
            "examples": [attack_example] if attack_example else [],
        },
        "attack_vectors": [
            {
                "kind": "mobile",
                "label": attack_label or function,
                "reason": attack_reason or description,
                "examples": [attack_example] if attack_example else [],
                "taint_symbols": ["mobile_input"],
            }
        ],
    }
