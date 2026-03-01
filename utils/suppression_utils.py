# Standard libraries
import json
import re
from pathlib import Path


DEFAULT_BASELINE = Path("config/suppressions.json")


def _normalize_path(value):
    return str(value or "").replace('\\', '/').strip().lower()


def _normalize_text(value):
    return str(value or "").strip().lower()


def _safe_compile(pattern):
    if not pattern:
        return None
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error:
        return None


def load_suppressions(path):
    baseline_path = Path(path)
    if not baseline_path.exists():
        return []

    try:
        content = json.loads(baseline_path.read_text(encoding="utf-8"))
    except Exception:
        return []

    entries = content.get("suppressions", []) if isinstance(content, dict) else content
    normalized = []

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        normalized.append({
            "platform": _normalize_text(entry.get("platform")),
            "rule_title": _normalize_text(entry.get("rule_title")),
            "category": _normalize_text(entry.get("category")),
            "file": _normalize_path(entry.get("file")),
            "line": entry.get("line"),
            "code_regex": _safe_compile(entry.get("code_regex")),
            "path_regex": _safe_compile(entry.get("path_regex")),
        })

    return normalized


def is_suppressed(entries, platform, rule_title, category, file_path, line_no, code):
    if not entries:
        return False

    platform_n = _normalize_text(platform)
    rule_title_n = _normalize_text(rule_title)
    category_n = _normalize_text(category)
    file_n = _normalize_path(file_path)
    code_t = str(code or "")

    for entry in entries:
        if entry["platform"] and entry["platform"] != platform_n:
            continue
        if entry["rule_title"] and entry["rule_title"] != rule_title_n:
            continue
        if entry["category"] and entry["category"] != category_n:
            continue
        if entry["file"] and entry["file"] != file_n:
            continue
        if entry["line"] is not None and int(entry["line"]) != int(line_no):
            continue
        if entry["path_regex"] and not entry["path_regex"].search(file_n):
            continue
        if entry["code_regex"] and not entry["code_regex"].search(code_t):
            continue
        return True

    return False


def build_baseline_from_findings(findings_json_path, baseline_path):
    findings_path = Path(findings_json_path)
    if not findings_path.exists():
        return 0

    try:
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
    except Exception:
        return 0

    suppressions = []
    seen = set()

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        for evidence in finding.get("evidence", []):
            file_path = _normalize_path(evidence.get("file"))
            line_no = evidence.get("line")
            key = (
                _normalize_text(finding.get("platform")),
                _normalize_text(finding.get("rule_title")),
                _normalize_text(finding.get("category")),
                file_path,
                int(line_no) if isinstance(line_no, int) else line_no,
            )
            if key in seen:
                continue
            seen.add(key)
            suppressions.append({
                "platform": finding.get("platform", ""),
                "rule_title": finding.get("rule_title", ""),
                "category": finding.get("category", ""),
                "file": evidence.get("file", ""),
                "line": line_no,
            })

    out = {
        "version": 1,
        "description": "Suppression baseline for recurring false positives.",
        "suppressions": suppressions,
    }

    path_obj = Path(baseline_path)
    path_obj.parent.mkdir(parents=True, exist_ok=True)
    path_obj.write_text(json.dumps(out, indent=2), encoding="utf-8")

    return len(suppressions)
