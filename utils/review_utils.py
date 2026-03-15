import json
import re
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path


REVIEW_STATUS_PENDING = "pending"
REVIEW_STATUS_CONFIRMED = "confirmed"
REVIEW_STATUS_FALSE_POSITIVE = "false_positive"
REVIEW_STATUS_SUPPRESSED = "suppressed"
ACTIVE_REVIEW_STATUSES = {REVIEW_STATUS_FALSE_POSITIVE, REVIEW_STATUS_SUPPRESSED}


def _normalize_text(value):
    return str(value or "").strip().lower()


def _normalize_path(value):
    return str(value or "").replace("\\", "/").strip().lower()


def _safe_compile(pattern):
    if not pattern:
        return None
    try:
        return re.compile(str(pattern), re.IGNORECASE)
    except re.error:
        return None


def _safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def default_review():
    return {
        "status": REVIEW_STATUS_PENDING,
        "note": "",
        "updated_at": "",
    }


def normalize_review(review):
    if not isinstance(review, dict):
        return default_review()
    status = _normalize_text(review.get("status")) or REVIEW_STATUS_PENDING
    if status not in {
        REVIEW_STATUS_PENDING,
        REVIEW_STATUS_CONFIRMED,
        REVIEW_STATUS_FALSE_POSITIVE,
        REVIEW_STATUS_SUPPRESSED,
    }:
        status = REVIEW_STATUS_PENDING
    return {
        "status": status,
        "note": str(review.get("note") or "").strip(),
        "updated_at": str(review.get("updated_at") or "").strip(),
    }


def review_status_breakdown(findings):
    counts = {
        REVIEW_STATUS_PENDING: 0,
        REVIEW_STATUS_CONFIRMED: 0,
        REVIEW_STATUS_FALSE_POSITIVE: 0,
        REVIEW_STATUS_SUPPRESSED: 0,
    }
    for finding in findings or []:
        status = normalize_review(finding.get("review", {})).get("status")
        counts[status] = counts.get(status, 0) + 1
    return counts


def build_source_rule(finding):
    evidence = finding.get("evidence", []) if isinstance(finding.get("evidence"), list) else []
    first = evidence[0] if evidence and isinstance(evidence[0], dict) else {}
    return {
        "platform": str(finding.get("platform") or ""),
        "rule_title": str(finding.get("title") or finding.get("rule_title") or ""),
        "category": str(finding.get("category") or ""),
        "file": str(first.get("file") or ""),
        "line": first.get("line"),
    }


def build_path_rule(finding):
    paths = finding.get("paths", []) if isinstance(finding.get("paths"), list) else []
    return {
        "rule_title": str(finding.get("title") or finding.get("rule_title") or ""),
        "path": str(paths[0] if paths else ""),
        "path_regex": "",
    }


def build_analyzer_rule(finding):
    trace = finding.get("trace", []) if isinstance(finding.get("trace"), list) else []
    first = trace[0] if trace and isinstance(trace[0], dict) else {}
    return {
        "target": str(finding.get("target") or ""),
        "title": str(finding.get("title") or ""),
        "file": str(finding.get("file") or first.get("file") or ""),
        "line": finding.get("line") or first.get("line"),
        "sink": str(finding.get("sink") or ""),
        "source": str(finding.get("source") or ""),
        "severity": str(finding.get("severity") or ""),
    }


def export_review_config(path, *, job_id="", project_name="", findings_payload=None):
    findings_payload = findings_payload or {}
    source_rules = []
    path_rules = []
    analyzer_rules = []
    for finding in findings_payload.get("source_findings", []):
        review = normalize_review(finding.get("review", {}))
        if review["status"] in ACTIVE_REVIEW_STATUSES:
            rule = build_source_rule(finding)
            rule["status"] = review["status"]
            rule["note"] = review["note"]
            source_rules.append(rule)
    for finding in findings_payload.get("path_findings", []):
        review = normalize_review(finding.get("review", {}))
        if review["status"] in ACTIVE_REVIEW_STATUSES:
            rule = build_path_rule(finding)
            rule["status"] = review["status"]
            rule["note"] = review["note"]
            path_rules.append(rule)
    for finding in findings_payload.get("analyzer_findings", []):
        review = normalize_review(finding.get("review", {}))
        if review["status"] in ACTIVE_REVIEW_STATUSES:
            rule = build_analyzer_rule(finding)
            rule["status"] = review["status"]
            rule["note"] = review["note"]
            analyzer_rules.append(rule)

    payload = {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "dakshscra-webui",
        "job_id": str(job_id or ""),
        "project_name": str(project_name or ""),
        "rules": {
            "source": source_rules,
            "path": path_rules,
            "analyzer": analyzer_rules,
        },
    }
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def load_review_config(path):
    path_obj = Path(path)
    if not path_obj.exists():
        return {"rules": {"source": [], "path": [], "analyzer": []}}
    try:
        data = json.loads(path_obj.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return {"rules": {"source": [], "path": [], "analyzer": []}}
    rules = data.get("rules", {}) if isinstance(data, dict) else {}
    return {
        "rules": {
            "source": rules.get("source", []) if isinstance(rules.get("source"), list) else [],
            "path": rules.get("path", []) if isinstance(rules.get("path"), list) else [],
            "analyzer": rules.get("analyzer", []) if isinstance(rules.get("analyzer"), list) else [],
        }
    }


def source_suppressions_from_review_config(review_config):
    rules = review_config.get("rules", {}) if isinstance(review_config, dict) else {}
    suppressions = []
    for rule in rules.get("source", []) if isinstance(rules.get("source"), list) else []:
        if not isinstance(rule, dict):
            continue
        status = _normalize_text(rule.get("status"))
        if status not in ACTIVE_REVIEW_STATUSES:
            continue
        suppressions.append(
            {
                "platform": _normalize_text(rule.get("platform")),
                "rule_title": _normalize_text(rule.get("rule_title")),
                "category": _normalize_text(rule.get("category")),
                "file": _normalize_path(rule.get("file")),
                "line": _safe_int(rule.get("line")),
                "code_regex": _safe_compile(rule.get("code_regex")),
                "path_regex": _safe_compile(rule.get("path_regex")),
            }
        )
    return suppressions


def _match_source_rule(rule, finding):
    if _normalize_text(rule.get("platform")) and _normalize_text(rule.get("platform")) != _normalize_text(finding.get("platform")):
        return False
    if _normalize_text(rule.get("rule_title")) and _normalize_text(rule.get("rule_title")) != _normalize_text(finding.get("rule_title") or finding.get("title")):
        return False
    if _normalize_text(rule.get("category")) and _normalize_text(rule.get("category")) != _normalize_text(finding.get("category")):
        return False
    file_rule = _normalize_path(rule.get("file"))
    line_rule = _safe_int(rule.get("line"))
    for ev in finding.get("evidence", []) if isinstance(finding.get("evidence"), list) else []:
        if not isinstance(ev, dict):
            continue
        if file_rule and file_rule != _normalize_path(ev.get("file")):
            continue
        ev_line = _safe_int(ev.get("line"))
        if line_rule is not None and ev_line != line_rule:
            continue
        return True
    return not file_rule and line_rule is None


def _match_path_rule(rule, finding):
    if _normalize_text(rule.get("rule_title")) and _normalize_text(rule.get("rule_title")) != _normalize_text(finding.get("rule_title") or finding.get("title")):
        return False
    path_rule = _normalize_path(rule.get("path"))
    path_regex = _safe_compile(rule.get("path_regex"))
    paths = finding.get("filepath") if isinstance(finding.get("filepath"), list) else finding.get("paths", [])
    for item in paths or []:
        normalized = _normalize_path(item)
        if path_rule and normalized == path_rule:
            return True
        if path_regex and path_regex.search(normalized):
            return True
    return not path_rule and not path_regex


def _match_analyzer_rule(rule, finding, *, target=""):
    if _normalize_text(rule.get("target")) and _normalize_text(rule.get("target")) != _normalize_text(target or finding.get("target")):
        return False
    title = finding.get("title") or finding.get("description")
    if _normalize_text(rule.get("title")) and _normalize_text(rule.get("title")) != _normalize_text(title):
        return False
    if _normalize_text(rule.get("severity")) and _normalize_text(rule.get("severity")) != _normalize_text(finding.get("severity")):
        return False
    if _normalize_text(rule.get("sink")) and _normalize_text(rule.get("sink")) != _normalize_text(finding.get("sink")):
        return False
    if _normalize_text(rule.get("source")) and _normalize_text(rule.get("source")) != _normalize_text(finding.get("source") or finding.get("function")):
        return False
    file_rule = _normalize_path(rule.get("file"))
    line_rule = _safe_int(rule.get("line"))
    file_value = _normalize_path(finding.get("file"))
    line_value = _safe_int(finding.get("line"))
    if file_rule and file_rule != file_value:
        return False
    if line_rule is not None and line_rule != line_value:
        return False
    return True


def _review_status_for_findings(finding_type, finding, rules, *, target=""):
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if finding_type == "source" and _match_source_rule(rule, finding):
            return _normalize_text(rule.get("status")) or REVIEW_STATUS_SUPPRESSED
        if finding_type == "path" and _match_path_rule(rule, finding):
            return _normalize_text(rule.get("status")) or REVIEW_STATUS_SUPPRESSED
        if finding_type == "analyzer" and _match_analyzer_rule(rule, finding, target=target):
            return _normalize_text(rule.get("status")) or REVIEW_STATUS_SUPPRESSED
    return ""


def apply_review_statuses(findings_payload, review_config):
    payload = deepcopy(findings_payload or {})
    rules = review_config.get("rules", {}) if isinstance(review_config, dict) else {}
    for finding in payload.get("source_findings", []):
        status = _review_status_for_findings("source", finding, rules.get("source", []))
        finding["review"] = normalize_review({"status": status}) if status else normalize_review(finding.get("review"))
    for finding in payload.get("path_findings", []):
        status = _review_status_for_findings("path", finding, rules.get("path", []))
        finding["review"] = normalize_review({"status": status}) if status else normalize_review(finding.get("review"))
    for finding in payload.get("analyzer_findings", []):
        status = _review_status_for_findings("analyzer", finding, rules.get("analyzer", []), target=finding.get("target"))
        finding["review"] = normalize_review({"status": status}) if status else normalize_review(finding.get("review"))
    payload["review_summary"] = {
        "source": review_status_breakdown(payload.get("source_findings", [])),
        "path": review_status_breakdown(payload.get("path_findings", [])),
        "analyzer": review_status_breakdown(payload.get("analyzer_findings", [])),
    }
    return payload


def filtered_findings_payload(findings_payload):
    payload = deepcopy(findings_payload or {})
    payload["source_findings"] = [
        finding for finding in payload.get("source_findings", [])
        if normalize_review(finding.get("review")).get("status") not in ACTIVE_REVIEW_STATUSES
    ]
    payload["path_findings"] = [
        finding for finding in payload.get("path_findings", [])
        if normalize_review(finding.get("review")).get("status") not in ACTIVE_REVIEW_STATUSES
    ]
    payload["analyzer_findings"] = [
        finding for finding in payload.get("analyzer_findings", [])
        if normalize_review(finding.get("review")).get("status") not in ACTIVE_REVIEW_STATUSES
    ]
    payload["overview"] = {
        "source_count": len(payload.get("source_findings", [])),
        "path_count": len(payload.get("path_findings", [])),
        "analyzer_count": len(payload.get("analyzer_findings", [])),
    }
    payload["review_summary"] = {
        "source": review_status_breakdown(findings_payload.get("source_findings", [])),
        "path": review_status_breakdown(findings_payload.get("path_findings", [])),
        "analyzer": review_status_breakdown(findings_payload.get("analyzer_findings", [])),
    }
    return payload


def filter_scan_outputs(review_config, *, source_findings, path_findings, analysis_summary, analysis_flow_map):
    rules = review_config.get("rules", {}) if isinstance(review_config, dict) else {}

    filtered_source = []
    for finding in source_findings if isinstance(source_findings, list) else []:
        if not isinstance(finding, dict):
            continue
        status = _review_status_for_findings("source", finding, rules.get("source", []))
        if status in ACTIVE_REVIEW_STATUSES:
            continue
        filtered_source.append(finding)

    filtered_path = []
    for finding in path_findings if isinstance(path_findings, list) else []:
        if not isinstance(finding, dict):
            continue
        status = _review_status_for_findings("path", finding, rules.get("path", []))
        if status in ACTIVE_REVIEW_STATUSES:
            continue
        filtered_path.append(finding)

    summary_copy = deepcopy(analysis_summary) if isinstance(analysis_summary, dict) else {}
    filtered_results = []
    analyzer_count = 0
    for entry in summary_copy.get("results", []) if isinstance(summary_copy.get("results"), list) else []:
        if not isinstance(entry, dict):
            continue
        target = str(entry.get("target") or entry.get("platform") or "")
        kept = []
        for finding in entry.get("findings", []) if isinstance(entry.get("findings"), list) else []:
            if not isinstance(finding, dict):
                continue
            status = _review_status_for_findings("analyzer", finding, rules.get("analyzer", []), target=target)
            if status in ACTIVE_REVIEW_STATUSES:
                continue
            kept.append(finding)
        entry_copy = deepcopy(entry)
        entry_copy["findings"] = kept
        analyzer_count += len(kept)
        filtered_results.append(entry_copy)
    if isinstance(summary_copy, dict):
        summary_copy["results"] = filtered_results
        summary = summary_copy.get("summary", {})
        if isinstance(summary, dict):
            summary["findings_identified"] = analyzer_count

    filtered_flow_map = {}
    for flow_key, flows in (analysis_flow_map or {}).items():
        kept = []
        for finding in flows if isinstance(flows, list) else []:
            if not isinstance(finding, dict):
                continue
            status = _review_status_for_findings("analyzer", finding, rules.get("analyzer", []), target=flow_key)
            if status in ACTIVE_REVIEW_STATUSES:
                continue
            kept.append(finding)
        filtered_flow_map[flow_key] = kept

    return {
        "source_findings": filtered_source,
        "path_findings": filtered_path,
        "analysis_summary": summary_copy,
        "analysis_flow_map": filtered_flow_map,
        "counts": {
            "source": len(filtered_source),
            "path": len(filtered_path),
            "analyzer": analyzer_count,
        },
    }
