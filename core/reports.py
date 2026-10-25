from utils.datetime_utils import format_datetime, presentation_dates
# Standard libraries
import base64
import html
import os
import re
import sys
import time
import shutil
import tempfile
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from re import search
import json

# Third-party libraries
try:
    from jinja2 import Environment, FileSystemLoader, Template
except ImportError:
    sys.exit("[!] The Jinja2 module is not installed, please install it and try again")

import yaml
from playwright.sync_api import sync_playwright


# Local application imports
import state.runtime_state as state
import utils.cli_utils as cli
import utils.config_utils as cutils
from utils.cli_utils import spinner
from utils.log_utils import get_logger
from core.parser import FILEPATH_RULE_GUIDANCE

logger = get_logger(__name__)


def _path_guidance(item):
    title = str(item.get("rule_title", "") or item.get("keyword", "")).strip()
    from core.issue_titles import issue_title
    guidance = FILEPATH_RULE_GUIDANCE.get(issue_title(title), {})
    return {
        "brief_desc": guidance.get("brief_desc", "") or str(item.get("brief_desc", "")).strip() or str(item.get("rule_desc", "")).strip(),
        "attack_desc": guidance.get("attack_desc", "") or str(item.get("attack_desc", "")).strip() or str(item.get("vuln_desc", "")).strip(),
        "developer_note": guidance.get("developer_note", "") or str(item.get("developer_note", "")).strip(),
        "reviewer_note": str(item.get("reviewer_note", "")).strip() or guidance.get("reviewer_note", ""),
    }


def _is_common_platform(platform_name):
    return str(platform_name or "").strip().lower() == "common"


def _platform_sort_key(platform_name):
    name = str(platform_name or "").strip()
    # Keep COMMON findings after all platform-specific findings.
    return (1 if _is_common_platform(name) else 0, name.lower())


def _ordered_platform_names(platform_names):
    return sorted(platform_names, key=_platform_sort_key)


def _ordered_platform_dict(mapping):
    return {name: mapping[name] for name in _ordered_platform_names(mapping.keys())}


def _format_platform_display_name(name):
    raw = str(name or "").strip()
    if not raw:
        return raw
    key = raw.lower()
    display_map = {
        "c": "C",
        "cpp": "C++",
        "c++": "C++",
        "csharp": "C#",
        "c#": "C#",
        "dotnet": ".NET",
        "aspnet": "ASP.NET",
        "aspnetcore": "ASP.NET Core",
        "javascript": "JavaScript",
        "typescript": "TypeScript",
        "php": "PHP",
        "java": "Java",
        "kotlin": "Kotlin",
        "python": "Python",
        "ruby": "Ruby",
        "rust": "Rust",
        "go": "Go",
        "golang": "Golang",
        "sql": "SQL",
        "ios": "iOS",
        "android": "Android",
        "reactnative": "React Native",
        "nextjs": "Next.js",
        "nestjs": "NestJS",
        "vue": "Vue",
        "common": "COMMON",
    }
    if key in display_map:
        return display_map[key]
    return raw[0].upper() + raw[1:] if raw else raw


def _parse_rule_breakdown(value):
    items = []
    if isinstance(value, list):
        raw_parts = [str(v).strip() for v in value if str(v).strip()]
    else:
        raw_text = str(value or "").strip()
        raw_parts = [p.strip() for p in raw_text.split(",") if p.strip()]

    for part in raw_parts:
        match = re.match(r"^(.*?)\[(\d+)\]\s*$", part)
        if match:
            name = match.group(1).strip()
            count = int(match.group(2))
        else:
            name = part
            count = None
        items.append({
            "name": _format_platform_display_name(name),
            "count": count,
            "raw": part,
        })
    return items


def _normalize_confidence_score(value, default=50):
    try:
        score = int(round(float(value)))
    except (TypeError, ValueError):
        score = default
    return max(0, min(100, score))


def _read_text_lines_cached(file_cache, source_path):
    file_key = str(source_path or "").strip()
    if not file_key:
        return []
    if file_key in file_cache:
        return file_cache[file_key]
    try:
        lines = Path(file_key).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        lines = []
    file_cache[file_key] = lines
    return lines


def _line_context_rows(lines, line_no, window=2):
    try:
        line_index = int(line_no) - 1
    except (TypeError, ValueError):
        return [], None, []
    if line_index < 0 or line_index >= len(lines):
        return [], None, []
    before = []
    after = []
    for idx in range(max(0, line_index - window), line_index):
        before.append({"line": idx + 1, "code": lines[idx]})
    for idx in range(line_index + 1, min(len(lines), line_index + 1 + window)):
        after.append({"line": idx + 1, "code": lines[idx]})
    return before, lines[line_index], after


def _enrich_path_step_context(step, file_cache, window=2):
    if not isinstance(step, dict):
        return step
    enriched = dict(step)
    step_file = str(step.get("file", "")).strip()
    step_line = step.get("line")
    lines = _read_text_lines_cached(file_cache, step_file)
    before, resolved_code, after = _line_context_rows(lines, step_line, window=window)
    if before:
        enriched["context_before"] = before
    if after:
        enriched["context_after"] = after
    if resolved_code is not None:
        enriched["resolved_code"] = resolved_code
    return enriched


def _enrich_path_context(path_rows, file_cache, window=2):
    if not isinstance(path_rows, list):
        return []
    return [
        _enrich_path_step_context(step, file_cache, window=window)
        for step in path_rows
        if isinstance(step, dict)
    ]


def _confidence_label(score):
    if score >= 80:
        return "High"
    if score >= 60:
        return "Medium"
    return "Low"


def _fallback_source_confidence(item):
    evidence = item.get("evidence", []) if isinstance(item, dict) else []
    if not isinstance(evidence, list):
        evidence = []
    evidence_count = len(evidence)
    unique_files = len({ev.get("file", "") for ev in evidence if isinstance(ev, dict)})
    # Conservative fallback for legacy findings without explicit confidence fields.
    # Keep this below "High" because evidence quality signals are unavailable here.
    score = 35 + min(14, evidence_count * 2) + min(8, unique_files * 2)
    if evidence_count >= 12:
        score -= 4
    return max(20, min(74, int(score)))


def _fallback_paths_confidence(item):
    paths = item.get("filepath", []) if isinstance(item, dict) else []
    if not isinstance(paths, list):
        paths = []
    score = 50 + min(36, len(paths) * 6)
    return max(35, min(96, int(score)))


def gen_pdf_report_modern(html_path, pdf_path, print_header=True):
    try:
        started_at = time.time()
        start_dt = datetime.now()

        if print_header:
            cli.section_print("[*] PDF Report Generation")
            print(f"    [-] Started at       : {format_datetime(start_dt)}")

        print("    [-] Rendering JSON-driven professional PDF report... ", end="", flush=True)
        spinner("start")

        report_context = _build_pdf_report_context()
        from core.report_pdf import render_pdf
        render_pdf(report_context, pdf_path)

        spinner("stop")
        end_dt = datetime.now()
        elapsed = time.time() - started_at

        if print_header:
            print(f"    [-] Completed at     : {format_datetime(end_dt)}")
            hours, rem = divmod(elapsed, 3600)
            minutes, seconds = divmod(rem, 60)
            seconds, milliseconds = str(seconds).split('.')
            print("    [-] Total time taken : {:0>2}Hr:{:0>2}Min:{:0>2}s:{}ms".format(int(hours), int(minutes), seconds, milliseconds[:3]))

        return pdf_path, start_dt, end_dt, elapsed

    except Exception as e:
        spinner("stop")
        logger.exception("Error during modern PDF generation: %s", e)

    return pdf_path, None, None, 0


def export_pdf_from_html(html_file_path, output_pdf_path, expand_all_details=False):
    """Generate a PDF from a local HTML file using Playwright + Chromium."""
    html_file_path = Path(html_file_path).resolve()
    output_pdf_path = Path(output_pdf_path).resolve()

    if not html_file_path.exists():
        raise FileNotFoundError(f"HTML file not found: {html_file_path}")

    # Calculate file size in megabytes
    file_size_mb = html_file_path.stat().st_size / (1024 * 1024)

    # Abort if the HTML file exceeds 100 MB
    if file_size_mb > 100:
        print(f"[!] Aborting PDF creation: HTML file is too large ({file_size_mb:.2f} MB). Limit is 100 MB.")
        return

    # Calculate timeout based on file size:
    # Base timeout: 30 seconds, increase by 20 seconds for every additional 10 MB
    base_timeout = 30  # seconds
    extra_per_10mb = 20  # seconds
    timeout = base_timeout + int(file_size_mb // 10) * extra_per_10mb

    # Clamp the timeout between 30s and 300s (5 minutes)
    timeout = max(30, min(timeout, 300))

    # Convert timeout to milliseconds as required by Playwright
    timeout_ms = timeout * 1000

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()

        page.route("http://**/*", lambda route: route.abort())
        page.route("https://**/*", lambda route: route.abort())
        page.goto(html_file_path.as_uri(), wait_until='load', timeout=timeout_ms)
        if expand_all_details:
            page.evaluate("""
                () => {
                    document.querySelectorAll('details').forEach((d) => {
                        d.open = true;
                    });
                }
            """)
            page.wait_for_timeout(250)

        page.pdf(
            path=str(output_pdf_path),
            format="A4",
            print_background=True,
            display_header_footer=True,
            header_template='<span></span>',
            footer_template='<div style="font-size:8px;color:#5d6f91;width:100%;padding:0 24px;display:flex;justify-content:space-between"><span>Daksh SCRA · Security Review</span><span><span class="pageNumber"></span> / <span class="totalPages"></span></span></div>',
            margin={"top": "20px", "bottom": "40px", "left": "20px", "right": "20px"}
        )

        browser.close()


def _saved_evidence_rows(evidence):
    """Merge saved excerpts while keeping every matched line highlighted."""
    files = defaultdict(dict)
    def add(path, row, matched):
        line = row.get('line')
        if not isinstance(line, int):
            return
        code = str(row.get('code', '')).rstrip()
        key = (line, code)
        previous = files[path].get(key)
        combined = ('match' if matched or (previous and previous[0] == 'match') else 'context', line, code)
        spans = row.get('highlights')
        if isinstance(spans, list):
            retained = list(previous[3]) if previous and len(previous) > 3 else []
            for span in spans:
                if span not in retained:
                    retained.append(span)
            combined += (retained,)
        elif previous and len(previous) > 3:
            combined += (previous[3],)
        files[path][key] = combined
    for item in evidence if isinstance(evidence, list) else []:
        if not isinstance(item, dict):
            continue
        path = str(item.get('file', '')).strip()
        if item.get('aggregated'):
            for row in item.get('matches', []):
                for context in row.get('context_before', []):
                    add(path, context, False)
                add(path, row, True)
                for context in row.get('context_after', []):
                    add(path, context, False)
        else:
            for row in item.get('context_before', []):
                add(path, row, False)
            add(path, item, True)
            for row in item.get('context_after', []):
                add(path, row, False)
    return {path: sorted(rows.values(), key=lambda row: row[1]) for path, rows in files.items()}


def _load_report_logo_data_uri():
    try:
        with open(state.staticLogo, "rb") as f:
            encoded_logo_image = base64.b64encode(f.read()).decode("utf-8")
            return f"data:image/svg+xml;base64,{encoded_logo_image}"
    except OSError as exc:
        logger.error("Failed to load logo image %s: %s", state.staticLogo, exc)
        return None


def _normalize_aoi_data(raw_aoi):
    if isinstance(raw_aoi, list):
        return raw_aoi
    if isinstance(raw_aoi, dict):
        return list(raw_aoi.values())
    return []


def _bar_rows_from_counter(counter_map, top_n=12, sort_by_value=True, label_sort_key=None):
    if not counter_map:
        return []
    if sort_by_value:
        top = sorted(
            counter_map.items(),
            key=lambda x: (
                -x[1],
                label_sort_key(x[0]) if label_sort_key else str(x[0]).lower(),
            ),
        )[:top_n]
    else:
        top = sorted(
            counter_map.items(),
            key=lambda x: label_sort_key(x[0]) if label_sort_key else str(x[0]).lower(),
        )[:top_n]
    max_value = max(v for _, v in top) or 1
    total_value = sum(v for _, v in top) or 1
    return [
        {
            "label": label,
            "value": value,
            "width_pct": round((value / max_value) * 100, 2),
            "share_pct": round((value / total_value) * 100, 1),
        }
        for label, value in top
    ]


def _infer_pdf_evidence_label(issue_scope, category, files):
    text = f"{issue_scope} {category}".lower()
    config_markers = (
        "config",
        "configuration",
        "settings",
        "property",
        "properties",
        "yaml",
        "yml",
        "ini",
        "toml",
        "xml",
        "json",
        "env",
    )
    config_exts = {
        ".conf", ".cfg", ".cnf", ".config", ".ini", ".toml", ".yaml", ".yml", ".properties",
        ".env", ".xml", ".json", ".plist", ".tfvars",
    }
    config_filenames = {
        "dockerfile", "makefile", "jenkinsfile", "kustomization.yaml",
        "application.properties", "application.yml", "application.yaml",
        "web.config", "app.config",
    }

    if any(marker in text for marker in config_markers):
        return "Matched Configuration Entries"

    for file_path in files:
        if not file_path:
            continue
        lower_path = str(file_path).lower()
        base = os.path.basename(lower_path)
        if any(lower_path.endswith(ext) for ext in config_exts) or base in config_filenames:
            return "Matched Configuration Entries"

    return "Matched Source Snippets"


def _build_pdf_report_context(
    platform_filter=None,
    summary_json_path=None,
    aoi_json_path=None,
    filepaths_aoi_json_path=None,
    filepaths_json_path=None,
    analysis_json_path=None,
    project_config_path=None,
    document=None,
):
    summary_json_path = Path(summary_json_path) if summary_json_path else Path(state.outputSummary_JSON)
    aoi_json_path = Path(aoi_json_path) if aoi_json_path else Path(state.outputAoI_JSON)
    filepaths_aoi_json_path = (
        Path(filepaths_aoi_json_path) if filepaths_aoi_json_path else Path(state.outputAoI_Fpaths_JSON)
    )
    filepaths_json_path = Path(filepaths_json_path) if filepaths_json_path else Path(state.output_Fpaths_JSON)
    analysis_json_path = Path(analysis_json_path) if analysis_json_path else Path(state.outputAnalysis_JSON)
    project_config_path = Path(project_config_path) if project_config_path else Path(state.projectConfig)

    sections = document.get("sections", {}) if document is not None else None
    def saved(name, path, default):
        return sections.get(name, default) if sections is not None else _load_json_file(path, default=default, label=name)
    scan_summary = saved("summary", summary_json_path, {}) or {}
    aoi_raw = saved("areas_of_interest", aoi_json_path, []) or []
    from core.rdl.narratives import enrich_source_findings
    aoi_raw = enrich_source_findings(list(aoi_raw.values()) if isinstance(aoi_raw, dict) else aoi_raw)
    filepaths_aoi = saved("filepaths_aoi", filepaths_aoi_json_path, []) or []
    filepaths_all_raw = saved("filepaths", filepaths_json_path, []) or []
    config = _load_yaml_file(project_config_path, default={}, label="project config") or {}

    inputs = scan_summary.get("inputs_received", {})
    detection = scan_summary.get("detection_summary", {})
    timeline = scan_summary.get("scanning_timeline", {})
    platform_rules_breakdown = _parse_rule_breakdown(inputs.get("platform_specific_rules", ""))
    common_rules_breakdown = _parse_rule_breakdown(inputs.get("common_rules", ""))

    aoi_list = _normalize_aoi_data(aoi_raw)
    findings = []
    platform_counter = defaultdict(int)
    category_counter = defaultdict(int)
    scope_counter = defaultdict(int)
    rule_counter = defaultdict(int)
    evidence_total = 0

    for item in aoi_list:
        if not isinstance(item, dict):
            continue
        platform = str(item.get("platform", "unknown")).strip() or "unknown"
        if platform_filter and platform.lower() != platform_filter.lower():
            continue

        rule_title = str(item.get("rule_title", "")).strip() or "Unnamed rule"
        category = str(item.get("category", "")).strip() or "-"
        issue_scope = str(item.get("issue_scope", "")).strip() or "-"
        evidence = item.get("evidence", [])
        evidence_count = len(evidence) if isinstance(evidence, list) else 0
        evidence_total += evidence_count

        files = []
        file_rows = _saved_evidence_rows(evidence)
        files = list(file_rows)

        evidence_samples = [
            {
                "file": src_file,
                "code": _render_code_viewer(
                    sorted(rows, key=lambda r: r[1] if isinstance(r[1], int) else 0),
                    (item.get('scan_config') or {}).get('highlight_enabled', True),
                ),
            }
            for src_file, rows in file_rows.items()
        ]

        confidence_score = _normalize_confidence_score(
            item.get("confidence_score"),
            default=_fallback_source_confidence(item),
        )
        finding = {
            "platform": platform,
            "rule_title": rule_title,
            "category": category,
            "issue_scope": issue_scope,
            "rule_desc": str(item.get("rule_desc", "")).strip(),
            "issue_desc": str(item.get("issue_desc", "")).strip(),
            "security_impact": str(item.get("security_impact", "")).strip(),
            "developer_note": str(item.get("developer_note", "")).strip(),
            "reviewer_note": str(item.get("reviewer_note", "")).strip(),
            "rule_id": str(item.get("rule_id", "")).strip(),
            "evidence_count": evidence_count,
            "files": files,
            "evidence_samples": evidence_samples,
            "evidence_label": _infer_pdf_evidence_label(issue_scope, category, files),
            "confidence_score": confidence_score,
            "logic_engine": str(item.get("logic_engine", "")).strip(),
            "logic_source": str(item.get("logic_source", "")).strip(),
            "logic_reason": str(item.get("logic_reason", "")).strip(),
            "logic_trace": [str(x).strip() for x in (item.get("logic_trace", []) or []) if str(x).strip()],
            "logic_consulted_files": [str(x).strip() for x in (item.get("logic_consulted_files", []) or []) if str(x).strip()],
        }
        finding["confidence_label"] = _confidence_label(finding["confidence_score"])
        findings.append(finding)
        platform_counter[platform] += 1
        category_counter[category] += 1
        scope_counter[issue_scope] += 1
        rule_counter[rule_title] += 1

    findings.sort(key=lambda f: (_platform_sort_key(f["platform"]), f["rule_title"].lower()))

    findings_by_platform = defaultdict(list)
    for finding in findings:
        findings_by_platform[finding["platform"]].append(finding)

    platform_sections = []
    for platform_name in _ordered_platform_names(findings_by_platform.keys()):
        slug = re.sub(r"[^a-z0-9]+", "-", platform_name.lower()).strip("-") or "platform"
        platform_sections.append({
            "name": platform_name,
            "slug": slug,
            "findings": findings_by_platform[platform_name],
            "count": len(findings_by_platform[platform_name]),
        })

    rule_index = [
        {"title": title, "count": count}
        for title, count in sorted(rule_counter.items(), key=lambda x: (-x[1], x[0].lower()))
    ]

    file_index = []
    parsed_paths_aoi = []
    if isinstance(filepaths_aoi, list):
        for item in filepaths_aoi:
            if not isinstance(item, dict):
                continue
            guidance = _path_guidance(item)
            paths = item.get("filepath", [])
            if not isinstance(paths, list):
                paths = []
            file_index.append({
                "rule_title": str(item.get("rule_title", "")).strip() or "Unnamed rule",
                "count": len(paths),
                "paths": paths[:20],
            })
            if paths:
                parsed_paths_aoi.append({
                    "keyword": str(item.get("rule_title", "")).strip() or "Unnamed rule",
                    "paths": paths,
                    "count": len(paths),
                    "confidence_score": _normalize_confidence_score(
                        item.get("confidence_score"),
                        default=_fallback_paths_confidence(item),
                    ),
                    "confidence_label": _confidence_label(_normalize_confidence_score(
                        item.get("confidence_score"),
                        default=_fallback_paths_confidence(item),
                    )),
                    **guidance,
                })
    file_index.sort(key=lambda x: (-x["count"], x["rule_title"].lower()))

    all_filepaths = []
    if isinstance(filepaths_all_raw, list):
        for item in filepaths_all_raw:
            if isinstance(item, dict):
                path = str(item.get("path", "")).strip()
                loc = item.get("loc")
                if path:
                    all_filepaths.append(f"{path}" + (f" (LOC: {loc})" if loc is not None else ""))
            elif item:
                all_filepaths.append(str(item))

    file_extensions = detection.get("file_extensions_identified", {})
    extension_rows = []
    if isinstance(file_extensions, dict):
        for pf in _ordered_platform_names(file_extensions.keys()):
            ext_list = file_extensions.get(pf)
            if isinstance(ext_list, list):
                extension_rows.append({"platform": pf, "extensions": ", ".join(ext_list)})

    top_files = []
    file_hit_counter = defaultdict(int)
    for finding in findings:
        for fp in finding["files"]:
            file_hit_counter[fp] += 1
    for path, hits in sorted(file_hit_counter.items(), key=lambda x: x[1], reverse=True)[:15]:
        top_files.append({"path": path, "hits": hits})

    report_title = config.get("title") or "Daksh SCRA Scan Report"
    report_subtitle = config.get("subtitle")
    if report_subtitle and str(report_subtitle).lower() == "none":
        report_subtitle = None

    cards = [
        {"label": "Total Findings", "value": len(findings)},
        {"label": "Evidence Matches", "value": evidence_total},
        {"label": "Platforms Impacted", "value": len(platform_sections)},
        {"label": "Rules Loaded", "value": inputs.get("total_rules_loaded", "-")},
        {"label": "Files Scanned", "value": detection.get("total_files_scanned", "-")},
        {"label": "AOI File Paths", "value": detection.get("file_paths_areas_of_interest_identified", "-")},
    ]

    from core.report_document import presentation_context, cli_document
    extra = presentation_context(document if document is not None else cli_document(analysis_path=analysis_json_path), platform_filter)
    return {
        **extra,
        "generated_at": format_datetime(),
        "report_date": format_datetime(date_only=True),
        "logoImagePath": _load_report_logo_data_uri(),
        "reportTitle": report_title,
        "reportSubTitle": report_subtitle,
        "platform_filter": platform_filter,
        "cards": cards,
        "inputs": inputs,
        "platform_rules_breakdown": platform_rules_breakdown,
        "common_rules_breakdown": common_rules_breakdown,
        "detection": detection,
        "timeline": presentation_dates(timeline),
        "extension_rows": extension_rows,
        "platform_sections": platform_sections,
        "rule_index": rule_index,
        "file_index": file_index,
        "parsed_paths_aoi": parsed_paths_aoi,
        "all_filepaths": all_filepaths,
        "top_files": top_files,
        "chart_platforms": _bar_rows_from_counter(
            platform_counter,
            top_n=16,
            sort_by_value=False,
            label_sort_key=_platform_sort_key,
        ),
        "chart_categories": _bar_rows_from_counter(category_counter, top_n=12),
        "chart_scopes": _bar_rows_from_counter(scope_counter, top_n=12),
    }


def _render_pdf_html(context):
    env = Environment(loader=FileSystemLoader(state.htmltemplates_dir), autoescape=True)
    from utils.guidance_format import guidance_html
    env.filters['guidance'] = guidance_html
    template = env.get_template("pdf_report.html")
    return template.render(**presentation_dates(context))


def _write_temp_pdf_html(rendered_html):
    pdf_temp_root = Path(state.reports_dirpath) / "scan" / "pdf"
    pdf_temp_root.mkdir(parents=True, exist_ok=True)
    fd, path_str = tempfile.mkstemp(prefix="report-json-", suffix=".html", dir=str(pdf_temp_root))
    os.close(fd)
    path = Path(path_str)
    path.write_text(rendered_html, encoding="utf-8")
    return path


def gen_pdf_reports_from_json(
    json_dir=None,
    output_pdf_path=None,
    multifile_output_dir=None,
    include_multifile=True,
    project_config_path=None,
):
    """
    Generate professional PDF report(s) directly from existing JSON outputs.

    Expected JSON filenames in json_dir:
      - summary.json
      - areas_of_interest.json
      - filepaths_aoi.json (optional)
    """
    json_root = Path(json_dir) if json_dir else (Path(state.reports_dirpath) / "data")
    summary_path = json_root / "summary.json"
    aoi_path = json_root / "areas_of_interest.json"
    filepaths_aoi_path = json_root / "filepaths_aoi.json"
    analysis_path = json_root / "analysis.json"

    if not summary_path.exists():
        raise FileNotFoundError(f"Missing required JSON: {summary_path}")
    if not aoi_path.exists():
        raise FileNotFoundError(f"Missing required JSON: {aoi_path}")

    single_pdf_path = Path(output_pdf_path) if output_pdf_path else Path(state.pdfreport_Fpath)
    multi_pdf_root = Path(multifile_output_dir) if multifile_output_dir else (Path(state.reports_dirpath) / "scan" / "pdf" / "multi-file")

    from core.report_document import cli_document
    document = cli_document(analysis_path=json_root / 'analysis.json')

    single_pdf_path.parent.mkdir(parents=True, exist_ok=True)

    context_all = _build_pdf_report_context(
        summary_json_path=summary_path,
        aoi_json_path=aoi_path,
        filepaths_aoi_json_path=filepaths_aoi_path,
        analysis_json_path=analysis_path if analysis_path.exists() else None,
        project_config_path=project_config_path,
        document=document,
    )
    from core.report_pdf import render_pdf
    render_pdf(context_all, single_pdf_path)

    generated_platform_pdfs = []
    if include_multifile:
        if multi_pdf_root.exists():
            shutil.rmtree(multi_pdf_root, ignore_errors=True)
        multi_pdf_root.mkdir(parents=True, exist_ok=True)
        platforms_dir = multi_pdf_root / "platforms"
        platforms_dir.mkdir(parents=True, exist_ok=True)

        full_pdf_path = multi_pdf_root / "report-full.pdf"
        shutil.copyfile(single_pdf_path, full_pdf_path)

        for section in context_all.get("platform_sections", []):
            platform_name = section.get("name")
            if not platform_name:
                continue
            platform_ctx = _build_pdf_report_context(
                platform_filter=platform_name,
                summary_json_path=summary_path,
                aoi_json_path=aoi_path,
                filepaths_aoi_json_path=filepaths_aoi_path,
                analysis_json_path=analysis_path if analysis_path.exists() else None,
                project_config_path=project_config_path,
                document=document,
            )
            safe_name = re.sub(r"[^a-z0-9]+", "-", str(platform_name).lower()).strip("-") or "platform"
            platform_pdf_path = platforms_dir / f"{safe_name}.pdf"
            render_pdf(platform_ctx, platform_pdf_path)
            generated_platform_pdfs.append(platform_pdf_path)

    return {
        "json_root": json_root,
        "single_pdf": single_pdf_path,
        "multi_pdf_root": multi_pdf_root if include_multifile else None,
        "platform_pdfs": generated_platform_pdfs,
    }

def gen_html_report_modern(scan_summary, snippets, filepaths, filepaths_aoi, report_output_path, document=None):
    try:
        with open(state.projectConfig, "r") as stream:
            config = yaml.safe_load(stream)
    except (OSError, yaml.YAMLError) as exc:
        logger.error("Failed to load project config %s: %s", state.projectConfig, exc)
        return None

    try:
        with open(state.staticLogo, "rb") as f:
            encoded_logo_image = base64.b64encode(f.read())
    except OSError as exc:
        logger.error("Failed to load logo image %s: %s", state.staticLogo, exc)
        return None

    detection = scan_summary.get("detection_summary", {}) if isinstance(scan_summary, dict) else {}
    inputs = scan_summary.get("inputs_received", {}) if isinstance(scan_summary, dict) else {}
    timeline = scan_summary.get("scanning_timeline", {}) if isinstance(scan_summary, dict) else {}
    platform_rules_breakdown = _parse_rule_breakdown(inputs.get("platform_specific_rules", ""))
    common_rules_breakdown = _parse_rule_breakdown(inputs.get("common_rules", ""))

    total_findings = sum(len(items) for items in snippets.values())
    platform_counts = {
        platform: len(snippets[platform])
        for platform in _ordered_platform_names(snippets.keys())
    }

    env = Environment(loader=FileSystemLoader(state.htmltemplates_dir), autoescape=True)
    from utils.guidance_format import guidance_html
    env.filters['guidance'] = guidance_html
    template = env.get_template("report_modern.html")
    from core.report_document import presentation_context, cli_document, safe_snippets
    extra = presentation_context(document if document is not None else cli_document())
    output_text = template.render(
        **extra,
        reportTitle=config.get("title") or "Daksh SCRA Scan Report",
        reportSubTitle=config["subtitle"] if config["subtitle"].lower() != 'none' and config["subtitle"] != "" else None,
        reportDate=format_datetime(date_only=True),
        logoImagePath=f"data:image/svg+xml;base64,{encoded_logo_image.decode('utf-8')}",
        inputs=inputs,
        platform_rules_breakdown=platform_rules_breakdown,
        common_rules_breakdown=common_rules_breakdown,
        detection=detection,
        timeline=presentation_dates(timeline),
        snippets=safe_snippets(snippets),
        filepaths_aoi=filepaths_aoi,
        filepaths=filepaths,
        platform_counts=platform_counts,
        total_findings=total_findings,
    )

    report_output_path.parent.mkdir(parents=True, exist_ok=True)
    report_output_path.write_text(output_text, encoding="utf-8")
    return report_output_path, output_text



def _render_code_viewer(rows, highlight_enabled=True):
    """
    Render a list of (row_type, line_num, code_str) tuples as an HTML code viewer
    with a line-number gutter.  row_type is "match" or "context".
    """
    if not rows:
        return ""
    valid_lns = [r[1] for r in rows if isinstance(r[1], int)]
    ln_width = len(str(max(valid_lns))) if valid_lns else 1
    parts = ['<div class="code-viewer">']
    from core.evidence_highlights import highlighted_html
    enabled = str(highlight_enabled).lower() not in {'false', '0', 'no'}
    for row in rows:
        row_type, ln, code = row[:3]
        spans = row[3] if len(row) > 3 and enabled else []
        css = "cv-row cv-match" if row_type == "match" and enabled else "cv-row cv-ctx"
        ln_str = str(ln).rjust(ln_width) if isinstance(ln, int) else " " * ln_width
        parts.append(
            f'<div class="{css}">'
            f'<span class="cv-ln">{ln_str}</span>'
            f'<code class="cv-code">{highlighted_html(code, spans)}</code>'
            f'</div>'
        )
    parts.append('</div>')
    return "\n".join(parts)



def get_areas_of_interest(input_file, raw=None):
    json_path = Path(input_file) if input_file else None
    try:
        if raw is None:
            raw = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        logger.error("Failed to load AoI JSON %s: %s", json_path, exc)
        return {}

    grouped = defaultdict(list)
    from core.rdl.narratives import enrich_source_findings
    findings = enrich_source_findings(list(raw.values()) if isinstance(raw, dict) else raw)
    for item in findings:
        platform = item.get("platform", "UNKNOWN")
        confidence_score = _normalize_confidence_score(
            item.get("confidence_score"),
            default=_fallback_source_confidence(item),
        )
        snippet = {
            "platform": platform,
            "rulecount": item.get("rule_id", ""),
            "keyword": html.escape(item.get("rule_title", "")),
            "category": html.escape(item.get("category", "")),
            "issue_scope": html.escape(item.get("issue_scope", "")),
            "rule_desc": html.escape(item.get("rule_desc", "")),
            "issue_desc": html.escape(item.get("issue_desc", "")),
            "security_impact": html.escape(item.get("security_impact", "")),
            "dev_note": html.escape(item.get("developer_note", "")),
            "rev_note": html.escape(item.get("reviewer_note", "")),
            "confidence_score": confidence_score,
            "confidence_label": "",
            "logic_engine": html.escape(item.get("logic_engine", "")),
            "logic_source": html.escape(item.get("logic_source", "")),
            "logic_reason": html.escape(item.get("logic_reason", "")),
            "logic_trace": [html.escape(str(x)) for x in (item.get("logic_trace", []) or []) if str(x).strip()],
            "logic_consulted_files": [html.escape(str(x)) for x in (item.get("logic_consulted_files", []) or []) if str(x).strip()],
            "sources": [],
        }
        snippet["confidence_label"] = _confidence_label(snippet["confidence_score"])
        evidence = item.get("evidence", [])
        file_rows = _saved_evidence_rows(evidence)
        for src_file, rows in file_rows.items():
            rows_sorted = sorted(rows, key=lambda r: r[1] if isinstance(r[1], int) else 0)
            snippet["sources"].append({
                "source": src_file,
                "code": _render_code_viewer(rows_sorted, (item.get('scan_config') or {}).get('highlight_enabled', True)),
            })
        grouped[platform].append(snippet)
    return _ordered_platform_dict(grouped)





def get_filepaths_of_aoi(input_file):
    json_path = Path(input_file)
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            mapped = []
            for item in data:
                guidance = _path_guidance(item if isinstance(item, dict) else {})
                mapped.append({
                    "keyword": item.get("rule_title", ""),
                    "paths": item.get("filepath", []),
                    "confidence_score": _normalize_confidence_score(
                        item.get("confidence_score"),
                        default=_fallback_paths_confidence(item),
                    ),
                    "confidence_label": _confidence_label(_normalize_confidence_score(
                        item.get("confidence_score"),
                        default=_fallback_paths_confidence(item),
                    )),
                    **guidance,
                })
            return mapped
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        logger.error("Failed to load Filepaths AoI JSON %s: %s", json_path, exc)
    return []



def get_filepaths(input_file):
    json_path = Path(input_file)
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            formatted = []
            for item in data:
                if isinstance(item, dict):
                    path = item.get("path", "")
                    loc = item.get("loc")
                    formatted.append(f"{path}" + (f" (LOC: {loc})" if loc is not None else ""))
                else:
                    formatted.append(item)
            return formatted
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        logger.error("Failed to load filepaths JSON %s: %s", json_path, exc)
    return []


def get_analysis_results(input_file):
    json_path = Path(input_file)
    from core.analysis_dispatch import unique_observation_count
    from core.rdl.narratives import enrich_analysis
    data = enrich_analysis(_load_json_file(json_path, default={}, label="analysis summary") or {})
    if not isinstance(data, dict):
        return {"summary": {}, "results": []}

    summary_raw = data.get("summary", {})
    results_raw = data.get("results", [])
    if not isinstance(summary_raw, dict):
        summary_raw = {}
    if not isinstance(results_raw, list):
        results_raw = []
    file_cache = {}

    normalized_results = []
    for entry in results_raw:
        if not isinstance(entry, dict):
            continue
        target_type = str(entry.get("target_type", "platform")).strip().lower() or "platform"
        target = str(entry.get("target", "")).strip()
        platform = str(entry.get("platform", "")).strip()
        framework = str(entry.get("framework", "")).strip()
        score = _normalize_confidence_score(entry.get("confidence_score"), default=0)
        analysis_kind = str(entry.get("analysis_kind", "")).strip().lower()
        findings = entry.get("findings", [])
        if not isinstance(findings, list):
            findings = []

        normalized_findings = []
        for finding in findings[:50]:
            if not isinstance(finding, dict):
                continue
            f_score = _normalize_confidence_score(finding.get("confidence_score"), default=score)
            normalized_path = _enrich_path_context(finding.get("path", []) if isinstance(finding.get("path"), list) else [], file_cache)
            termination_nodes = [
                _enrich_path_step_context(node, file_cache)
                for node in (finding.get("termination_nodes", []) if isinstance(finding.get("termination_nodes"), list) else [])
                if isinstance(node, dict)
            ]
            normalized_findings.append({
                "id": str(finding.get("id", "")).strip(),
                "title": str(finding.get("title", "")).strip() or "Analyzer finding",
                "description": str(finding.get("description", "")).strip(),
                "analysis_kind": str(finding.get("analysis_kind", analysis_kind or "heuristic")).strip().lower(),
                "source": str(finding.get("source", "")).strip(),
                "sink": str(finding.get("sink", "")).strip(),
                "trace_chain": finding.get("trace_chain", []) if isinstance(finding.get("trace_chain"), list) else [],
                "path": normalized_path,
                "xref": finding.get("xref", []) if isinstance(finding.get("xref"), list) else [],
                "input_surface": finding.get("input_surface", {}) if isinstance(finding.get("input_surface"), dict) else {},
                "attack_vectors": finding.get("attack_vectors", []) if isinstance(finding.get("attack_vectors"), list) else [],
                "file": str(finding.get("file", "")).strip(),
                "function": str(finding.get("function", "")).strip(),
                "line": finding.get("line"),
                "source_file": str(finding.get("source_file", "")).strip(),
                "source_line": finding.get("source_line"),
                "sink_file": str(finding.get("sink_file", "")).strip(),
                "sink_line": finding.get("sink_line"),
                "termination_nodes": termination_nodes,
                "cross_file": bool(finding.get("cross_file", False)),
                "risk_score": finding.get("risk_score"),
                "priority_score": finding.get('priority_score', finding.get('risk_score')),
                "rating_basis": finding.get('rating_basis', ''),
                "build_scope": finding.get('build_scope', 'unresolved'),
                "severity": str(finding.get("severity", "")).strip(),
                "source_count": finding.get("source_count", 0),
                "confidence_score": f_score,
                "confidence_label": _confidence_label(f_score),
                "confidence_basis": finding.get('confidence_basis', ''),
                "path_step_count": finding.get('path_step_count', len(normalized_path)),
            })

        display_target = target
        if target_type == "platform":
            display_target = _format_platform_display_name(target)
        normalized_results.append({
            "target_type": target_type,
            "target": display_target,
            "platform": _format_platform_display_name(platform) if platform else "",
            "framework": framework,
            "engine": str(entry.get("engine", "")).strip(),
            "analysis_kind": analysis_kind or ("taint_flow" if str(entry.get("engine", "")).strip() == "dataflow_controlflow" else "heuristic"),
            "status": str(entry.get("status", "")).strip() or "completed",
            "confidence_score": score,
            "confidence_label": _confidence_label(score),
            "artifacts": entry.get("artifacts", {}) if isinstance(entry.get("artifacts"), dict) else {},
            "security_inventory": entry.get("security_inventory", {}) if isinstance(entry.get("security_inventory"), dict) else {"summary": {}, "vulnerabilities": [], "mitigations": [], "finding_reviews": [], "false_positives": [], "manual_reviews": []},
            "findings": normalized_findings,
        })

    taint_results = [item for item in normalized_results if item.get("engine") == "dataflow_controlflow"]
    fallback_results = [item for item in normalized_results if item.get("engine") != "dataflow_controlflow"]

    summary = {
        "enabled": bool(summary_raw.get("enabled", False)),
        "targets_total": int(summary_raw.get("targets_total", len(normalized_results)) or 0),
        "targets_analyzed": int(summary_raw.get("targets_analyzed", len(normalized_results)) or 0),
        "taint_targets": int(summary_raw.get("taint_targets", len(taint_results)) or 0),
        "findings_identified": int(summary_raw.get("findings_identified", unique_observation_count(normalized_results)) or 0),
        "validated_findings": int(summary_raw.get("validated_findings", sum(int(((x.get("security_inventory", {}) or {}).get("summary", {}) or {}).get("validated_findings", 0) or 0) for x in normalized_results)) or 0),
        "confirmed_vulnerabilities": int(summary_raw.get("confirmed_vulnerabilities", sum(len((x.get("security_inventory", {}) or {}).get("vulnerabilities", [])) for x in normalized_results)) or 0),
        "mitigated_implementations": int(summary_raw.get("mitigated_implementations", sum(len((x.get("security_inventory", {}) or {}).get("mitigations", [])) for x in normalized_results)) or 0),
        "suppressed_false_positives": int(summary_raw.get("suppressed_false_positives", sum(len((x.get("security_inventory", {}) or {}).get("false_positives", [])) for x in normalized_results)) or 0),
        "manual_review_recommended": int(summary_raw.get("manual_review_recommended", sum(int(((x.get("security_inventory", {}) or {}).get("summary", {}) or {}).get("manual_review_recommended", 0) or 0) for x in normalized_results)) or 0),
        "generated_at": str(summary_raw.get("generated_at", "")).strip(),
    }
    return {
        "summary": summary,
        "results": normalized_results,
        "taint_results": taint_results,
        "fallback_results": fallback_results,
    }



def get_summary(input_file):
    json_path = Path(input_file)
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        logger.error("Failed to load summary JSON %s: %s", json_path, exc)
        return ""

    lines = []
    inputs = data.get("inputs_received", {})
    det = data.get("detection_summary", {})
    timeline = data.get("scanning_timeline", {})

    lines.append("[+] Inputs Selected:")
    lines.append(f"    [-] Target Directory: {inputs.get('target_directory','')}")
    lines.append(f"    [-] Rule Selected: {inputs.get('rule_selected','')}")
    lines.append(f"    [-] File Types Selected: {inputs.get('filetypes_selected','')}")
    lines.append(f"    [-] Platform Specific Rules: {inputs.get('platform_specific_rules','')}")
    lines.append(f"    [-] Common Rules: {inputs.get('common_rules','')}")
    lines.append(f"    [-] Total Rules Loaded: {inputs.get('total_rules_loaded','')}")
    lines.append("")

    lines.append("[+] Detection Summary:")
    lines.append(f"    [-] Total Project Files Identified: {det.get('total_project_files_identified','')}")
    lines.append(f"    [-] Total Files Identified (Based on Selected Rule): {det.get('total_files_identified','')}")
    lines.append(f"    [-] Total Files Scanned (Based on Selected Rule): {det.get('total_files_scanned','')}")
    exts = det.get("file_extensions_identified", {})
    if exts:
        lines.append("    [-] File Extensions Identified (Based on Selected Rule):")
        for platform in _ordered_platform_names(exts.keys()):
            extensions = exts.get(platform, [])
            lines.append(f"        [-] {platform}: [{', '.join(extensions)}]")
    lines.append(f"    [-] Code Files - Areas-of-Interest (Rules Matched): {det.get('areas_of_interest_identified','')}")
    lines.append(f"    [-] File Paths - Areas-of-Interest (Rules Matched): {det.get('file_paths_areas_of_interest_identified','')}")
    if det.get('total_loc'):
        lines.append(f"    [-] Total LOC (effective): {det.get('total_loc')}")
    lines.append("")

    lines.append("[+] Scanning Timeline:")
    lines.append(f"    [-] Scan start time: {format_datetime(timeline.get('scan_start_time',''))}")
    lines.append(f"    [-] Scan end time: {format_datetime(timeline.get('scan_end_time',''))}")
    lines.append(f"    [-] Scan completed in: {timeline.get('scan_duration','')}")

    return html.escape("\n".join(lines))


# Generate the HTML and PDF reports
def gen_report(formats="html,pdf", include_multifile_pdf=True):
    from utils.output_mode import web_scan
    if web_scan():
        return
    from core.report_document import cli_document, render_document, render_html_package, render_json
    from core.report_word import render_word
    document = cli_document()
    selected = {value.strip().lower() for value in formats.split(',')}
    if 'json' in selected:
        output = Path(state.reports_dirpath) / 'scan' / 'json' / 'report.json'
        render_json(document, output)
        cli.section_print("[*] JSON Report:")
        print("     Path:", output)
    if 'html' in selected:
        outputs = render_html_package(document, state.htmlreport_Fpath)
        cli.section_print("[*] HTML Report (summary and linked detail files):")
        print("     Path:", state.htmlreport_Fpath)
        print("     Files:", len(outputs))
    if 'pdf' in selected:
        render_document(document, state.pdfreport_Fpath, 'pdf')
        cli.section_print("[*] PDF Report:")
        print("     Path:", state.pdfreport_Fpath)
    if 'docx' in selected:
        output = Path(state.reports_dirpath) / 'scan' / 'word' / 'report.docx'
        render_word(document, output)
        cli.section_print("[*] Word Report:")
        print("     Path:", output)


def _load_json_file(path, default=None, label="json"):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.error("Failed to load %s file %s: %s", label, path, exc)
        return default


def _load_yaml_file(path, default=None, label="yaml"):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except (OSError, yaml.YAMLError) as exc:
        logger.error("Failed to load %s file %s: %s", label, path, exc)
        return default


def _render_template(env, template_name, context, output_path):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    template = env.get_template(template_name)
    html = template.render(**presentation_dates(context))
    output_path.write_text(html, encoding="utf-8")
    return output_path


def gen_report_multifile(formats="html,pdf", output_dir=None, pdf_output_dir=None, expand_all_details_in_pdf=False):
    """Compatibility entry point using the complete shared saved-result renderer."""
    from core.report_document import cli_document, render_html_package, render_document
    document = cli_document()
    html_root = Path(output_dir) if output_dir else Path(state.reports_dirpath) / 'scan' / 'html' / 'multi-file'
    pdf_root = Path(pdf_output_dir) if pdf_output_dir else Path(state.reports_dirpath) / 'scan' / 'pdf' / 'multi-file'
    result = {}
    if 'html' in formats:
        result.update(html_root=html_root, html_pages=render_html_package(document, html_root / 'index.html'))
    if 'pdf' in formats:
        result.update(pdf_root=pdf_root, pdf_pages=[render_document(document, pdf_root / 'report-full.pdf', 'pdf')])
    return result


# Backward-compatible aliases for legacy camelCase callers.
genPdfReportModern = gen_pdf_report_modern
genHtmlReportModern = gen_html_report_modern
getAreasOfInterest = get_areas_of_interest
getFilePathsOfAOI = get_filepaths_of_aoi
getFilePaths = get_filepaths
getSummary = get_summary
genReport = gen_report
gen_report_multipage = gen_report_multifile
genReportMultifile = gen_report_multifile
genReportMultipage = gen_report_multifile
genPdfReportsFromJson = gen_pdf_reports_from_json
