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

logger = get_logger(__name__)


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
            print(f"    [-] Started at       : {start_dt.strftime('%Y-%m-%d %H:%M:%S')}")

        print("    [-] Rendering JSON-driven professional PDF report... ", end="", flush=True)
        spinner("start")

        report_context = _build_pdf_report_context()
        rendered_html = _render_pdf_html(report_context)
        temp_html_file = _write_temp_pdf_html(rendered_html)
        try:
            export_pdf_from_html(temp_html_file, pdf_path, expand_all_details=True)
        finally:
            try:
                temp_html_file.unlink(missing_ok=True)
            except OSError:
                pass

        spinner("stop")
        end_dt = datetime.now()
        elapsed = time.time() - started_at

        if print_header:
            print(f"    [-] Completed at     : {end_dt.strftime('%Y-%m-%d %H:%M:%S')}")
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

        page.goto(f"file://{html_file_path}", wait_until='load', timeout=timeout_ms)
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
            margin={"top": "20px", "bottom": "20px", "left": "20px", "right": "20px"}
        )

        browser.close()


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
):
    summary_json_path = Path(summary_json_path) if summary_json_path else Path(state.outputSummary_JSON)
    aoi_json_path = Path(aoi_json_path) if aoi_json_path else Path(state.outputAoI_JSON)
    filepaths_aoi_json_path = (
        Path(filepaths_aoi_json_path) if filepaths_aoi_json_path else Path(state.outputAoI_Fpaths_JSON)
    )
    filepaths_json_path = Path(filepaths_json_path) if filepaths_json_path else Path(state.output_Fpaths_JSON)
    analysis_json_path = Path(analysis_json_path) if analysis_json_path else Path(state.outputAnalysis_JSON)
    project_config_path = Path(project_config_path) if project_config_path else Path(state.projectConfig)

    scan_summary = _load_json_file(summary_json_path, default={}, label="scan summary") or {}
    aoi_raw = _load_json_file(aoi_json_path, default=[], label="areas of interest") or []
    filepaths_aoi = _load_json_file(filepaths_aoi_json_path, default=[], label="filepaths aoi") or []
    filepaths_all_raw = _load_json_file(filepaths_json_path, default=[], label="filepaths") or []
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
        # Build per-file code viewer rows (handles aggregated + context evidence).
        file_rows = defaultdict(list)
        seen_lines = defaultdict(set)
        if isinstance(evidence, list):
            for ev in evidence:
                if not isinstance(ev, dict):
                    continue
                ev_file = str(ev.get("file", "")).strip()
                if ev_file and ev_file not in files:
                    files.append(ev_file)
                if ev.get("aggregated"):
                    for m in ev.get("matches", []):
                        ln = m.get("line")
                        code = str(m.get("code", "")).rstrip()
                        if len(code) > 240:
                            code = code[:240] + "..."
                        if isinstance(ln, int) and ln not in seen_lines[ev_file]:
                            seen_lines[ev_file].add(ln)
                            file_rows[ev_file].append(("match", ln, code))
                else:
                    for ctx in ev.get("context_before", []):
                        ln = ctx.get("line")
                        code = str(ctx.get("code", "")).rstrip()
                        if isinstance(ln, int) and ln not in seen_lines[ev_file]:
                            seen_lines[ev_file].add(ln)
                            file_rows[ev_file].append(("context", ln, code))
                    ln = ev.get("line")
                    code = str(ev.get("code", "")).rstrip()
                    if len(code) > 240:
                        code = code[:240] + "..."
                    if code and isinstance(ln, int) and ln not in seen_lines[ev_file]:
                        seen_lines[ev_file].add(ln)
                        file_rows[ev_file].append(("match", ln, code))
                    for ctx in ev.get("context_after", []):
                        ln = ctx.get("line")
                        code = str(ctx.get("code", "")).rstrip()
                        if isinstance(ln, int) and ln not in seen_lines[ev_file]:
                            seen_lines[ev_file].add(ln)
                            file_rows[ev_file].append(("context", ln, code))

        evidence_samples = [
            {
                "file": src_file,
                "code": _render_code_viewer(
                    sorted(rows, key=lambda r: r[1] if isinstance(r[1], int) else 0)
                ),
            }
            for src_file, rows in list(file_rows.items())[:12]
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
            "developer_note": str(item.get("developer_note", "")).strip(),
            "reviewer_note": str(item.get("reviewer_note", "")).strip(),
            "rule_id": str(item.get("rule_id", "")).strip(),
            "evidence_count": evidence_count,
            "files": files[:8],
            "evidence_samples": evidence_samples[:12],
            "evidence_label": _infer_pdf_evidence_label(issue_scope, category, files),
            "confidence_score": confidence_score,
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

    report_title = config.get("title", "Daksh SCRA Scan Report")
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

    return {
        "generated_at": datetime.now().strftime("%b %d, %Y %H:%M"),
        "report_date": datetime.now().strftime("%b %d, %Y"),
        "logoImagePath": _load_report_logo_data_uri(),
        "reportTitle": report_title,
        "reportSubTitle": report_subtitle,
        "platform_filter": platform_filter,
        "cards": cards,
        "inputs": inputs,
        "platform_rules_breakdown": platform_rules_breakdown,
        "common_rules_breakdown": common_rules_breakdown,
        "detection": detection,
        "timeline": timeline,
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
    env = Environment(loader=FileSystemLoader(state.htmltemplates_dir))
    template = env.get_template("pdf_report.html")
    return template.render(**context)


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

    single_pdf_path.parent.mkdir(parents=True, exist_ok=True)

    context_all = _build_pdf_report_context(
        summary_json_path=summary_path,
        aoi_json_path=aoi_path,
        filepaths_aoi_json_path=filepaths_aoi_path,
        analysis_json_path=analysis_path if analysis_path.exists() else None,
        project_config_path=project_config_path,
    )
    rendered_html = _render_pdf_html(context_all)
    temp_html_file = _write_temp_pdf_html(rendered_html)
    try:
        export_pdf_from_html(temp_html_file, single_pdf_path, expand_all_details=True)
    finally:
        try:
            temp_html_file.unlink(missing_ok=True)
        except OSError:
            pass

    generated_platform_pdfs = []
    if include_multifile:
        if multi_pdf_root.exists():
            shutil.rmtree(multi_pdf_root, ignore_errors=True)
        multi_pdf_root.mkdir(parents=True, exist_ok=True)
        platforms_dir = multi_pdf_root / "platforms"
        platforms_dir.mkdir(parents=True, exist_ok=True)

        full_pdf_path = multi_pdf_root / "report-full.pdf"
        full_html = _render_pdf_html(context_all)
        full_html_path = _write_temp_pdf_html(full_html)
        try:
            export_pdf_from_html(full_html_path, full_pdf_path, expand_all_details=True)
        finally:
            try:
                full_html_path.unlink(missing_ok=True)
            except OSError:
                pass

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
            )
            platform_html = _render_pdf_html(platform_ctx)
            platform_html_path = _write_temp_pdf_html(platform_html)
            safe_name = re.sub(r"[^a-z0-9]+", "-", str(platform_name).lower()).strip("-") or "platform"
            platform_pdf_path = platforms_dir / f"{safe_name}.pdf"
            try:
                export_pdf_from_html(platform_html_path, platform_pdf_path, expand_all_details=True)
                generated_platform_pdfs.append(platform_pdf_path)
            finally:
                try:
                    platform_html_path.unlink(missing_ok=True)
                except OSError:
                    pass

    return {
        "json_root": json_root,
        "single_pdf": single_pdf_path,
        "multi_pdf_root": multi_pdf_root if include_multifile else None,
        "platform_pdfs": generated_platform_pdfs,
    }

def gen_html_report_modern(scan_summary, snippets, filepaths, filepaths_aoi, report_output_path):
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

    env = Environment(loader=FileSystemLoader(state.htmltemplates_dir))
    template = env.get_template("report_modern.html")
    output_text = template.render(
        reportTitle=config["title"],
        reportSubTitle=config["subtitle"] if config["subtitle"].lower() != 'none' and config["subtitle"] != "" else None,
        reportDate=datetime.now().strftime("%b %d, %Y"),
        logoImagePath=f"data:image/svg+xml;base64,{encoded_logo_image.decode('utf-8')}",
        inputs=inputs,
        platform_rules_breakdown=platform_rules_breakdown,
        common_rules_breakdown=common_rules_breakdown,
        detection=detection,
        timeline=timeline,
        snippets=snippets,
        filepaths_aoi=filepaths_aoi,
        filepaths=filepaths,
        platform_counts=platform_counts,
        total_findings=total_findings,
    )

    report_output_path.parent.mkdir(parents=True, exist_ok=True)
    report_output_path.write_text(output_text, encoding="utf-8")
    return report_output_path, output_text



def _render_code_viewer(rows):
    """
    Render a list of (row_type, line_num, code_str) tuples as an HTML code viewer
    with a line-number gutter.  row_type is "match" or "context".
    """
    if not rows:
        return ""
    valid_lns = [r[1] for r in rows if isinstance(r[1], int)]
    ln_width = len(str(max(valid_lns))) if valid_lns else 1
    parts = ['<div class="code-viewer">']
    for row_type, ln, code in rows:
        css = "cv-row cv-match" if row_type == "match" else "cv-row cv-ctx"
        ln_str = str(ln).rjust(ln_width) if isinstance(ln, int) else " " * ln_width
        parts.append(
            f'<div class="{css}">'
            f'<span class="cv-ln">{ln_str}</span>'
            f'<code class="cv-code">{html.escape(code or "")}</code>'
            f'</div>'
        )
    parts.append('</div>')
    return "\n".join(parts)



def get_areas_of_interest(input_file):
    json_path = Path(input_file)
    try:
        raw = json.loads(json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        logger.error("Failed to load AoI JSON %s: %s", json_path, exc)
        return {}

    grouped = defaultdict(list)
    findings = raw.values() if isinstance(raw, dict) else raw
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
            "dev_note": html.escape(item.get("developer_note", "")),
            "rev_note": html.escape(item.get("reviewer_note", "")),
            "confidence_score": confidence_score,
            "confidence_label": "",
            "sources": [],
        }
        snippet["confidence_label"] = _confidence_label(snippet["confidence_score"])
        evidence = item.get("evidence", [])
        # file -> list of (row_type, line_num, code_str); use seen set to avoid duplicate lines
        file_rows = defaultdict(list)
        seen_lines = defaultdict(set)
        for ev in evidence:
            if not isinstance(ev, dict):
                continue
            ev_file = str(ev.get("file", "")).strip()
            if ev.get("aggregated"):
                for m in ev.get("matches", []):
                    ln = m.get("line")
                    code = str(m.get("code", "")).rstrip()
                    if isinstance(ln, int) and ln not in seen_lines[ev_file]:
                        seen_lines[ev_file].add(ln)
                        file_rows[ev_file].append(("match", ln, code))
            else:
                for ctx in ev.get("context_before", []):
                    ln = ctx.get("line")
                    code = str(ctx.get("code", "")).rstrip()
                    if isinstance(ln, int) and ln not in seen_lines[ev_file]:
                        seen_lines[ev_file].add(ln)
                        file_rows[ev_file].append(("context", ln, code))
                ln = ev.get("line")
                code = str(ev.get("code", "")).rstrip()
                if code and isinstance(ln, int) and ln not in seen_lines[ev_file]:
                    seen_lines[ev_file].add(ln)
                    file_rows[ev_file].append(("match", ln, code))
                for ctx in ev.get("context_after", []):
                    ln = ctx.get("line")
                    code = str(ctx.get("code", "")).rstrip()
                    if isinstance(ln, int) and ln not in seen_lines[ev_file]:
                        seen_lines[ev_file].add(ln)
                        file_rows[ev_file].append(("context", ln, code))
        for src_file, rows in file_rows.items():
            rows_sorted = sorted(rows, key=lambda r: r[1] if isinstance(r[1], int) else 0)
            snippet["sources"].append({
                "source": src_file,
                "code": _render_code_viewer(rows_sorted),
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
    data = _load_json_file(json_path, default={}, label="analysis summary") or {}
    if not isinstance(data, dict):
        return {"summary": {}, "results": []}

    summary_raw = data.get("summary", {})
    results_raw = data.get("results", [])
    if not isinstance(summary_raw, dict):
        summary_raw = {}
    if not isinstance(results_raw, list):
        results_raw = []

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
            normalized_findings.append({
                "id": str(finding.get("id", "")).strip(),
                "title": str(finding.get("title", "")).strip() or "Analyzer finding",
                "description": str(finding.get("description", "")).strip(),
                "analysis_kind": str(finding.get("analysis_kind", analysis_kind or "heuristic")).strip().lower(),
                "source": str(finding.get("source", "")).strip(),
                "sink": str(finding.get("sink", "")).strip(),
                "trace_chain": finding.get("trace_chain", []) if isinstance(finding.get("trace_chain"), list) else [],
                "source_count": finding.get("source_count", 0),
                "confidence_score": f_score,
                "confidence_label": _confidence_label(f_score),
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
            "findings": normalized_findings,
        })

    taint_results = [item for item in normalized_results if item.get("engine") == "dataflow_controlflow"]
    fallback_results = [item for item in normalized_results if item.get("engine") != "dataflow_controlflow"]

    summary = {
        "enabled": bool(summary_raw.get("enabled", False)),
        "targets_total": int(summary_raw.get("targets_total", len(normalized_results)) or 0),
        "targets_analyzed": int(summary_raw.get("targets_analyzed", len(normalized_results)) or 0),
        "taint_targets": int(summary_raw.get("taint_targets", len(taint_results)) or 0),
        "findings_identified": int(summary_raw.get("findings_identified", sum(len(x.get("findings", [])) for x in normalized_results)) or 0),
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
    lines.append(f"    [-] Scan start time: {timeline.get('scan_start_time','')}")
    lines.append(f"    [-] Scan end time: {timeline.get('scan_end_time','')}")
    lines.append(f"    [-] Scan completed in: {timeline.get('scan_duration','')}")

    return html.escape("\n".join(lines))


# Generate the HTML and PDF reports
def gen_report(formats="html,pdf", include_multifile_pdf=True):
    multifile_result = None
    state.htmlreport_Fpath.parent.mkdir(parents=True, exist_ok=True)

    snippets = get_areas_of_interest(state.outputAoI_JSON)
    filepaths_aoi = get_filepaths_of_aoi(state.outputAoI_Fpaths_JSON)
    filepaths = get_filepaths(state.output_Fpaths_JSON)
    scan_summary_data = _load_json_file(state.scanSummary_Fpath, default={}, label="scan summary") or {}

    html_report_output_path = state.htmlreport_Fpath
    pdf_report_path = state.pdfreport_Fpath

    htmlfile = None
    single_start = cutils.get_now()
    single_elapsed_start = time.time()

    if "html" in formats or "pdf" in formats:
        render_result = gen_html_report_modern(
            scan_summary_data,
            snippets,
            filepaths,
            filepaths_aoi,
            html_report_output_path
        )
        if render_result:
            htmlfile, _ = render_result
    single_end = cutils.get_now()
    single_elapsed = time.time() - single_elapsed_start

    if isinstance(formats, str):
        formats_csv = ",".join([fmt.strip() for fmt in formats.split(",") if fmt.strip()]) or "html,pdf"
    else:
        formats_csv = "html,pdf"

    # Multi-file HTML generation (always run when html in formats)
    mp_html_result = None
    mp_html_started = mp_html_completed = None
    mp_html_hours = mp_html_minutes = 0
    mp_html_seconds = mp_html_milliseconds = "0"
    if "html" in formats_csv:
        mp_html_started = cutils.get_now()
        mp_html_elapsed_start = time.time()
        try:
            mp_html_result = gen_report_multifile(
                formats="html",
                output_dir=Path(state.reports_dirpath) / "scan" / "html" / "multi-file",
                pdf_output_dir=Path(state.reports_dirpath) / "scan" / "pdf" / "multi-file",
                expand_all_details_in_pdf=True,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            logger.error("Multi-file HTML report generation failed: %s", exc)
        mp_html_hours, mp_html_rem = divmod(time.time() - mp_html_elapsed_start, 3600)
        mp_html_minutes, mp_html_sec = divmod(mp_html_rem, 60)
        mp_html_seconds, mp_html_milliseconds = str(mp_html_sec).split('.')
        mp_html_completed = cutils.get_now()

    # Multi-file PDF generation (only when pdf in formats and not suppressed)
    mp_pdf_result = None
    mp_pdf_started = mp_pdf_completed = None
    mp_pdf_hours = mp_pdf_minutes = 0
    mp_pdf_seconds = mp_pdf_milliseconds = "0"
    if "pdf" in formats_csv and include_multifile_pdf:
        mp_pdf_started = cutils.get_now()
        mp_pdf_elapsed_start = time.time()
        try:
            mp_pdf_result = gen_report_multifile(
                formats="pdf",
                output_dir=Path(state.reports_dirpath) / "scan" / "html" / "multi-file",
                pdf_output_dir=Path(state.reports_dirpath) / "scan" / "pdf" / "multi-file",
                expand_all_details_in_pdf=True,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            logger.error("Multi-file PDF report generation failed: %s", exc)
        mp_pdf_hours, mp_pdf_rem = divmod(time.time() - mp_pdf_elapsed_start, 3600)
        mp_pdf_minutes, mp_pdf_sec = divmod(mp_pdf_rem, 60)
        mp_pdf_seconds, mp_pdf_milliseconds = str(mp_pdf_sec).split('.')
        mp_pdf_completed = cutils.get_now()

    # Unified multifile_result for downstream checks (html_root from html pass, pdf_root from pdf pass)
    multifile_result = {}
    if mp_html_result:
        multifile_result.update(mp_html_result)
    if mp_pdf_result:
        multifile_result.update(mp_pdf_result)

    # Single-file HTML timing
    sf_hours = int(single_elapsed // 3600)
    sf_minutes = int((single_elapsed % 3600) // 60)
    _sf_sec_parts = str(single_elapsed % 60).split('.')
    sf_seconds = _sf_sec_parts[0]
    sf_milliseconds = _sf_sec_parts[1] if len(_sf_sec_parts) > 1 else "0"

    # Single-file PDF generation (suppress internal header; timing captured here)
    pdf_sf_start = pdf_sf_end = None
    pdf_sf_elapsed = 0.0
    if "pdf" in formats and htmlfile:
        _, pdf_sf_start, pdf_sf_end, pdf_sf_elapsed = gen_pdf_report_modern(htmlfile, pdf_report_path, print_header=False)
    pdf_sf_hours = int(pdf_sf_elapsed // 3600)
    pdf_sf_minutes = int((pdf_sf_elapsed % 3600) // 60)
    _pdf_sf_sec_parts = str(pdf_sf_elapsed % 60).split('.')
    pdf_sf_seconds = _pdf_sf_sec_parts[0]
    pdf_sf_milliseconds = _pdf_sf_sec_parts[1] if len(_pdf_sf_sec_parts) > 1 else "0"

    # Report path output
    if "html" in formats:
        cli.section_print("[*] HTML Report:")
        if htmlfile:
            print("     [-] Single-file:")
            print("         Path      : " + re.sub(str(state.root_dir), "", str(htmlfile)))
            print("         Started   : " + single_start.strftime('%Y-%m-%d %H:%M:%S'))
            print("         Completed : " + single_end.strftime('%Y-%m-%d %H:%M:%S'))
            print("         Time      : {:0>2}Hr:{:0>2}Min:{:0>2}s:{}ms".format(sf_hours, sf_minutes, sf_seconds, sf_milliseconds[:3]))
        if mp_html_result and mp_html_result.get("html_root") and mp_html_started:
            print("     [-] Multi-file:")
            print("         Path      : " + re.sub(str(state.root_dir), "", str(mp_html_result["html_root"] / "index.html")))
            print("         Started   : " + mp_html_started.strftime('%Y-%m-%d %H:%M:%S'))
            print("         Completed : " + mp_html_completed.strftime('%Y-%m-%d %H:%M:%S'))
            print("         Time      : {:0>2}Hr:{:0>2}Min:{:0>2}s:{}ms".format(int(mp_html_hours), int(mp_html_minutes), mp_html_seconds, mp_html_milliseconds[:3]))

    if "pdf" in formats:
        cli.section_print("[*] PDF Report:")
        if htmlfile:
            print("     [-] Single-file:")
            print("         Path      : " + re.sub(str(state.root_dir), "", str(pdf_report_path)))
            if pdf_sf_start:
                print("         Started   : " + pdf_sf_start.strftime('%Y-%m-%d %H:%M:%S'))
            if pdf_sf_end:
                print("         Completed : " + pdf_sf_end.strftime('%Y-%m-%d %H:%M:%S'))
            print("         Time      : {:0>2}Hr:{:0>2}Min:{:0>2}s:{}ms".format(pdf_sf_hours, pdf_sf_minutes, pdf_sf_seconds, pdf_sf_milliseconds[:3]))
        if mp_pdf_result and mp_pdf_result.get("pdf_root") and mp_pdf_started:
            print("     [-] Multi-file:")
            pdf_count = "({} PDF(s))".format(len(mp_pdf_result["pdf_pages"])) if mp_pdf_result.get("pdf_pages") else ""
            print("         Path      : " + re.sub(str(state.root_dir), "", str(mp_pdf_result["pdf_root"])) + (" " + pdf_count if pdf_count else ""))
            print("         Started   : " + mp_pdf_started.strftime('%Y-%m-%d %H:%M:%S'))
            print("         Completed : " + mp_pdf_completed.strftime('%Y-%m-%d %H:%M:%S'))
            print("         Time      : {:0>2}Hr:{:0>2}Min:{:0>2}s:{}ms".format(int(mp_pdf_hours), int(mp_pdf_minutes), mp_pdf_seconds, mp_pdf_milliseconds[:3]))

    cli.section_print("[*] Structured Reports:")
    if os.path.isfile(state.outputRecSummary_JSON):
        print("     [-] Reconnaissance Summary (JSON):", re.sub(str(state.root_dir), "", str(state.outputRecSummary_JSON)))
    if os.path.isfile(state.outputAoI_JSON):
        print("     [-] Areas of Interest (AoI) JSON:", re.sub(str(state.root_dir), "", str(state.outputAoI_JSON)))
    if os.path.isfile(state.outputAoI_Fpaths_JSON):
        print("     [-] Filepaths (AoI) JSON:", re.sub(str(state.root_dir), "", str(state.outputAoI_Fpaths_JSON)))
    if os.path.isfile(state.output_Fpaths_JSON):
        print("     [-] All Discovered Files (JSON):", re.sub(str(state.root_dir), "", str(state.output_Fpaths_JSON)))
    if os.path.isfile(state.outputAnalysis_JSON):
        print("     [-] Analyzer Results (JSON):", re.sub(str(state.root_dir), "", str(state.outputAnalysis_JSON)))

    print("\nNote: The tool generates reports in HTML and PDF formats, with JSON available for structured data. "
          "Reports continue to be refined with each iteration.")


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
    html = template.render(**context)
    output_path.write_text(html, encoding="utf-8")
    return output_path


def gen_report_multifile(formats="html,pdf", output_dir=None, pdf_output_dir=None, expand_all_details_in_pdf=False):
    """
    Experimental multi-file report generator (keeps existing single-file report untouched).

    Creates a lightweight index + per-section pages to reduce HTML/PDF size for large scans.
    """
    started_at = time.time()
    output_root = Path(output_dir) if output_dir else Path(state.reports_dirpath) / "scan" / "html" / "multi-file"
    pdf_output_root = Path(pdf_output_dir) if pdf_output_dir else Path(state.reports_dirpath) / "scan" / "pdf" / "multi-file"
    aoi_dir = output_root / "aoi"
    filepaths_dir = output_root / "filepaths"

    # Clean previous multi-file output to avoid stale links/files
    if output_root.exists():
        shutil.rmtree(output_root, ignore_errors=True)

    # Setup templating (looks in v2 folder first, then falls back to legacy templates)
    env = Environment(
        loader=FileSystemLoader(
            [state.htmltemplates_dir / "v2", state.htmltemplates_dir]
        )
    )

    config = _load_yaml_file(state.projectConfig, default={}, label="project config") or {}
    scan_summary = _load_json_file(state.scanSummary_Fpath, default={}, label="scan summary") or {}
    logo_image_path = None
    try:
        with open(state.staticLogo, "rb") as f:
            encoded_logo_image = base64.b64encode(f.read()).decode("utf-8")
            logo_image_path = f"data:image/svg+xml;base64,{encoded_logo_image}"
    except OSError as exc:
        logger.error("Failed to load logo image %s: %s", state.staticLogo, exc)

    snippets = get_areas_of_interest(state.outputAoI_JSON)
    filepaths_aoi = get_filepaths_of_aoi(state.outputAoI_Fpaths_JSON)
    filepaths = get_filepaths(state.output_Fpaths_JSON)
    summary_text = get_summary(state.outputSummary_JSON)
    recon_text = ""
    if Path(state.outputRecSummary_JSON).exists():
        try:
            recon_text = Path(state.outputRecSummary_JSON).read_text(encoding="utf-8")
        except OSError as exc:
            logger.error("Failed to load recon summary json %s: %s", state.outputRecSummary_JSON, exc)

    formats_set = {fmt.strip() for fmt in formats.lower().split(",") if fmt}

    detection = scan_summary.get("detection_summary", {})
    inputs = scan_summary.get("inputs_received", {})
    timeline = scan_summary.get("scanning_timeline", {})

    cache_bust = f"?v={int(time.time())}"

    links_root = {
        "home": f"./index.html{cache_bust}",
        "aoi_index": f"./{aoi_dir.name}/index.html{cache_bust}",
        "filepaths_aoi": f"./{filepaths_dir.name}/filepaths_aoi.html{cache_bust}",
        "filepaths_all": f"./{filepaths_dir.name}/filepaths_all.html{cache_bust}",
    }

    overview_cards = [
        {"label": "Total project files", "value": detection.get("total_project_files_identified", "-")},
        {"label": "Files identified for scanning", "value": detection.get("total_files_identified", "-")},
        {"label": "Files scanned", "value": detection.get("total_files_scanned", "-")},
        {"label": "Code AOI matched", "value": detection.get("areas_of_interest_identified", "-")},
        {"label": "Path AOI matched", "value": detection.get("file_paths_areas_of_interest_identified", "-")},
        {"label": "Total rules loaded", "value": inputs.get("total_rules_loaded", "-")},
    ]
    if detection.get("total_loc"):
        overview_cards.append({
            "label": "Total LOC (effective)",
            "value": detection.get("total_loc", "-"),
            "href": links_root.get("filepaths_all")
        })

    platforms = []
    for platform, entries in snippets.items():
        platforms.append({
            "name": platform,
            "count": len(entries),
            # Href from main index (root)
            "href_index": f"./{aoi_dir.name}/{platform.lower()}.html{cache_bust}",
            # Href from aoi index (inside /aoi)
            "href_aoi": f"./{platform.lower()}.html{cache_bust}",
        })

    platforms_from_root = [
        {"name": platform["name"], "href": f"./{aoi_dir.name}/{platform['name'].lower()}.html{cache_bust}"}
        for platform in platforms
    ]
    platforms_from_aoi = [
        {"name": platform["name"], "href": f"./{platform['name'].lower()}.html{cache_bust}"}
        for platform in platforms
    ]
    platforms_from_filepaths = [
        {"name": platform["name"], "href": f"../{aoi_dir.name}/{platform['name'].lower()}.html{cache_bust}"}
        for platform in platforms
    ]

    # Render index/overview
    index_ctx = {
        "config": config,
        "overview_cards": overview_cards,
        "platforms": platforms,
        "summary_text": summary_text,
        "recon_text": recon_text,
        "timeline": timeline,
        "links": links_root,
        "nav_links": links_root,
        "platform_nav": platforms_from_root,
        "active_nav": "home",
        "logoImagePath": logo_image_path,
        "generated_at": datetime.now().strftime("%b %d, %Y %H:%M"),
    }
    index_path = _render_template(env, "index.html", index_ctx, output_root / "index.html")

    # Render AOI index
    aoi_index_ctx = {
        "platforms": platforms,
        "back_link": "../index.html",
        "nav_links": {
            "home": f"../index.html{cache_bust}",
            "aoi_index": f"./index.html{cache_bust}",
            "filepaths_aoi": f"../{filepaths_dir.name}/filepaths_aoi.html{cache_bust}",
            "filepaths_all": f"../{filepaths_dir.name}/filepaths_all.html{cache_bust}",
        },
        "platform_nav": platforms_from_aoi,
        "active_nav": "aoi_index",
        "logoImagePath": logo_image_path,
        "generated_at": index_ctx["generated_at"],
    }
    aoi_index_path = _render_template(env, "aoi_index.html", aoi_index_ctx, aoi_dir / "index.html")

    # Render per-platform AOI pages
    platform_pages = []
    for platform, entries in snippets.items():
        ctx = {
            "platform": platform,
            "entries": entries,
            "back_link": "../index.html",
            "nav_links": {
                "home": f"../index.html{cache_bust}",
                "aoi_index": f"./index.html{cache_bust}",
                "filepaths_aoi": f"../{filepaths_dir.name}/filepaths_aoi.html{cache_bust}",
                "filepaths_all": f"../{filepaths_dir.name}/filepaths_all.html{cache_bust}",
            },
            "platform_nav": platforms_from_aoi,
            "active_nav": "aoi_index",
            "logoImagePath": logo_image_path,
            "generated_at": index_ctx["generated_at"],
        }
        page_path = _render_template(env, "aoi_platform.html", ctx, aoi_dir / f"{platform.lower()}.html")
        platform_pages.append(page_path)

    # Render AOI filepaths and all filepaths pages
    _render_template(
        env,
        "filepaths_aoi.html",
        {
            "items": filepaths_aoi,
            "back_link": "../index.html",
            "nav_links": {
                "home": f"../index.html{cache_bust}",
                "aoi_index": f"../{aoi_dir.name}/index.html{cache_bust}",
                "filepaths_aoi": f"./filepaths_aoi.html{cache_bust}",
                "filepaths_all": f"./filepaths_all.html{cache_bust}",
            },
            "platform_nav": platforms_from_filepaths,
            "active_nav": "filepaths_aoi",
            "logoImagePath": logo_image_path,
            "generated_at": index_ctx["generated_at"],
        },
        filepaths_dir / "filepaths_aoi.html",
    )

    _render_template(
        env,
        "filepaths_all.html",
        {
            "filepaths": filepaths,
            "back_link": "../index.html",
            "nav_links": {
                "home": f"../index.html{cache_bust}",
                "aoi_index": f"../{aoi_dir.name}/index.html{cache_bust}",
                "filepaths_aoi": f"./filepaths_aoi.html{cache_bust}",
                "filepaths_all": f"./filepaths_all.html{cache_bust}",
            },
            "platform_nav": platforms_from_filepaths,
            "active_nav": "filepaths_all",
            "logoImagePath": logo_image_path,
            "generated_at": index_ctx["generated_at"],
        },
        filepaths_dir / "filepaths_all.html",
    )

    generated_html = [index_path, aoi_index_path, *platform_pages, filepaths_dir / "filepaths_aoi.html", filepaths_dir / "filepaths_all.html"]

    # Optional PDFs (JSON-driven and print-optimized)
    generated_pdfs = []
    if "pdf" in formats_set:
        if pdf_output_root.exists():
            shutil.rmtree(pdf_output_root, ignore_errors=True)
        pdf_output_root.mkdir(parents=True, exist_ok=True)

        context_all = _build_pdf_report_context()
        full_html = _render_pdf_html(context_all)
        full_html_path = _write_temp_pdf_html(full_html)
        full_pdf_path = pdf_output_root / "report-full.pdf"
        try:
            export_pdf_from_html(full_html_path, full_pdf_path, expand_all_details=expand_all_details_in_pdf)
            generated_pdfs.append(full_pdf_path)
        except (OSError, RuntimeError, ValueError) as exc:
            logger.error("Multipage PDF generation failed for full report: %s", exc)
        finally:
            try:
                full_html_path.unlink(missing_ok=True)
            except OSError:
                pass

        platforms_dir = pdf_output_root / "platforms"
        platforms_dir.mkdir(parents=True, exist_ok=True)
        for platform in snippets.keys():
            context_platform = _build_pdf_report_context(platform_filter=platform)
            platform_html = _render_pdf_html(context_platform)
            platform_html_path = _write_temp_pdf_html(platform_html)
            safe_name = re.sub(r"[^a-z0-9]+", "-", platform.lower()).strip("-") or "platform"
            platform_pdf_path = platforms_dir / f"{safe_name}.pdf"
            try:
                export_pdf_from_html(platform_html_path, platform_pdf_path, expand_all_details=expand_all_details_in_pdf)
                generated_pdfs.append(platform_pdf_path)
            except (OSError, RuntimeError, ValueError) as exc:
                logger.error("Multipage PDF generation failed for platform %s: %s", platform, exc)
            finally:
                try:
                    platform_html_path.unlink(missing_ok=True)
                except OSError:
                    pass

    return {
        "html_root": output_root,
        "pdf_root": pdf_output_root if generated_pdfs else None,
        "html_pages": generated_html,
        "pdf_pages": generated_pdfs,
    }


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
