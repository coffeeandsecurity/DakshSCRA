# Standard libraries
import base64
import html
import os
import re
import sys
import time
import shutil
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
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import PythonLexer
from pygments_better_html import BetterHtmlFormatter
from playwright.sync_api import sync_playwright


# Local application imports
import state.runtime_state as state
import utils.cli_utils as cli
from utils.cli_utils import spinner
from utils.log_utils import get_logger

logger = get_logger(__name__)


def gen_pdf_report_modern(html_path, pdf_path):
    try:
        started_at = time.time()
        cli.section_print(f"[*] Modern PDF Report Generation")

        print(f"    [-] Started at       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("    [-] Rendering expanded modern HTML to PDF... ", end="", flush=True)
        spinner("start")

        export_pdf_from_html(html_path, pdf_path, expand_all_details=True)

        spinner("stop")
        print(f"    [-] Completed at     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        hours, rem = divmod(time.time() - started_at, 3600)
        minutes, seconds = divmod(rem, 60)
        seconds, milliseconds = str(seconds).split('.')
        print("    [-] Total time taken : {:0>2}Hr:{:0>2}Min:{:0>2}s:{}ms".format(int(hours), int(minutes), seconds, milliseconds[:3]))

        return pdf_path

    except (OSError, RuntimeError, ValueError) as e:
        spinner("stop")
        logger.exception("Error during modern PDF generation: %s", e)

    return pdf_path


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

    total_findings = sum(len(items) for items in snippets.values())
    platform_counts = {
        platform: len(items)
        for platform, items in snippets.items()
    }

    env = Environment(loader=FileSystemLoader(state.htmltemplates_dir))
    template = env.get_template("report_modern.html")
    output_text = template.render(
        reportTitle=config["title"],
        reportSubTitle=config["subtitle"] if config["subtitle"].lower() != 'none' and config["subtitle"] != "" else None,
        reportDate=datetime.now().strftime("%b %d, %Y"),
        logoImagePath=f"data:image/jpg;base64,{encoded_logo_image.decode('utf-8')}",
        inputs=inputs,
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



def _highlight_code(statements):
    code = "".join(statements)
    # Make the style 'default' to show the code snippet in grey background
    code = highlight(code, PythonLexer(), BetterHtmlFormatter(linenos="table", noclasses=True, style='github-dark'))
    return code



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
            "sources": [],
        }
        evidence = item.get("evidence", [])
        file_groups = defaultdict(list)
        for ev in evidence:
            file_groups[ev.get("file", "")].append((ev.get("line", 0), ev.get("code", "")))
        for src_file, entries in file_groups.items():
            entries = sorted(entries, key=lambda x: x[0] if isinstance(x[0], int) else 0)
            statements = [f"[{ln}] {code}\n" for ln, code in entries]
            snippet["sources"].append({
                "source": src_file,
                "code": _highlight_code(statements)
            })
        grouped[platform].append(snippet)
    return grouped





def get_filepaths_of_aoi(input_file):
    json_path = Path(input_file)
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            mapped = []
            for item in data:
                mapped.append({
                    "keyword": item.get("rule_title", ""),
                    "paths": item.get("filepath", [])
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
        for platform, extensions in exts.items():
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
def gen_report(formats="html,pdf"):
    multipage_result = None
    started_at = time.time()
    state.htmlreport_Fpath.parent.mkdir(parents=True, exist_ok=True)
    cli.section_print("[*] HTML Report Generation")
    single_start = datetime.now()
    print(f"    [-] Started at       : {single_start.strftime('%Y-%m-%d %H:%M:%S')}")

    snippets = get_areas_of_interest(state.outputAoI_JSON)
    filepaths_aoi = get_filepaths_of_aoi(state.outputAoI_Fpaths_JSON)
    filepaths = get_filepaths(state.output_Fpaths_JSON)
    scan_summary_data = _load_json_file(state.scanSummary_Fpath, default={}, label="scan summary") or {}

    html_report_output_path = state.htmlreport_Fpath
    pdf_report_path = state.pdfreport_Fpath

    htmlfile = None

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
    single_end = datetime.now()
    print(f"    [-] Completed at     : {single_end.strftime('%Y-%m-%d %H:%M:%S')}")
    hours, rem = divmod(time.time() - started_at, 3600)
    minutes, seconds = divmod(rem, 60)
    seconds, milliseconds = str(seconds).split('.')
    print("    [-] Total time taken : {:0>2}Hr:{:0>2}Min:{:0>2}s:{}ms".format(int(hours), int(minutes), seconds, milliseconds[:3]))

    if isinstance(formats, str):
        formats_csv = ",".join([fmt.strip() for fmt in formats.split(",") if fmt.strip()]) or "html,pdf"
    else:
        formats_csv = "html,pdf"

    # Multi-page timing
    mp_started = datetime.now()
    mp_elapsed_start = time.time()
    try:
        multipage_result = gen_report_multipage(
            formats=formats_csv,
            output_dir=Path(state.root_dir) / "reports/html/multi-page",
            pdf_output_dir=Path(state.root_dir) / "reports/pdf/multi-page",
            expand_all_details_in_pdf=True,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        logger.error("Multipage report generation failed: %s", exc)
    mp_hours, mp_rem = divmod(time.time() - mp_elapsed_start, 3600)
    mp_minutes, mp_seconds = divmod(mp_rem, 60)
    mp_seconds, mp_milliseconds = str(mp_seconds).split('.')
    mp_completed = datetime.now()

    if "pdf" in formats and htmlfile:
        gen_pdf_report_modern(htmlfile, pdf_report_path)

    # Report path output
    if "html" in formats:
        cli.section_print("[*] HTML Report:")
        if htmlfile:
            print("     [-] HTML Report Path : " + re.sub(str(state.root_dir), "", str(htmlfile)))
        if multipage_result and multipage_result.get("html_root"):
            print("     [-] Multi-page HTML Started at  : " + mp_started.strftime('%Y-%m-%d %H:%M:%S'))
            print("     [-] Multi-page HTML Completed at: " + mp_completed.strftime('%Y-%m-%d %H:%M:%S'))
            print("     [-] Multi-page HTML time       : {:0>2}Hr:{:0>2}Min:{:0>2}s:{}ms".format(int(mp_hours), int(mp_minutes), mp_seconds, mp_milliseconds[:3]))
            print("     [-] Multi-page HTML report     : " + re.sub(str(state.root_dir), "", str(multipage_result["html_root"] / "index.html")))
            if multipage_result.get("pdf_root"):
                print("     [-] Multi-page PDF root        : " + re.sub(str(state.root_dir), "", str(multipage_result["pdf_root"])))
            if multipage_result.get("pdf_pages"):
                print("     [-] Multi-page PDFs generated  : " + str(len(multipage_result["pdf_pages"])))

    if "pdf" in formats:
        cli.section_print("[*] PDF Report:")
        if htmlfile:
            print("     [-] PDF Report Path : " + re.sub(str(state.root_dir), "", str(pdf_report_path)))
        if multipage_result and multipage_result.get("pdf_root"):
            print("     [-] Multi-page PDF root : " + re.sub(str(state.root_dir), "", str(multipage_result["pdf_root"])))
        if multipage_result and multipage_result.get("pdf_pages"):
            print("     [-] Multi-page PDFs     : " + str(len(multipage_result["pdf_pages"])))

    cli.section_print("[*] Structured Reports:")
    if os.path.isfile(state.outputRecSummary_JSON):
        print("     [-] Reconnaissance Summary (JSON):", re.sub(str(state.root_dir), "", str(state.outputRecSummary_JSON)))
    if os.path.isfile(state.outputAoI_JSON):
        print("     [-] Areas of Interest (AoI) JSON:", re.sub(str(state.root_dir), "", str(state.outputAoI_JSON)))
    if os.path.isfile(state.outputAoI_Fpaths_JSON):
        print("     [-] Filepaths (AoI) JSON:", re.sub(str(state.root_dir), "", str(state.outputAoI_Fpaths_JSON)))
    if os.path.isfile(state.output_Fpaths_JSON):
        print("     [-] All Discovered Files (JSON):", re.sub(str(state.root_dir), "", str(state.output_Fpaths_JSON)))

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


def gen_report_multipage(formats="html,pdf", output_dir=None, pdf_output_dir=None, expand_all_details_in_pdf=False):
    """
    Experimental multi-page report generator (keeps existing single-page report untouched).

    Creates a lightweight index + per-section pages to reduce HTML/PDF size for large scans.
    """
    started_at = time.time()
    output_root = Path(output_dir) if output_dir else Path(state.root_dir) / "reports/html/multi-page"
    pdf_output_root = Path(pdf_output_dir) if pdf_output_dir else Path(state.root_dir) / "reports/pdf/multi-page"
    aoi_dir = output_root / "aoi"
    filepaths_dir = output_root / "filepaths"

    # Clean previous multipage output to avoid stale links/files
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
            logo_image_path = f"data:image/jpg;base64,{encoded_logo_image}"
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

    # Optional PDFs (one per page to avoid giant single PDF)
    generated_pdfs = []
    if "pdf" in formats_set:
        if pdf_output_root.exists():
            shutil.rmtree(pdf_output_root, ignore_errors=True)
        for html_page in generated_html:
            rel = html_page.relative_to(output_root)
            pdf_page = (pdf_output_root / rel).with_suffix(".pdf")
            pdf_page.parent.mkdir(parents=True, exist_ok=True)
            try:
                export_pdf_from_html(html_page, pdf_page, expand_all_details=expand_all_details_in_pdf)
                generated_pdfs.append(pdf_page)
            except (OSError, RuntimeError, ValueError) as exc:
                logger.error("Multipage PDF generation failed for %s: %s", html_page, exc)

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
genReportMultipage = gen_report_multipage
