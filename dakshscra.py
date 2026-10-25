# Standard libraries
import argparse
import atexit
from utils.output_mode import web_scan
import fnmatch
import inspect
import json
import os
import re
import sys
import threading
import time
from datetime import datetime
from os import path  # This lowercase path to be used only to validate whether a directory exists
from pathlib import Path  # Resolve the Windows / macOS / Linux path issue
from uuid import uuid4

# Local application imports
import core.discovery as discover
import core.estimator as estimate
from core.effort import DOMAINS as EFFORT_DOMAINS
import core.parser as parser
import core.recon as rec
import core.reports as report
from core.analysis import report as analysis_report
from core import analysis_dispatch
from core.rdl.shadow import default_shadow_runner, summarize_shadow_records
from core.rdl.selection import configure_engines

from core.analysis.php import analyzer as php_analysis
from core.analysis.dotnet import analyzer as dotnet_analysis
from core.analysis.java import analyzer as java_analysis
from core.analysis.python import analyzer as py_analysis
from core.analysis.javascript import analyzer as js_analysis
from core.analysis.golang import analyzer as go_analysis
from core.analysis.ruby import analyzer as ruby_analysis
from core.analysis.kotlin import analyzer as kotlin_analysis
from core.analysis.c import analyzer as c_analysis
from core.analysis.cpp import analyzer as cpp_analysis
from core.analysis.mobile import android as android_analysis
from core.analysis.mobile import ios as ios_analysis
from core.analysis.mobile import flutter as flutter_analysis
from core.analysis.mobile import reactnative as reactnative_analysis
from core.analysis.mobile import ionic as ionic_analysis
from core.analysis.mobile import cordova as cordova_analysis
from core.analysis.mobile import nativescript as nativescript_analysis
from core.analysis.mobile import xamarin as xamarin_analysis
from core.analysis.mobile import maui as maui_analysis
from core.analysis.mobile import kmp as kmp_analysis

import state.constants as constants
import state.runtime_state as state

import utils.cli_utils as cli
import utils.config_utils as cutils
import utils.file_utils as futils
import utils.result_utils as result
import utils.rules_utils as rutils
import utils.review_utils as review_utils
import utils.string_utils as strutils
import utils.suppression_utils as supp
from utils.decision_trace import append_trace, cleanup_trace_dir, cleanup_trace_dir, cleanup_trace_dir
from utils.cli_utils import spinner
from utils.config_utils import get_tool_version
from utils.scan_state_utils import ScanStateManager


version = get_tool_version()

# ---- Initilisation -----
root_dir = os.path.dirname(os.path.realpath(__file__))
state.root_dir = root_dir         # initialise global root directory which is referenced at multiple locations
# ------------------------- #

args = cli.DakshArgumentParser(
    prog="dakshscra.py",
    description=(
        "Source Code Review Assist for rule-based scanning, reconnaissance,\n"
        "and effort estimation."
    ),
    formatter_class=cli.DakshHelpFormatter,
    epilog=(
        "Examples:\n"
        "  dakshscra.py -r php -t ./src\n"
        "  dakshscra.py -r php,cpp -vv -t /path/to/code\n"
        "  dakshscra.py -r auto -t ./codebase\n"
        "  dakshscra.py -recon -t ./api\n"
        "  dakshscra.py -recon -rs -t ./mobile_app\n"
        "  dakshscra.py -recon -r java -t ./javaapp\n"
        "  dakshscra.py -r dotnet -f dotnet -t ./dotnetapp\n"
        "  dakshscra.py --pdf-from-json\n"
        "  dakshscra.py --pdf-from-json --json-input-dir ./custom/reports/data\n"
        "  dakshscra.py -l RF\n\n"
        "Notes:\n"
        "  - If -f is not provided, default filetypes for selected platform(s) are used.\n"
        "  - Use -r auto to detect file types and auto-apply relevant platform rules.\n"
        "  - Use -recon alone to detect technology stack without scanning.\n"
        "  - Use --rs (or --recon-strict) with --recon for high-confidence recon output."
    ),
)

settings_group = args.add_argument_group("Global date and time settings")
settings_group.add_argument('--settings', action='store_true', help='Show global date/time preferences and exit')
settings_group.add_argument('--save-settings', action='store_true', help='Save date/time preferences globally and exit')
settings_group.add_argument('--date-format', choices=('MM-DD-YYYY', 'DD-MM-YYYY', 'YYYY-MM-DD'), default=None)
settings_group.add_argument('--time-format', choices=('24h', '12h'), default=None)
settings_group.add_argument('--timezone', default=None, metavar='IANA_ZONE')
scan_group = args.add_argument_group("Scan options")
scan_group.add_argument('--custom-rdl', action='append', default=[], metavar='PACK.json',
                        help='Include an optional application-specific RDL v2 pack; repeat for multiple packs')
scan_group.add_argument('--rule-mode', choices=('pattern', 'semantic', 'both'), default=None,
                        help='Rules to run (default: both). Pattern Rules identify areas of interest; Semantic Rules analyze relationships and modeled flows. Reviewer confirmation is required.')
scan_group.add_argument('--rdl-engine', choices=('v1', 'v2', 'both'), default=None,
                        help='Compatibility selection for older scripts: v1, v2 (includes native pattern baselines), or both. Prefer --rule-mode.')
mode_group = args.add_argument_group("Mode options")
output_group = args.add_argument_group("Output options")
advanced_group = args.add_argument_group("Advanced options")

scan_group.add_argument('-r', type=str, action='store', dest='rule_file', required=False,
                        metavar='RULES',
                        help='Platform rules (e.g. php,java,cpp) or "auto"')

scan_group.add_argument('-f', type=str, action='store', dest='file_types', required=False,
                        metavar='FILE_TYPES',
                        help='Override default filetypes for scanning')

scan_group.add_argument('-v', action='count', dest='verbosity', default=0,
                        help='Verbosity level (-v, -vv, -vvv)')

scan_group.add_argument('-t', type=str, action='store', dest='target_dir', required=False,
                        metavar='TARGET_DIR',
                        help='Target source code directory')

mode_group.add_argument('-l', '--list', type=str, action='store', dest='rules_filetypes',
                        required=False, choices=['R', 'RF'], metavar='{R,RF}',
                        help='List platform rules + frameworks [R] or include filetypes [RF]')

mode_group.add_argument('--recon', action='store_true', dest='recon',
                        help='Run reconnaissance (platform/framework/language detection)')

mode_group.add_argument('--rs', '--recon-strict', action='store_true', dest='recon_strict',
                        help='Strict recon filter (use with --recon): high-confidence framework/platform detections only')

mode_group.add_argument('--estimate', action='store_true', dest='estimate',
                        help='Scan supplied scope, collect recon/LOC and estimate review effort from final evidence')
mode_group.add_argument('--estimate-assumptions', default='{}', metavar='JSON',
                        help='Per-scan effort rate overrides as a JSON object; omitted rates use global defaults')
mode_group.add_argument('--estimate-mode', choices=('assisted', 'targeted', 'manual', 'ai'), default='assisted',
                        help='Review effort scenario (default: assisted manual review)')
mode_group.add_argument('--estimate-domain', action='append', default=None,
                        choices=tuple(key for key, _ in EFFORT_DOMAINS),
                        help='Targeted review domain; repeat to select multiple domains (default: all)')
mode_group.add_argument('--estimate-calibration', default='', metavar='JSON',
                        help='Observed comparable task samples: component, units and hours; at least five per component')

mode_group.add_argument('--pdf-from-json', action='store_true', dest='pdf_from_json',
                        help='Generate PDF report(s) from existing JSON outputs without re-running scan')

output_group.add_argument('-rpt', '--report', type=str, action='store', dest='report_format',
                          default='html', metavar='FORMATS',
                          help='Report formats to generate: html, pdf, docx, json, or a comma-separated combination (default: html)')

output_group.add_argument('--json-input-dir', type=str, action='store', dest='json_input_dir',
                          default='', metavar='PATH',
                          help='Path to JSON report directory (for example: ./reports/<project-id>/<run-id>/data)')

output_group.add_argument('--report-audience', choices=('developer', 'code_review', 'both'), default='both',
                          help='Guidance shown in output reports: implementation checks, exploitability review, or both (default: both)')

output_group.add_argument('--pdf-output', type=str, action='store', dest='pdf_output',
                          default='', metavar='PATH',
                          help='Output path for single PDF report (default: ./reports/<project-id>/<run-id>/scan/pdf/report.pdf)')

output_group.add_argument('--pdf-multi-dir', type=str, action='store', dest='pdf_multi_dir',
                          default='', metavar='PATH',
                          help='Output directory for multi-file PDF report set (default: ./reports/<project-id>/<run-id>/scan/pdf/multi-file)')

output_group.add_argument('--pdf-single-only', action='store_true', dest='pdf_single_only',
                          help='Generate only the combined single-file PDF; skip the per-platform multi-file PDF set')

advanced_group.add_argument('--skip-analysis', action='store_true', dest='skip_analysis',
                            help='Disable the analyzer stage for this run')

advanced_group.add_argument('--loc', action='store_true', dest='loc',
                            help='Count effective lines of code (may add scan time)')

advanced_group.add_argument('--baseline-file', type=str, dest='baseline_file',
                            default=str(state.suppressionBaseline), metavar='PATH',
                            help='Suppression baseline file (JSON)')

advanced_group.add_argument('--baseline-generate', action='store_true', dest='baseline_generate',
                            help='Generate suppression baseline from current findings')

advanced_group.add_argument('--no-baseline', action='store_true', dest='no_baseline',
                            help='Disable baseline suppression for this run')

advanced_group.add_argument('--resume-scan', action='store_true', dest='resume_scan',
                            help='Resume a previously interrupted long-running scan from state file')

advanced_group.add_argument('--review-config', type=str, dest='review_config',
                            default='', metavar='PATH',
                            help='Path to a findings triage file (JSON); previously reviewed false positives and suppressed findings will be excluded from generated reports')

advanced_group.add_argument('--state-file', type=str, dest='state_file',
                            default='', metavar='PATH',
                            help='Custom scan state/checkpoint file path')

advanced_group.add_argument('--no-state', action='store_true', dest='state_disable',
                            help='Disable scan state checkpointing for this run')

advanced_group.add_argument('--state', action='store_true', dest='state_enable',
                            help='Force enable scan state checkpointing for this run')

scan_group.add_argument('--exclude-check', action='append', default=[], dest='exclude_checks', metavar='CLASS',
                        help='Exclude a check class; repeat for multiple classes (see Web UI Vulnerability DB)')
scan_group.add_argument('--exclude-path', action='append', default=[], dest='exclude_paths', metavar='GLOB',
                        help='Exclude a project-relative file/directory path or glob; repeat as needed')
scan_group.add_argument('--exclude-type', action='append', default=[], dest='exclude_types', metavar='EXT',
                        help='Exclude a file extension or filename glob; repeat as needed')
scan_group.add_argument('--exclude-keyword', action='append', default=[], dest='exclude_keywords', metavar='TEXT',
                        help='Exclude whole files containing literal text, case-insensitive; repeat as needed')

# Display help if no arguments are passed
if len(sys.argv) < 2:
    args.print_help()
    sys.exit(1)

# Parse arguments with error handling
results = args.parse_args()
from utils.datetime_utils import configure_display, format_datetime, save_display_preferences
from utils.config_utils import get_display_config, get_now
try:
    display = get_display_config()
    for key in ('date_format', 'time_format', 'timezone'):
        if getattr(results, key) is not None:
            display[key] = getattr(results, key)
    display = configure_display(display)
    if results.save_settings:
        save_display_preferences(display)
    if results.settings or results.save_settings:
        print(json.dumps(display, indent=2))
        sys.exit(0)
except ValueError as exc:
    args.error(str(exc))
from core.rdl.selection import RULE_MODES
from utils.report_audience import configure_audience
configure_audience(results.report_audience)
if results.rule_mode is not None and results.rdl_engine is not None and RULE_MODES[results.rule_mode] != results.rdl_engine:
    args.error('--rule-mode and --rdl-engine select conflicting modes')
if results.rdl_engine is None:
    results.rule_mode = results.rule_mode or 'both'
    results.rdl_engine = RULE_MODES[results.rule_mode]
estimate_calibration_samples = []
try:
    estimate_assumptions = json.loads(results.estimate_assumptions)
    from core.effort import validate_assumptions
    if estimate_assumptions:
        validate_assumptions(estimate_assumptions)
    elif not isinstance(estimate_assumptions, dict):
        raise ValueError('Effort assumptions must be a JSON object')
except (ValueError, TypeError) as exc:
    args.error(str(exc))
if results.estimate:
    # Estimates need the completed scan evidence and a measured code inventory.
    results.rule_file = results.rule_file or 'auto'
    results.recon = True
    results.loc = True
    if results.estimate_calibration:
        try:
            estimate_calibration_samples = json.loads(Path(results.estimate_calibration).read_text())
            from core.effort import calibrate, load_assumptions
            calibrate(estimate_calibration_samples, load_assumptions())
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            args.error('Effort calibration: ' + str(exc))
try:
    configure_engines(state.root_dir, results.rdl_engine, results.custom_rdl, results.rule_mode)
except (OSError, ValueError, KeyError, TypeError) as exc:
    args.error('Custom RDL configuration: ' + str(exc))

from utils.scan_scope import configure_scope
try:
    configure_scope(results.target_dir, exclude_checks=results.exclude_checks, exclude_paths=results.exclude_paths,
                    exclude_types=results.exclude_types, exclude_keywords=results.exclude_keywords)
except ValueError as exc:
    args.error(str(exc))

original_rule_file = results.rule_file

# Normalize target path early so every stage uses the same canonical location.
if results.target_dir:
    try:
        results.target_dir = str(Path(results.target_dir).expanduser().resolve())
    except OSError:
        pass

# Remove duplicates in rule_file and file_types
results.rule_file = strutils.remove_duplicates(results.rule_file)
results.file_types = strutils.remove_duplicates(results.file_types)

# Utility mode: generate professional PDF report(s) from existing JSON outputs.
if results.pdf_from_json:
    print(constants.AUTHOR_BANNER.format(version=version))
    cli.section_print("[*] On-Demand PDF Generation (JSON)")

    # Resolve the same project/run identity the normal scan flow uses (env vars,
    # falling back to -t/--target-dir's basename) before computing default paths,
    # so unset --json-input-dir/--pdf-output/--pdf-multi-dir fall back to the
    # correct per-project/run directory instead of the legacy flat reports root.
    _pdf_project_id = os.environ.get("DAKSH_PROJECT_ID", "").strip()
    if not _pdf_project_id and getattr(results, "target_dir", None):
        _pdf_project_id = Path(str(results.target_dir).rstrip("/\\")).name
    _pdf_run_id = os.environ.get("DAKSH_RUN_ID", "").strip()
    state.configure_project_paths(_pdf_project_id, _pdf_run_id)

    json_input_dir = Path(results.json_input_dir).expanduser() if results.json_input_dir else (Path(state.reports_dirpath) / "data")
    single_pdf_output = Path(results.pdf_output).expanduser() if results.pdf_output else Path(state.pdfreport_Fpath)
    multi_pdf_output = Path(results.pdf_multi_dir).expanduser() if results.pdf_multi_dir else (Path(state.reports_dirpath) / "scan" / "pdf" / "multi-file")

    print(f"     [-] JSON Input Dir       : {json_input_dir}")
    print(f"     [-] Single PDF Output    : {single_pdf_output}")
    if results.pdf_single_only:
        print("     [-] Multi-file PDF       : disabled")
    else:
        print(f"     [-] Multi-file PDF Dir   : {multi_pdf_output}")

    try:
        generated = report.gen_pdf_reports_from_json(
            json_dir=json_input_dir,
            output_pdf_path=single_pdf_output,
            multifile_output_dir=multi_pdf_output,
            include_multifile=not results.pdf_single_only,
        )
    except Exception as exc:
        print(f"[!] PDF generation failed: {exc}")
        sys.exit(1)

    cli.section_print("[*] PDF Report:")
    print("     [-] PDF Report Path : " + str(generated.get("single_pdf")))
    if generated.get("multi_pdf_root"):
        print("     [-] Multi-file PDF root : " + str(generated.get("multi_pdf_root")))
        print("     [-] Multi-file PDFs     : " + str(len(generated.get("platform_pdfs", [])) + 1))
    sys.exit(0)

state_cfg = cutils.get_state_management_config()
analysis_cfg = cutils.get_analysis_config()
state_enabled = (state_cfg["enabled"] and not results.state_disable) or results.state_enable
state_file_path = results.state_file.strip() if results.state_file else state_cfg["default_state_file"]
if not Path(state_file_path).is_absolute():
    state_file_path = str(Path(state.root_dir) / state_file_path)

restored_output_cfg = {}
if (results.resume_scan or state_cfg["resume_mode"] == "auto") and Path(state_file_path).is_file():
    try:
        restored_state = json.loads(Path(state_file_path).read_text(encoding="utf-8"))
        if isinstance(restored_state, dict):
            restored_output_cfg = restored_state.get("scan_config", {}) or {}
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        restored_output_cfg = {}

if results.skip_analysis:
    analysis_enabled_for_run = False
else:
    analysis_enabled_for_run = bool(analysis_cfg.get("run_by_default", True))

analysis_include_frameworks = bool(analysis_cfg.get("include_frameworks", True))


def _safe_load_json(path_obj, default):
    try:
        with open(path_obj, "r", encoding="utf-8") as f_obj:
            return json.load(f_obj)
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return default


def _safe_write_json(path_obj, payload):
    try:
        Path(path_obj).parent.mkdir(parents=True, exist_ok=True)
        from utils.json_io import write_json_atomic
        write_json_atomic(path_obj, payload)
        return True
    except OSError:
        return False


def _apply_review_config_to_outputs(review_config_path):
    if not review_config_path:
        return

    config = review_utils.load_review_config(review_config_path)
    source_path = Path(state.outputAoI_JSON)
    path_aoi_path = Path(state.outputAoI_Fpaths_JSON)
    analysis_path = Path(state.outputAnalysis_JSON)
    summary_path = Path(state.outputSummary_JSON)
    scan_summary_path = Path(state.scanSummary_Fpath)

    source_raw = _safe_load_json(source_path, [])
    if isinstance(source_raw, dict):
        source_items = list(source_raw.values())
    elif isinstance(source_raw, list):
        source_items = source_raw
    else:
        source_items = []

    path_items = _safe_load_json(path_aoi_path, [])
    if not isinstance(path_items, list):
        path_items = []

    analysis_summary = _safe_load_json(analysis_path, {"summary": {"enabled": False, "targets_total": 0, "targets_analyzed": 0, "findings_identified": 0}, "results": []})
    flow_map = {}
    analysis_root = Path(state.reports_dirpath) / "analysis"
    if analysis_root.exists():
        for flow_json in analysis_root.glob("*/analysis.json"):
            platform_key = flow_json.parent.name
            flow_map[platform_key] = _safe_load_json(flow_json, [])

    filtered = review_utils.filter_scan_outputs(
        config,
        source_findings=source_items,
        path_findings=path_items,
        analysis_summary=analysis_summary,
        analysis_flow_map=flow_map,
    )

    _safe_write_json(source_path, filtered["source_findings"])
    _safe_write_json(path_aoi_path, filtered["path_findings"])
    _safe_write_json(analysis_path, filtered["analysis_summary"])
    for platform_key, flows in filtered["analysis_flow_map"].items():
        flow_json = analysis_root / platform_key / "analysis.json"
        if flow_json.exists():
            _safe_write_json(flow_json, flows)

    summary_data = _safe_load_json(summary_path, {})
    if isinstance(summary_data, dict):
        detected = summary_data.get("detected", {}) if isinstance(summary_data.get("detected"), dict) else {}
        detected["areas_of_interest_identified"] = filtered["counts"]["source"]
        detected["file_paths_areas_of_interest_identified"] = filtered["counts"]["path"]
        summary_data["detected"] = detected
        summary_data["review_config_applied"] = str(review_config_path)
        _safe_write_json(summary_path, summary_data)

    scan_summary = _safe_load_json(scan_summary_path, {})
    if isinstance(scan_summary, dict):
        detection = scan_summary.get("detection_summary", {}) if isinstance(scan_summary.get("detection_summary"), dict) else {}
        analyzer_summary = scan_summary.get("analyzer_summary", {}) if isinstance(scan_summary.get("analyzer_summary"), dict) else {}
        detection["areas_of_interest_identified"] = str(filtered["counts"]["source"])
        detection["file_paths_areas_of_interest_identified"] = str(filtered["counts"]["path"])
        analyzer_summary["findings_identified"] = filtered["counts"]["analyzer"]
        scan_summary["detection_summary"] = detection
        scan_summary["analyzer_summary"] = analyzer_summary
        scan_summary["review_config_applied"] = str(review_config_path)
        _safe_write_json(scan_summary_path, scan_summary)

    print(f"     [-] Review Config Applied: {review_config_path}")
    print(f"     [-] Review Filtered Src  : {filtered['counts']['source']}")
    print(f"     [-] Review Filtered Path : {filtered['counts']['path']}")
    print(f"     [-] Review Filtered Anlz : {filtered['counts']['analyzer']}")


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


def _analysis_fallback_from_aoi(aoi_records, platform_key):
    findings = []
    scores = []
    for item in aoi_records:
        if not isinstance(item, dict):
            continue
        platform = str(item.get("platform", "")).strip().lower()
        if platform != str(platform_key).strip().lower():
            continue
        evidence = item.get("evidence", [])
        evidence_count = len(evidence) if isinstance(evidence, list) else 0
        default_score = min(75, 45 + (evidence_count * 3))
        score = _normalize_confidence_score(item.get("confidence_score"), default=default_score)
        findings.append({
            "id": str(item.get("rule_id", "")).strip(),
            "title": str(item.get("rule_title", "")).strip() or "Unnamed finding",
            "description": str(item.get("issue_desc", "")).strip() or str(item.get("rule_desc", "")).strip(),
            "confidence_score": score,
            "confidence_label": _confidence_label(score),
            "source_count": evidence_count,
        })
        scores.append(score)
    overall = int(round(sum(scores) / len(scores))) if scores else 0
    return findings, overall


def _run_analyzer_stage(source_root, selected_platforms, framework_rules_map, include_frameworks=True):
    """Save complete findings and return small orchestration/status metadata."""
    from core.analysis.spool import AnalysisSpool
    with AnalysisSpool() as spool:
        return _run_analyzer_stage_with_store(source_root, selected_platforms, framework_rules_map,
                                              include_frameworks, spool)


def _run_analyzer_stage_with_store(source_root, selected_platforms, framework_rules_map, include_frameworks, spool):
    analyzers = {
        "python": py_analysis.run,
        "php": php_analysis.run,
        "javascript": js_analysis.run,
        "java": java_analysis.run,
        "dotnet": dotnet_analysis.run,
        "golang": go_analysis.run,
        "ruby": ruby_analysis.run,
        "kotlin": kotlin_analysis.run,
        "c": c_analysis.run,
        "cpp": cpp_analysis.run,
        "android": android_analysis.run,
        "ios": ios_analysis.run,
        "flutter": flutter_analysis.run,
        "reactnative": reactnative_analysis.run,
        "ionic": ionic_analysis.run,
        "cordova": cordova_analysis.run,
        "nativescript": nativescript_analysis.run,
        "xamarin": xamarin_analysis.run,
        "maui": maui_analysis.run,
        "kmp": kmp_analysis.run,
    }
    alias_map = {
        "py": "python",
        "python": "python",
        "php": "php",
        "js": "javascript",
        "javascript": "javascript",
        "node": "javascript",
        "nodejs": "javascript",
        "java": "java",
        "kotlin": "kotlin",
        "ios": "ios",
        "flutter": "flutter",
        "maui": "maui",
        "kmp": "kmp",
        "reactnative": "reactnative",
        "ionic": "ionic",
        "cordova": "cordova",
        "nativescript": "nativescript",
        "xamarin": "xamarin",
        "android": "android",
        "dotnet": "dotnet",
        ".net": "dotnet",
        "csharp": "dotnet",
        "c#": "dotnet",
        "go": "golang",
        "golang": "golang",
        "ruby": "ruby",
        "rails": "ruby",
        "c": "c",
        "cpp": "cpp",
        "c++": "cpp",
    }

    aoi_raw = _safe_load_json(state.outputAoI_JSON, [])
    if isinstance(aoi_raw, dict):
        aoi_records = list(aoi_raw.values())
    elif isinstance(aoi_raw, list):
        aoi_records = aoi_raw
    else:
        aoi_records = []

    results_payload = []
    cache = {}
    platform_result_map = {}
    language_hints = analysis_dispatch.project_language_hints(source_root)

    platform_targets = sorted({str(p).strip().lower() for p in selected_platforms if str(p).strip() and str(p).strip().lower() != "common"})
    total_platform_targets = len(platform_targets)

    result.update_scan_summary_many({
        "analyzer_summary.enabled": True,
        "analyzer_summary.platform_targets_total": total_platform_targets,
        "analyzer_summary.platform_targets_completed": 0,
        "analyzer_summary.current_target": "",
        "analyzer_summary.heartbeat_message": "Analyzer queued",
    })

    for index, platform in enumerate(platform_targets, start=1):
        canonical, runner = analysis_dispatch.resolve_analysis_target(platform, alias_map, analyzers, language_hints)
        try:
            runner_accepts_progress = "progress_callback" in inspect.signature(runner).parameters
        except (TypeError, ValueError):
            runner_accepts_progress = False
        target_started_at = time.time()
        last_analysis_progress = {}
        def _analysis_progress(payload):
            last_analysis_progress.update(payload)
            phase = str(payload.get("phase", "running") or "running")
            current_file = str(payload.get("current_file", "") or "")
            current_function = str(payload.get("current_function", "") or "")
            current_index = int(payload.get("current_index", 0) or 0)
            total_items = int(payload.get("total_items", 0) or 0)
            elapsed = int(time.time() - target_started_at)
            message_bits = [f"Analyzing {platform}"]
            if phase:
                message_bits.append(phase.replace("_", " "))
            if current_function:
                message_bits.append(current_function)
            elif current_file:
                message_bits.append(os.path.basename(current_file))
            message = " | ".join(message_bits)
            scan_state_mgr.update_cursor({
                "stage": "analysis",
                "platform": platform,
                "current_phase": phase,
                "current_file": current_file,
                "current_function": current_function,
                "current_index": current_index,
                "total_items": total_items,
            })
            scan_state_mgr.touch_heartbeat(message, {
                "platform": platform,
                "phase": phase,
                "current_index": current_index,
                "total_items": total_items,
                "current_file": current_file,
                "current_function": current_function,
                "elapsed_seconds": elapsed,
            }, force=False)
            _update_live_progress(
                stage="analysis",
                status=str(payload.get("status", "running")),
                message=message,
                platform=platform,
                current_phase=phase,
                current_file=current_file,
                current_function=current_function,
                current_index=current_index,
                total_items=total_items,
                elapsed_seconds=elapsed,
            )
        scan_state_mgr.update_cursor({
            "stage": "analysis",
            "platform": platform,
            "current_file": platform,
            "current_index": index,
            "total_items": total_platform_targets,
        })
        heartbeat_message = f"Analyzing target {index}/{total_platform_targets}: {platform}"
        scan_state_mgr.touch_heartbeat(heartbeat_message, {
            "platform": platform,
            "current_index": index,
            "total_items": total_platform_targets,
        })
        result.update_scan_summary_many({
            "analyzer_summary.current_target": platform,
            "analyzer_summary.last_heartbeat_at": get_now().isoformat(),
            "analyzer_summary.heartbeat_message": heartbeat_message,
        })
        print(f"     [-] Analyzer Target      : {platform} ({index}/{total_platform_targets})")
        entry = {
            "target_type": "platform",
            "target": platform,
            "platform": platform,
            "engine": "heuristic_fallback",
            "engine_platform": canonical,
            "analysis_kind": "heuristic",
            "supported_engine": bool(runner),
            "status": "completed",
            "confidence_score": 0,
            "confidence_label": "Low",
            "findings": [],
            "artifacts": {},
        }

        if runner:
            if canonical not in cache:
                heartbeat_stop = threading.Event()

                def _heartbeat_worker():
                    while not heartbeat_stop.wait(10):
                        elapsed = int(time.time() - target_started_at)
                        heartbeat = f"Analyzer still running for {platform} ({index}/{total_platform_targets}) after {elapsed}s"
                        print(f"     [-] {heartbeat}")
                        scan_state_mgr.touch_heartbeat(heartbeat, {
                            "platform": platform,
                            "current_index": index,
                            "total_items": total_platform_targets,
                            "elapsed_seconds": elapsed,
                        })
                        _update_live_progress(
                            stage="analysis",
                            status="running",
                            message=heartbeat,
                            platform=platform,
                            current_phase="heartbeat",
                            current_index=index,
                            total_items=total_platform_targets,
                            elapsed_seconds=elapsed,
                        )
                        result.update_scan_summary_many({
                            "analyzer_summary.current_target": platform,
                            "analyzer_summary.last_heartbeat_at": get_now().isoformat(),
                            "analyzer_summary.heartbeat_message": heartbeat,
                        })

                heartbeat_thread = threading.Thread(target=_heartbeat_worker, daemon=True)
                heartbeat_thread.start()
                try:
                    if runner_accepts_progress:
                        flow_json_path, flow_html_path = runner(source_root, progress_callback=_analysis_progress)
                    else:
                        flow_json_path, flow_html_path = runner(source_root)
                    _analysis_progress({'phase': 'reading_analyzer_results',
                                        'current_file': str(flow_json_path), 'current_function': ''})
                    from utils.json_io import iter_json_array
                    flow_items = spool.add(
                        (analysis_report.flow_finding(flow) for flow in iter_json_array(flow_json_path)
                         if isinstance(flow, dict)),
                        score=lambda finding: _normalize_confidence_score(finding.get('risk_score'), default=55))
                    cache[canonical] = {
                        "ok": True,
                        "flows": flow_items,
                        "json_path": str(flow_json_path),
                        "html_path": str(flow_html_path) if flow_html_path else "",
                    }
                except Exception as exc:
                    error_message = analysis_dispatch.analyzer_exception_message(exc)
                    print(f"     [!] Analyzer failed      : {platform}: {error_message}", flush=True)
                    cache[canonical] = {
                        "ok": False,
                        "error": error_message,
                        "failure_context": {key: last_analysis_progress.get(key, '') for key in
                                            ('phase', 'current_file', 'current_function')},
                    }
                finally:
                    heartbeat_stop.set()
                    heartbeat_thread.join(timeout=1)
            cache_entry = cache[canonical]
            if cache_entry.get("ok"):
                entry["engine"] = "dataflow_controlflow"
                legacy_json = cache_entry.get("json_path", "")
                legacy_html = cache_entry.get("html_path", "")
                legacy_json_path = Path(legacy_json) if legacy_json else None
                legacy_html_path = Path(legacy_html) if legacy_html else None
                modern_theme = str(analysis_cfg.get("report_theme", "hacker_mode")).strip().lower()
                modern_variants = []
                if legacy_json_path and not web_scan():
                    analysis_dir = legacy_json_path.parent
                    if modern_theme == "both":
                        modern_variants = [
                            {
                                "theme": "hacker_mode",
                                "json": str(analysis_dir / "analysis.json"),
                                "html": str(analysis_dir / "analysis.html"),
                                "xref_html": str(analysis_dir / "analysis_xref.html"),
                            },
                            {
                                "theme": "professional_mode",
                                "json": str(analysis_dir / "analysis.json"),
                                "html": str(analysis_dir / "analysis_professional.html"),
                                "xref_html": str(analysis_dir / "analysis_xref_professional.html"),
                            },
                        ]
                    else:
                        modern_variants = [
                            {
                                "theme": modern_theme,
                                "json": str(analysis_dir / "analysis.json"),
                                "html": str(analysis_dir / "analysis.html"),
                                "xref_html": str(analysis_dir / "analysis_xref.html"),
                            }
                        ]
                entry["artifacts"] = {
                    "json": legacy_json,
                    "html": legacy_html,
                    "xref_html": str(legacy_html_path.parent / "analysis_xref.html") if legacy_html_path else "",
                    "modern_variants": modern_variants,
                }
                # Flow analyzers supply evidence to Advanced Analysis. Vulnerability
                # decisions are owned by RDL v2, not a second sink-name classifier.
                entry["vulnerability_engine"] = "rdl_v2"
                entry['findings'] = cache_entry['flows']
                if entry['findings']:
                    entry["confidence_score"] = int(round(entry['findings'].score_sum / len(entry['findings'])))
                    entry["confidence_label"] = _confidence_label(entry["confidence_score"])
            else:
                entry["status"] = "failed"
                entry["error"] = cache_entry.get("error", "analysis failed")
                entry["failure_context"] = cache_entry.get("failure_context", {})

        if not entry["findings"]:
            fallback_findings, fallback_score = _analysis_fallback_from_aoi(aoi_records, platform)
            for finding in fallback_findings:
                finding["analysis_kind"] = "heuristic"
            entry["findings"] = spool.add(fallback_findings) if fallback_findings else []
            if fallback_score:
                entry["confidence_score"] = fallback_score
                entry["confidence_label"] = _confidence_label(fallback_score)
            entry["engine"] = "heuristic_fallback" if entry["engine"] != "dataflow_controlflow" else entry["engine"]
            entry["analysis_kind"] = "heuristic" if entry["engine"] == "heuristic_fallback" else entry["analysis_kind"]
            if not fallback_findings and entry["status"] == "completed":
                entry["status"] = "no_findings"

        platform_result_map[platform] = entry
        results_payload.append(entry)
        result.update_scan_summary_many({
            "analyzer_summary.platform_targets_completed": index,
            "analyzer_summary.last_heartbeat_at": get_now().isoformat(),
            "analyzer_summary.heartbeat_message": f"Analyzer finished target {platform} ({index}/{total_platform_targets})",
        })
        _update_live_progress(
            force=True,
            stage="analysis",
            status="running",
            message=f"Analyzer finished target {platform} ({index}/{total_platform_targets})",
            platform=platform,
            current_phase="target_completed",
            current_index=index,
            total_items=total_platform_targets,
        )

    if include_frameworks:
        framework_seen = set()
        for platform, fw_entries in framework_rules_map.items():
            platform_key = str(platform).strip().lower()
            for fw_entry in fw_entries:
                names = fw_entry.get("names") or [fw_entry.get("name", "")]
                for framework_name in names:
                    fw_key = str(framework_name).strip().lower()
                    if not fw_key or (platform_key, fw_key) in framework_seen:
                        continue
                    framework_seen.add((platform_key, fw_key))

                    parent = platform_result_map.get(platform_key)
                    inherited_score = parent.get("confidence_score", 0) if parent else 0
                    inherited_findings = parent.get("findings", []) if parent else []

                    if inherited_findings:
                        fw_findings = inherited_findings[:20]
                    else:
                        fw_findings, inherited_score = _analysis_fallback_from_aoi(aoi_records, platform_key)
                        if fw_findings:
                            fw_findings = spool.add(fw_findings)

                    fw_entry_payload = {
                        "target_type": "framework",
                        "target": framework_name,
                        "framework": framework_name,
                        "platform": platform_key,
                        "engine": "platform_inherited",
                        "analysis_kind": "inherited",
                        "supported_engine": bool(parent and parent.get("supported_engine")),
                        **analysis_dispatch.inherited_analysis_state(parent, bool(fw_findings)),
                        "confidence_score": inherited_score,
                        "confidence_label": _confidence_label(inherited_score),
                        "findings": fw_findings,
                        "artifacts": parent.get("artifacts", {}) if parent else {},
                        "vulnerability_engine": "rdl_v2",
                    }
                    results_payload.append(fw_entry_payload)

    total_findings = spool.unique_count()
    taint_targets = len([item for item in results_payload if item.get("engine") == "dataflow_controlflow"])
    summary = {
        "enabled": True,
        "generated_at": get_now().isoformat(),
        "targets_total": len(results_payload),
        "targets_analyzed": len([item for item in results_payload if item.get("status") in {"completed", "no_findings"}]),
        "targets_failed": len([item for item in results_payload if item.get("status") == "failed"]),
        "taint_targets": taint_targets,
        "findings_identified": total_findings,
        "vulnerability_engine": "rdl_v2",
        "platform_targets_total": total_platform_targets,
        "platform_targets_completed": total_platform_targets,
        "current_target": "",
        "last_heartbeat_at": get_now().isoformat(),
        "heartbeat_message": "Analyzer completed with target failures" if any(item.get("status") == "failed" for item in results_payload) else "Analyzer completed",
    }

    output_path = Path(state.outputAnalysis_JSON)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    spool.write(output_path, summary, results_payload)
    # The CLI needs status/counts, not another copy of the persisted evidence.
    # File-backed rows are intentionally scoped to this stage's context manager.
    return {'summary': summary, 'results': [
        dict({key: value for key, value in entry.items() if key != 'findings'},
             finding_count=len(entry['findings'])) for entry in results_payload]}

scan_state_mgr = ScanStateManager(
    state_file=state_file_path,
    enabled=state_enabled,
    persist_after_seconds=state_cfg["persist_after_seconds"],
    persist_interval_seconds=state_cfg["persist_interval_seconds"],
    cleanup_on_success=state_cfg["cleanup_on_success"],
)

_live_progress_tick = {"last": 0.0}
_repository_progress_totals = {
    "directories_scanned": 0,
    "files_discovered": 0,
    "files_selected": 0,
}


def _update_live_progress(force=False, **payload):
    now = time.time()
    if not force and (now - _live_progress_tick["last"]) < 0.25:
        return
    payload.setdefault("updated_at", now)
    payload.setdefault("operation_started_at", 0)
    payload.setdefault("elapsed_seconds", max(0, int(now - state.start_time)))
    result.update_scan_summary_many({
        f"live_progress.{key}": value for key, value in payload.items()
    })
    _live_progress_tick["last"] = now


def _repository_progress(payload):
    phase = str(payload.get("phase", "enumerating") or "enumerating")
    stage = "reconnaissance" if phase.startswith("recon_") else "discovery"
    current_index = int(payload.get("current_index", 0) or 0)
    force = current_index == 0 or phase.endswith(("_ready", "_detected"))
    for metric in _repository_progress_totals:
        value = int(payload.get(metric, 0) or 0)
        if metric == "files_selected" and phase == "inventory_ready":
            # Discovery's unique selection supersedes reconnaissance candidates.
            _repository_progress_totals[metric] = value
        else:
            _repository_progress_totals[metric] = max(_repository_progress_totals[metric], value)
    _update_live_progress(
        force=force,
        stage=stage,
        status=str(payload.get("status", "running") or "running"),
        message=str(payload.get("message", "Mapping repository") or "Mapping repository"),
        platform="",
        category="",
        rule_title="",
        current_function="",
        current_phase=phase,
        current_file=str(payload.get("current_file", "") or ""),
        current_index=current_index,
        total_items=int(payload.get("total_items", 0) or 0),
        elapsed_seconds=max(0, int(time.time() - state.start_time)),
        directories_scanned=_repository_progress_totals["directories_scanned"],
        files_discovered=_repository_progress_totals["files_discovered"],
        files_selected=_repository_progress_totals["files_selected"],
    )


project_output_id = os.environ.get("DAKSH_PROJECT_ID", "").strip()
if not project_output_id and getattr(results, "target_dir", None):
    project_output_id = Path(str(results.target_dir).rstrip("/\\")).name
project_output_id = restored_output_cfg.get("project_output_id", project_output_id)
run_output_id = restored_output_cfg.get("run_output_id", os.environ.get("DAKSH_RUN_ID", "").strip())
if not run_output_id:
    run_output_id = datetime.now().strftime("%Y%m%d%H%M%S") + "-" + uuid4().hex[:8]
state.configure_project_paths(project_output_id, run_output_id)

should_preserve_runtime = bool(results.resume_scan)
if not should_preserve_runtime:
    futils.dir_cleanup(str(state.runtime_dirpath))
    futils.dir_cleanup(str(state.runtime_dirpath / "platform"))
    futils.dir_cleanup(str(state.reports_dirpath / "scan"))
    futils.dir_cleanup(str(state.reports_dirpath / "data"))
    futils.dir_cleanup_recursive(str(state.reports_dirpath / "analysis"))

_update_live_progress(
    force=True,
    stage="initialization",
    status="running",
    message="Scan engine online - preparing repository",
    current_phase="preparing_workspace",
    current_file=str(getattr(results, "target_dir", "") or ""),
    current_index=0,
    total_items=0,
    elapsed_seconds=0,
    directories_scanned=0,
    files_discovered=0,
    files_selected=0,
)

# If rule_file is present but file_types is empty, inherit rule_file value
if results.rule_file and not results.file_types:
    results.file_types = results.rule_file.lower()

elif results.recon:
    if not results.target_dir:
        print("You must specify the target directory using -t option.\n")
        sys.exit(1)

elif results.rules_filetypes is not None:
    rutils.list_rules_filetypes(results.rules_filetypes)
    sys.exit(0)

# Recon-only mode does not produce a review-effort plan.
if results.recon and results.target_dir and not results.rule_file:
    print(constants.AUTHOR_BANNER.format(version=version))
    if not path.isdir(results.target_dir):
        print("\nInvalid target directory :" + results.target_dir + "\n")
        cli.tool_usage("invalid_dir")
        sys.exit(1)
    rec.recon(results.target_dir, False, strict_mode=results.recon_strict, progress_callback=_repository_progress)
    sys.exit(0)

# Priority #2 - rule based scan
elif results.rule_file:
    if not results.file_types:
        results.file_types = results.rule_file.lower()
    if not results.target_dir:
        print("You must specify the target directory using -t option")
        sys.exit(1)

    display_rule_file = "auto" if original_rule_file and original_rule_file.lower() == "auto" else results.rule_file.lower()
    display_file_types = "auto" if original_rule_file and original_rule_file.lower() == "auto" else results.file_types.lower()

    print(constants.AUTHOR_BANNER.format(version=version))
    cli.section_print(f"[*] Inputs & Rule Selection")
    print(f"     [-] Rule Selected        : {display_rule_file!r}")
    print(f"     [-] File Types Selected  : {display_file_types!r}")
    print(f"     [-] Target Directory     : {results.target_dir}")
    print(f"     [-] Project ID           : {project_output_id}")
    print(f"     [-] Run ID               : {run_output_id}")
    print(f"     [-] Report Root          : {state.reports_dirpath}")
    print(f"     [-] Analyzer Stage       : {'enabled' if analysis_enabled_for_run else 'disabled'}")

    result.update_scan_summary("inputs_received.rule_selected", display_rule_file)
    result.update_scan_summary("inputs_received.filetypes_selected", display_file_types)
    result.update_scan_summary("inputs_received.target_directory", results.target_dir)
    result.update_scan_summary("inputs_received.analyzer_enabled", analysis_enabled_for_run)
    result.update_scan_summary("inputs_received.project_id", state.project_id or project_output_id)
    result.update_scan_summary("inputs_received.run_id", state.run_id or run_output_id)
    result.update_scan_summary("inputs_received.report_root", str(state.reports_dirpath))
    result.update_scan_summary("inputs_received.rdl_engine", results.rdl_engine)
    result.update_scan_summary("inputs_received.rule_mode", results.rule_mode or results.rdl_engine)
    result.update_scan_summary("inputs_received.report_audience", results.report_audience)
    result.update_scan_summary("inputs_received.custom_rdl", results.custom_rdl)
    result.update_scan_summary(
        "inputs_received.rdl_v2_shadow_enabled",
        default_shadow_runner(state.root_dir).enabled,
    )

    cutils.init_or_prompt_project_config()
    if str(results.verbosity) in ('1', '2', '3'):
        state.verbosity = results.verbosity
        print(f"     [-] Verbosity Level      : {results.verbosity}")
    else:
        print(f"     [-] Verbosity Level      : Default [1]")

# Check if the directory path is valid
if path.isdir(results.target_dir) is False:
    print("\nInvalid target directory :" + results.target_dir + "\n")
    cli.tool_usage("invalid_dir")
    sys.exit(1)

project_dir = os.path.join(results.target_dir, '')
state.source_root = str(Path(results.target_dir).resolve())
# Retain review evidence and unresolved analysis, without comparison-only history.
os.environ["DAKSH_RDL_RESULT_RETENTION"] = "review"
# Source and rule bytes remain consistent across all passes in this scan.
from utils.source_cache import source_snapshot
_scan_source_snapshot = source_snapshot(state.source_root, Path(state.root_dir) / 'rules')
_scan_source_snapshot.__enter__()
atexit.register(lambda: _scan_source_snapshot.__exit__(None, None, None))
state.sourcedir = re.search(r'((?!\/|\\).)*(\/|\\)$', project_dir)[0]        # Target Source Code Directory

root_dir = os.path.dirname(os.path.realpath(__file__))
state.root_dir = root_dir
state.suppressionBaseline = Path(results.baseline_file)

if results.no_baseline:
    state.suppressions = []
    print("     [-] Baseline Suppression : Disabled")
else:
    # For baseline generation mode, scan raw findings and generate baseline from those findings.
    if results.baseline_generate:
        state.suppressions = []
        print(f"     [-] Baseline Mode        : Generate ({state.suppressionBaseline})")
    else:
        state.suppressions = supp.load_suppressions(state.suppressionBaseline)
        print(f"     [-] Baseline Loaded      : {len(state.suppressions)} suppression entries")

if results.review_config:
    print(f"     [-] Review Config        : {results.review_config}")
    review_cfg = review_utils.load_review_config(results.review_config)
    review_suppressions = review_utils.source_suppressions_from_review_config(review_cfg)
    if review_suppressions:
        state.suppressions.extend(review_suppressions)
        print(f"     [-] Review Suppressions  : {len(review_suppressions)} source entries merged into active suppression set")

# Auto-detect rule types
if original_rule_file and original_rule_file.lower() == "auto":
    print("     [-] Auto-detecting applicable platform types... ", end="", flush=True)
    spinner("start")
    auto_details = discover.auto_detect_rule_types_with_details(
        results.target_dir,
        progress_callback=_repository_progress,
    )
    detected = auto_details.get("result", "")
    results.rule_file = detected
    results.file_types = detected
    spinner("stop")
    print(f"     [-] Auto Candidates (Ext): {', '.join(auto_details.get('extension_detected', [])) or 'none'}")
    print(f"     [-] Auto Candidates (Mrk): {', '.join(auto_details.get('marker_detected', [])) or 'none'}")
    suppressed_map = auto_details.get("suppressed_by_platform", {}) or {}
    if suppressed_map:
        suppressed_labels = []
        for platform, overlaps in sorted(suppressed_map.items()):
            suppressed_labels.append(f"{platform} -> {', '.join(overlaps)}")
        print(f"     [-] Suppressed Overlaps  : {'; '.join(suppressed_labels)}")
    else:
        print("     [-] Suppressed Overlaps  : none")
    print(f"     [-] Final Auto Targets   : {detected}")
    append_trace("auto_selection", {
        "mode": "auto",
        "extension_detected": auto_details.get("extension_detected", []),
        "marker_detected": auto_details.get("marker_detected", []),
        "suppressed": suppressed_map,
        "selected": auto_details.get("selected", []),
    })

codebase = results.file_types
selected_rule_platforms = [p.strip() for p in str(results.rule_file).split(",") if p.strip()]
framework_rule_files = discover.detect_framework_rule_files(results.target_dir, selected_rule_platforms, progress_callback=_repository_progress)
framework_summary = {
    platform: [
        {
            "name": entry.get("name", ""),
            "rule_file": entry["path"].name,
            "scan_ftypes": entry.get("scan_ftypes", []),
        }
        for entry in entries
    ]
    for platform, entries in framework_rule_files.items()
    if entries
}
if framework_summary:
    print("     [-] Framework Rule Packs :")
    for platform, fw_entries in sorted(framework_summary.items()):
        fw_labels = []
        for fw in fw_entries:
            patt = fw.get("scan_ftypes") or []
            label = fw.get("name") or fw.get("rule_file")
            if patt:
                label = f"{label} [{', '.join(patt)}]"
            fw_labels.append(label)
        print(f"         [-] {platform}: {', '.join(sorted(fw_labels))}")
else:
    print("     [-] Framework Rule Packs : none detected")
result.update_scan_summary("inputs_received.framework_rules_selected", framework_summary)

# Verify rule names
rule_files = {}
for rule_name in results.rule_file.split(','):
    rule_paths = rutils.get_rules_path_or_filetypes(rule_name.strip(), "rules")
    if not rule_paths:
        print("\nError: Invalid rule name or no path found:", rule_name.strip())
        sys.exit()
    full_path = Path(str(state.rulesRootDir) + rule_paths)
    rule_files[rule_name.strip()] = full_path

rules_main = rule_files
rule_paths_str = []
rule_counts = []
platform_rules_list = []
for rule_name, rule_path in rules_main.items():
    rule_paths_str.append(str(rule_path))
    count = rutils.rules_count(Path(str(rule_path)))
    rule_counts.append(str(count))
    platform_rules_list.append(f"{rule_name}[{count}]")

platform_rules_paths = ", ".join(rule_paths_str)
platform_rules_total = ", ".join(platform_rules_list)

rules_common = Path(str(state.rulesRootDir) + rutils.get_rules_path_or_filetypes("common", "rules"))
common_rules_total = rutils.rules_count(rules_common)
framework_rules_total = 0
for fw_entries in framework_rule_files.values():
    for fw_entry in fw_entries:
        framework_rules_total += rutils.rules_count(fw_entry["path"])
total_rules_loaded = sum(map(int, rule_counts)) + common_rules_total + framework_rules_total

cli.section_print(f"[*] Rules Loaded")
print(f"     [-] Rule Mode            : {results.rule_mode or results.rdl_engine}")
print(f"     [-] Platform Rules       : {platform_rules_total}")
print(f"     [-] Framework Rules      : {framework_rules_total}")
print(f"     [-] Common Rules         : {common_rules_total}")
print(f"     [-] Total Rules Loaded   : {total_rules_loaded}")

result.update_scan_summary("inputs_received.platform_specific_rules", platform_rules_total)
result.update_scan_summary("inputs_received.framework_rules_count", str(framework_rules_total))
result.update_scan_summary("inputs_received.common_rules", str(common_rules_total))
result.update_scan_summary("inputs_received.total_rules_loaded", str(total_rules_loaded))
result.update_scan_summary("inputs_received.rule_engine", state.ruleEngine)

resume_progress = {}
if results.rule_file:
    scan_fingerprint = {
        "target_dir": str(results.target_dir),
        "rule_file": str(results.rule_file),
        "file_types": str(results.file_types),
        "recon": bool(results.recon),
        "recon_strict": bool(results.recon_strict),
        "exclude_checks": results.exclude_checks,
        "exclude_paths": results.exclude_paths,
        "exclude_types": results.exclude_types,
        "exclude_keywords": results.exclude_keywords,
        "rdl_engine": results.rdl_engine,
        "rule_mode": results.rule_mode or results.rdl_engine,
    }
    scan_config = {
        "state_file": str(state_file_path),
        "state_enabled": bool(state_enabled),
        "persist_after_seconds": state_cfg["persist_after_seconds"],
        "persist_interval_seconds": state_cfg["persist_interval_seconds"],
        "rule_engine": state.ruleEngine,
        "rdl_engine": results.rdl_engine,
        "rule_mode": results.rule_mode or results.rdl_engine,
        "project_output_id": project_output_id,
        "run_output_id": run_output_id,
    }

    restored = None
    if results.resume_scan or state_cfg["resume_mode"] == "auto":
        restored = scan_state_mgr.load_for_resume(scan_fingerprint)
        if results.resume_scan and not restored:
            print(f"[!] Unable to resume scan. No matching valid state found at: {state_file_path}")
            sys.exit(1)

    if not restored:
        scan_state_mgr.start_new(scan_fingerprint, scan_config)
    else:
        print(f"     [-] Resume State Loaded  : {state_file_path}")
        resume_progress = scan_state_mgr.get_resume_progress()

    scan_state_mgr.install_signal_handlers()
    atexit.register(lambda: scan_state_mgr.persist(force=True))

    def _uncaught_excepthook(exc_type, exc_value, exc_traceback):
        scan_state_mgr.mark_failed(str(exc_value))
        scan_state_mgr.persist(force=True)
        scan_state_mgr.uninstall_signal_handlers()
        sys.__excepthook__(exc_type, exc_value, exc_traceback)

    sys.excepthook = _uncaught_excepthook

sourcepath = Path(results.target_dir)
state.start_time = time.time()
state.start_timestamp = get_now().isoformat()
result.update_scan_summary_many({'display.' + key: value for key, value in display.items()})

sCnt = 0
cli.section_print("[*] Scanner Initiated")
resume_stages = resume_progress.get("stages", {}) if isinstance(resume_progress, dict) else {}
resume_discovery = resume_stages.get("discovery", {})
resume_pattern = resume_stages.get("pattern_matching", {})
resume_paths = resume_stages.get("path_analysis", {})

scan_state_mgr.update_stage("initialization", "completed", {
    "start_timestamp": state.start_timestamp,
})

###### [Stage #] File Path Discovery ######
sCnt += 1
if resume_discovery.get("status") == "completed":
    master_file_paths = Path(resume_discovery.get("master_file_paths", ""))
    platform_file_paths = [Path(p) for p in resume_discovery.get("platform_file_paths", [])]
    if not master_file_paths.exists() or not all(p.exists() for p in platform_file_paths):
        print("     [-] Resume checkpoint missing discovery artifacts; re-running file discovery.")
        resume_discovery = {}

if resume_discovery.get("status") == "completed":
    cli.section_print(f"[*] [Stage {sCnt}] File Path Discovery")
    print("     [-] Discovery Stage      : Resumed from checkpoint")
else:
    scan_state_mgr.update_stage("discovery", "running")
    if results.recon:
        cli.section_print(f"[*] [Stage {sCnt}] Reconnaissance (a.k.a Software Composition Analysis)")
        rec.recon(results.target_dir, True, strict_mode=results.recon_strict, progress_callback=_repository_progress)
        sCnt += 1
        cli.section_print(f"[*] [Stage {sCnt}] File Path Discovery")
        master_file_paths, platform_file_paths = discover.discover_files(
            codebase, sourcepath, 1, progress_callback=_repository_progress
        )
    else:
        cli.section_print(f"[*] [Stage {sCnt}] File Path Discovery")
        master_file_paths, platform_file_paths = discover.discover_files(
            codebase, sourcepath, 1, progress_callback=_repository_progress
        )

    scan_state_mgr.update_stage("discovery", "completed", {
        "master_file_paths": str(master_file_paths),
        "platform_file_paths": [str(p) for p in platform_file_paths],
    })

###### [Stage 2 or 3] Pattern Matching & Analysis ######
sCnt += 1
cli.section_print(f"[*] [Stage {sCnt}] Pattern Matching & Analysis")
os.makedirs(os.path.dirname(state.outputAoI_JSON), exist_ok=True)

source_matched_rules = []
source_unmatched_rules = []
completed_platforms = set(resume_pattern.get("completed_platforms", [])) if isinstance(resume_pattern, dict) else set()
common_rules_done = bool(resume_pattern.get("common_rules_done", False)) if isinstance(resume_pattern, dict) else False

scan_state_mgr.update_stage("pattern_matching", "running", {
    "completed_platforms": sorted(completed_platforms),
    "common_rules_done": common_rules_done,
})
_update_live_progress(
    force=True,
    stage="pattern_matching",
    status="running",
    message="Pattern matching in progress",
    current_phase="loading_rules",
    current_file="",
    current_index=0,
    total_items=0,
)


def _source_progress(payload):
    scan_state_mgr.update_cursor({
        "stage": "pattern_matching",
        "platform": payload.get("platform", ""),
        "category": payload.get("category", ""),
        "rule_title": payload.get("rule_title", ""),
        "filepath": payload.get("filepath", ""),
        "file_index": payload.get("file_index", 0),
    })
    scan_state_mgr.update_counters({
        "rules_match_count": state.rulesMatchCnt,
        "suppressed_count": state.suppressedFindingsCnt,
        "parse_error_count": state.parseErrorCnt,
    })
    _update_live_progress(
        stage="pattern_matching",
        status=str(payload.get("status", "running")),
        message=payload.get("message", "Scanning source rules"),
        updated_at=payload.get("updated_at", time.time()),
        operation_started_at=payload.get("operation_started_at", 0),
        platform=payload.get("platform", ""),
        category=payload.get("category", ""),
        rule_title=payload.get("rule_title", ""),
        current_function=str(payload.get("current_function", payload.get("rule_title", ""))),
        current_phase=payload.get("phase", "pattern_matching"),
        current_file=str(payload.get("filepath", "")),
        current_index=int(payload.get("file_index", 0) or 0),
        total_items=int(payload.get("total_items", 0) or 0),
        rules_match_count=state.rulesMatchCnt,
        suppressed_count=state.suppressedFindingsCnt,
        parse_error_count=state.parseErrorCnt,
    )

# Platform-specific rules (+ framework-specific overlays)
if results.rule_file.lower() not in ['common']:
    def _filter_framework_target_files(src_file_path, framework_key, patterns):
        if not patterns:
            return src_file_path, None

        out_file_path = state.runtime_dirpath / "platform" / f"{Path(src_file_path).stem}_{framework_key}.log"
        selected = []

        with open(src_file_path, "r", encoding=futils.detect_encoding_type(src_file_path)) as f_src:
            for each in f_src:
                candidate = each.rstrip()
                if not candidate:
                    continue
                base = os.path.basename(candidate)
                normalized = candidate.replace("\\", "/")
                matched = False
                for patt in patterns:
                    if fnmatch.fnmatch(base, patt) or fnmatch.fnmatch(normalized, patt):
                        matched = True
                        break
                if matched:
                    selected.append(candidate)

        out_file_path.write_text("\n".join(selected) + ("\n" if selected else ""), encoding="utf-8")
        return out_file_path, len(selected)

    pattern_overlay_seen = set()
    native_pattern_overlay_summary = {}
    for index, (platform, rules_main_path) in enumerate(rules_main.items()):
        if platform.upper() in completed_platforms:
            print(f"\033[92m     --> Skipping {platform} (already completed in checkpoint)\033[0m")
            continue
        if index < len(platform_file_paths):
            platform_file_path = platform_file_paths[index]
            print(f"\033[92m     --> Applying rules for {platform} \033[0m")
            with open(platform_file_path, 'r', encoding=futils.detect_encoding_type(platform_file_path)) as f_targetfiles:
                matched, unmatched = parser.source_parser(
                    rules_main_path,
                    f_targetfiles,
                    outputfile=None,
                    findings_json_path=state.outputAoI_JSON,
                    progress_callback=_source_progress,
                )
                source_matched_rules.extend(matched)
                source_unmatched_rules.extend(unmatched)
                f_targetfiles.seek(0)

                applied_fw_rule_paths = set()
                for fw_entry in framework_rule_files.get(platform, []):
                    fw_rule_path = fw_entry["path"]
                    fw_rule_key = str(fw_rule_path).lower()
                    if fw_rule_key in applied_fw_rule_paths:
                        continue
                    fw_key = fw_entry.get("name", fw_rule_path.stem).replace(" ", "_")
                    fw_scan_ftypes = fw_entry.get("scan_ftypes", [])
                    target_file_for_fw, fw_target_count = _filter_framework_target_files(
                        platform_file_path, fw_key, fw_scan_ftypes
                    )
                    if fw_target_count == 0:
                        print(f"\033[93m     --> Skipping framework rules: {platform}/{fw_rule_path.stem} (no applicable files)\033[0m")
                        applied_fw_rule_paths.add(fw_rule_key)
                        continue
                    aliases = fw_entry.get("names", [])
                    alias_suffix = f" [aliases: {', '.join(aliases)}]" if aliases else ""
                    print(f"\033[92m     --> Applying framework rules: {platform}/{fw_rule_path.stem}{alias_suffix}\033[0m")
                    with open(target_file_for_fw, 'r', encoding=futils.detect_encoding_type(target_file_for_fw)) as f_fw_targetfiles:
                        fw_matched, fw_unmatched = parser.source_parser(
                            fw_rule_path,
                            f_fw_targetfiles,
                            outputfile=None,
                            findings_json_path=state.outputAoI_JSON,
                            progress_callback=_source_progress,
                        )
                    source_matched_rules.extend(fw_matched)
                    source_unmatched_rules.extend(fw_unmatched)
                    applied_fw_rule_paths.add(fw_rule_key)
                    f_targetfiles.seek(0)
            if results.rdl_engine != 'v2':
                from core.mobile_scope import pattern_overlays
                from io import StringIO
                selected_files = Path(platform_file_path).read_text(encoding='utf-8').splitlines()
                for overlay_pack, overlay_files in pattern_overlays(state.root_dir, rules_main_path, selected_files, list(rules_main.values()) + [entry['path'] for entries in framework_rule_files.values() for entry in entries]):
                    overlay_files = [name for name in overlay_files if (str(overlay_pack), name) not in pattern_overlay_seen]
                    if not overlay_files:
                        continue
                    pattern_overlay_seen.update((str(overlay_pack), name) for name in overlay_files)
                    overlay_info = native_pattern_overlay_summary.setdefault(str(overlay_pack), dict(pack=str(overlay_pack), rules=rutils.rules_count(overlay_pack), files=0))
                    overlay_info['files'] += len(overlay_files)
                    print(f"     --> Applying native Pattern Rules: {overlay_pack.name} ({len(overlay_files)} files)")
                    matched, unmatched = parser.source_parser(overlay_pack, StringIO('\n'.join(overlay_files)),
                        findings_json_path=state.outputAoI_JSON, progress_callback=_source_progress)
                    source_matched_rules.extend(matched)
                    source_unmatched_rules.extend(unmatched)
            completed_platforms.add(platform.upper())
            scan_state_mgr.mark_platform_completed(platform.upper())
            scan_state_mgr.update_stage("pattern_matching", "running", {
                "completed_platforms": sorted(completed_platforms),
                "common_rules_done": common_rules_done,
            })

if results.rdl_engine != 'v2' and locals().get('native_pattern_overlay_summary'):
    result.update_scan_summary('inputs_received.native_pattern_overlays', list(native_pattern_overlay_summary.values()))
    result.update_scan_summary('inputs_received.total_rules_loaded', total_rules_loaded + sum(item['rules'] for item in native_pattern_overlay_summary.values()))

# Common rules
if common_rules_done:
    print("\033[92m     --> Skipping common rules (already completed in checkpoint)\033[0m")
    common_matched_rules, common_unmatched_rules = [], []
else:
    print("\033[92m     --> Applying common (platform-independent) rules \033[0m")
    with open(master_file_paths, 'r', encoding=futils.detect_encoding_type(master_file_paths)) as f_targetfiles:
        common_matched_rules, common_unmatched_rules = parser.source_parser(
            rules_common,
            f_targetfiles,
            outputfile=None,
            findings_json_path=state.outputAoI_JSON,
            progress_callback=_source_progress,
        )
    common_rules_done = True
    scan_state_mgr.mark_common_rules_completed()

source_matched_rules.extend(common_matched_rules)
source_unmatched_rules.extend(common_unmatched_rules)
coverage_path = state.runtime_dirpath / 'analysis_coverage.json'
if coverage_path.exists():
    from core.analysis_coverage import publish_findings, TITLE as coverage_title
    coverage_report = json.loads(coverage_path.read_text(encoding='utf-8'))
    result.update_scan_summary_many({
        'analysis_coverage.status': coverage_report['status'],
        'analysis_coverage.affected_files': coverage_report['affected_files'],
    })
    if publish_findings(coverage_report, state.outputAoI_JSON):
        source_matched_rules.append(coverage_title)
        state.rulesMatchCnt += 1
        print(f"     [!] Incomplete source analysis: {coverage_report['affected_files']} affected files; see {coverage_title} finding for required actions.")
print("\033[92m     --- Pattern Matching Summary ---\033[0m")
scan_state_mgr.update_stage("pattern_matching", "completed", {
    "completed_platforms": sorted(completed_platforms),
    "common_rules_done": common_rules_done,
})

result.update_scan_summary("source_files_scanning_summary.matched_rules", source_matched_rules)
result.update_scan_summary("source_files_scanning_summary.unmatched_rules", source_unmatched_rules)

print("     [-] Total Files Scanned:", str(state.totalFilesIdentified - state.parseErrorCnt))
result.update_scan_summary("detection_summary.total_files_scanned", str(state.totalFilesIdentified - state.parseErrorCnt))
result.update_scan_summary("detection_summary.areas_of_interest_identified", str(state.rulesMatchCnt))
result.update_scan_summary("detection_summary.suppressed_findings", str(state.suppressedFindingsCnt))
print("     [-] Total matched rules:", len(source_matched_rules))
print("     [-] Total unmatched rules:", len(source_unmatched_rules))
print("     [-] Total suppressed hits:", state.suppressedFindingsCnt)

###### [Stage 3 or 4] Parse File Paths for areas of interest ######
sCnt += 1
cli.section_print(f"[*] [Stage {sCnt}] Identifying Areas of Interest")

scan_state_mgr.update_stage("path_analysis", "running")
_update_live_progress(
    force=True,
    stage="path_analysis",
    status="running",
    message="Path analysis in progress",
    current_phase="loading_path_rules",
    current_file="",
    current_index=0,
    total_items=0,
)
if resume_paths.get("status") == "completed" and Path(state.outputAoI_Fpaths_JSON).exists():
    print("     [-] Path Analysis Stage : Resumed from checkpoint")
    matched_rules, unmatched_rules = [], []
else:
    def _paths_progress(payload):
        scan_state_mgr.update_cursor({
            "stage": "path_analysis",
            "rule_title": payload.get("rule_title", ""),
            "filepath": payload.get("filepath", ""),
            "file_index": payload.get("file_index", 0),
        })
        scan_state_mgr.update_counters({
            "paths_match_count": state.rulesPathsMatchCnt,
        })
        _update_live_progress(
            stage="path_analysis",
            status=str(payload.get("status", "running")),
            message="Scanning path-based rules",
            rule_title=payload.get("rule_title", ""),
            current_function=str(payload.get("rule_title", "")),
            current_phase="path_analysis",
            current_file=str(payload.get("filepath", "")),
            current_index=int(payload.get("file_index", 0) or 0),
            total_items=int(payload.get("total_items", 0) or 0),
            paths_match_count=state.rulesPathsMatchCnt,
        )

    with open(master_file_paths, 'r', encoding=futils.detect_encoding_type(master_file_paths)) as f_targetfiles:
        rule_no = 1
        matched_rules, unmatched_rules = parser.paths_parser(
            state.rulesFpaths,
            f_targetfiles,
            outputfile=None,
            rule_no=rule_no,
            findings_json_path=state.outputAoI_Fpaths_JSON,
            progress_callback=_paths_progress,
        )

print("     [-] Total matched rules:", len(matched_rules))
print("     [-] Total unmatched rules:", len(unmatched_rules))
result.update_scan_summary("paths_scanning_summary.matched_rules", matched_rules)
result.update_scan_summary("paths_scanning_summary.unmatched_rules", unmatched_rules)

result.update_scan_summary("detection_summary.file_paths_areas_of_interest_identified", str(state.rulesPathsMatchCnt))

total_loc = futils.clean_file_paths(master_file_paths, count_loc=bool(results.loc))
if total_loc is not None:
    result.update_scan_summary("detection_summary.total_loc", str(total_loc))
if default_shadow_runner(state.root_dir).enabled:
    try:
        from core.rdl.xref import build_index, write_index, INDEX_NAME
        _update_live_progress(force=True, stage="analysis", status="running", message="Indexing source cross-references")
        xref_index = build_index(results.target_dir, progress=lambda filename, count: _update_live_progress(
            stage="analysis", status="running", message="Indexing source cross-references",
            current_file=filename, current_index=count))
        write_index(state.runtime_dirpath / INDEX_NAME, xref_index)
        print("     [-] Source cross-references :", xref_index['summary']['symbols'], "symbols /", xref_index['summary']['calls'], "calls")
    except Exception as exc:
        print("     [!] Source cross-reference index:", exc)

if default_shadow_runner(state.root_dir).enabled or analysis_enabled_for_run:
    try:
        from core.rdl.program_graphs import build_catalog, INDEX_NAME as PROGRAM_GRAPH_INDEX
        from core.rdl.xref import write_index
        _update_live_progress(force=True, stage="analysis", status="running", message="Saving CFG and DFG evidence")
        program_graphs = build_catalog(results.target_dir)
        write_index(state.runtime_dirpath / PROGRAM_GRAPH_INDEX, program_graphs)
        print("     [-] Saved CFG / DFG files  :", program_graphs['summary']['files'])
    except Exception as exc:
        print("     [!] CFG / DFG evidence:", exc)

os.unlink(master_file_paths)
scan_state_mgr.mark_path_analysis_completed()

cli.section_print(f"[*] {'Rule Scan Timeline' if analysis_enabled_for_run else 'Scanning Timeline'}")
print("    [-] Scan start time     : " + format_datetime(state.start_timestamp))
end_timestamp = get_now().isoformat()
print("    [-] Scan end time       : " + format_datetime(end_timestamp))
hours, rem = divmod(time.time() - state.start_time, 3600)
minutes, seconds = divmod(rem, 60)
seconds, milliseconds = str(seconds).split('.')
scan_duration = "{:0>2}Hr:{:0>2}Min:{:0>2}s:{}ms".format(int(hours), int(minutes), seconds, milliseconds[:3])
if analysis_enabled_for_run:
    print(f"    [-] Rule scan completed in: {scan_duration}")
    print("    [-] Next stage           : Analyzer")
    print("    [-] Overall run status   : Rule scan is done. Analyzer/report generation still running.")
else:
    print(f"    [-] Scan completed in    : {scan_duration}")

result.update_scan_summary("scanning_timeline.scan_start_time", state.start_timestamp)
result.update_scan_summary("scanning_timeline.scan_end_time", end_timestamp)
result.update_scan_summary("scanning_timeline.scan_duration", scan_duration)

parser.gen_scan_summary_text(state.scanSummary_Fpath)

if results.baseline_generate:
    baseline_count = supp.build_baseline_from_findings(state.outputAoI_JSON, state.suppressionBaseline)
    print(f"     [-] Baseline generated   : {baseline_count} entries")

###### [Stage 4] Analyzer ######
analysis_payload = {"summary": {"enabled": False, "targets_total": 0, "targets_analyzed": 0, "findings_identified": 0}, "results": []}
analyzer_error_message = ""
if analysis_enabled_for_run:
    sCnt += 1
    cli.section_print(f"[*] [Stage {sCnt}] Analyzer")
    scan_state_mgr.update_stage("analysis", "running")
    _update_live_progress(
        force=True,
        stage="analysis",
        status="running",
        message="Analyzer queued",
        current_phase="preparing_analyzers",
        current_file="",
        current_index=0,
        total_items=0,
    )
    try:
        analysis_payload = _run_analyzer_stage(
            sourcepath,
            selected_rule_platforms,
            framework_rule_files,
            include_frameworks=analysis_include_frameworks,
        )
        summary = analysis_payload.get("summary", {})
        analyzer_error_message = analysis_dispatch.analysis_failure_message(analysis_payload)
        print("     [-] Analyzer Targets     :", summary.get("targets_total", 0))
        print("     [-] Analyzer Findings    :", summary.get("findings_identified", 0))
        print("     [-] Analyzer JSON        :", re.sub(str(state.root_dir), "", str(state.outputAnalysis_JSON)))
        scan_state_mgr.update_stage("analysis", "failed" if analyzer_error_message else "completed", summary)
        result.update_scan_summary("analyzer_summary.enabled", True)
        result.update_scan_summary("analyzer_summary.targets_total", summary.get("targets_total", 0))
        result.update_scan_summary("analyzer_summary.targets_analyzed", summary.get("targets_analyzed", 0))
        result.update_scan_summary("analyzer_summary.targets_failed", summary.get("targets_failed", 0))
        result.update_scan_summary("analyzer_summary.error", analyzer_error_message)
        result.update_scan_summary("analyzer_summary.taint_targets", summary.get("taint_targets", 0))
        result.update_scan_summary("analyzer_summary.findings_identified", summary.get("findings_identified", 0))
        result.update_scan_summary("analyzer_summary.output_json", str(state.outputAnalysis_JSON))
    except Exception as exc:
        analyzer_error_message = analysis_dispatch.analyzer_exception_message(exc)
        print(f"[!] Analyzer stage failed: {analyzer_error_message}")
        scan_state_mgr.update_stage("analysis", "failed", {"error": str(exc)})
        result.update_scan_summary("analyzer_summary.enabled", False)
        result.update_scan_summary("analyzer_summary.taint_targets", 0)
        result.update_scan_summary("analyzer_summary.error", analyzer_error_message)
else:
    result.update_scan_summary("analyzer_summary.enabled", False)
    result.update_scan_summary("analyzer_summary.taint_targets", 0)

mobile_platforms = {'android','ios','reactnative','flutter','cordova','ionic','nativescript','xamarin','maui','kmp'}
if mobile_platforms.intersection(str(p).lower() for p in selected_rule_platforms):
    try:
        from core.mobile_project import write_review, retained_outcomes
        mobile_review = write_review(sourcepath, Path(state.outputAoI_JSON).parent / 'mobile_review.json',
                                     evaluation_counts=retained_outcomes(state.runtime_dirpath / 'rdl_shadow_comparisons.jsonl'))
        result.update_scan_summary_many({'mobile_review.status': mobile_review['state'],
            'mobile_review.coverage': mobile_review['coverage'],
            'mobile_review.contracts': sum(len(mobile_review[k]) for k in ('privacy','backup','lifecycle','bridges','api_contracts','control_contracts'))})
        print('     [-] Mobile review evidence: mobile_review.json / mobile_review.html')
    except Exception as exc:
        result.update_scan_summary_many({'mobile_review.status':'incomplete','mobile_review.error':str(exc)})
        print('     [!] Mobile review evidence incomplete:',exc)

# Re-snapshot the report-facing summary so the analyzer stage's results
# (only known after this point) reach reports/.../data/summary.json,
# which core/reports.py reads when rendering the final report.
parser.gen_scan_summary_text(state.scanSummary_Fpath)

###### [Stage 5] Generate Reports ######
if results.review_config:
    _apply_review_config_to_outputs(results.review_config)

if results.estimate:
    cli.section_print('[*] Review Effort Planning')
    try:
        effort_plan = estimate.effort_estimator(mode=results.estimate_mode,
            domains=results.estimate_domain, calibration=estimate_calibration_samples, assumptions=estimate_assumptions)
        print('     [-] Review scenario     :', effort_plan['mode'])
        print('     [-] Planning hours      :', effort_plan['total_hours'] or 'Not estimable from available measurements')
    except (ValueError, OSError, KeyError) as exc:
        print(f'     [!] Effort planning failed: {exc}')

scan_state_mgr.update_stage("reporting", "running")
_update_live_progress(
    force=True,
    stage="reporting",
    status="running",
    message="Generating reports",
    current_phase="rendering_reports",
    current_file="",
    current_index=0,
    total_items=0,
)
from utils.output_mode import web_scan
valid_formats = {"html", "pdf", "docx", "json"}
requested_formats = results.report_format.lower().replace(" ", "").split(",")
selected_formats = [fmt for fmt in requested_formats if fmt in valid_formats]

if web_scan():
    selected_formats = []
    print("[*] Web results saved. CLI report files are not generated.")
elif selected_formats:
    report.gen_report(formats=",".join(selected_formats), include_multifile_pdf=not results.pdf_single_only)
else:
    print("[!] No valid report format selected. Defaulting to html.")
    selected_formats = ["html"]
    report.gen_report(formats="html", include_multifile_pdf=False)

shadow_summary = summarize_shadow_records(state.runtime_dirpath / "rdl_shadow_comparisons.jsonl")
shadow_enabled = default_shadow_runner(state.root_dir).enabled
if shadow_enabled:
    print("")
    print("[*] Recorded rule evidence")
    print("     [-] Retained results      :", shadow_summary["total"])
    print("     [-] Unique review leads   :", shadow_summary.get('review_leads', 0))
    print("     [-] Unresolved analysis   :", sum(shadow_summary['statuses'].get(key, 0) for key in ('INDETERMINATE', 'RULE_ERROR', 'SHADOW_ERROR')))
    if shadow_summary["malformed"]:
        print("     [!] Malformed records     :", shadow_summary["malformed"])
    print("     [-] Evidence available in the RDL review views; comparison history is not retained.")

scan_state_mgr.update_stage("reporting", "completed")
_update_live_progress(force=True, stage="reporting", status="completed", message="Reports generated")

if not web_scan() and "pdf" not in selected_formats:
    print("")
    print("     [i] PDF report not generated. To generate PDF from existing JSON output:")
    print("         dakshscra.py --pdf-from-json --json-input-dir ./reports/<project-id>/<run-id>/data")
    print("         dakshscra.py --pdf-from-json --json-input-dir ./reports/<project-id>/<run-id>/data --pdf-single-only")

cutils.update_project_config("","")     # Clean up project details in the config file
final_counters = dict(
    rules_match_count=state.rulesMatchCnt,
    suppressed_count=state.suppressedFindingsCnt,
    paths_match_count=state.rulesPathsMatchCnt,
    parse_error_count=state.parseErrorCnt,
)
if analyzer_error_message:
    scan_state_mgr.mark_failed(analyzer_error_message)
    _update_live_progress(force=True, stage="failed", status="failed", message=analyzer_error_message + "; partial results saved", **final_counters)
else:
    scan_state_mgr.mark_completed()
    _update_live_progress(force=True, stage="completed", status="completed", message="Scan completed", **final_counters)
parser.gen_scan_summary_text(state.scanSummary_Fpath)
scan_state_mgr.uninstall_signal_handlers()

if not os.environ.get("DAKSH_RUNTIME_DIR", "").strip():
    # Plain CLI run (not spawned by the web UI, which sweeps its own
    # per-run diagnostics via scan_runtime.cleanup_run_runtime) - the
    # decision-trace JSONL files have no reader once the run is done.
    cleanup_trace_dir()

if analyzer_error_message:
    raise SystemExit(1)

if not os.environ.get("DAKSH_RUNTIME_DIR", "").strip():
    # Plain CLI run (not spawned by the web UI, which sweeps its own
    # per-run diagnostics via scan_runtime.cleanup_run_runtime) - the
    # decision-trace JSONL files have no reader once the run is done.
    cleanup_trace_dir()
