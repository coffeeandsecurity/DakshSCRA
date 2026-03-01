# Standard libraries
import argparse
import atexit
import os
import re
import sys
import time
from datetime import datetime
from os import path  # This lowercase path to be used only to validate whether a directory exists
from pathlib import Path  # Resolve the Windows / macOS / Linux path issue

# Local application imports
import core.discovery as discover
import core.estimator as estimate
import core.parser as parser
import core.recon as rec
import core.reports as report

from core.analysis.php import analyzer as php_analysis
from core.analysis.dotnet import analyzer as dotnet_analysis
from core.analysis.java import analyzer as java_analysis
from core.analysis.python import analyzer as py_analysis
from core.analysis.javascript import analyzer as js_analysis
from core.analysis.golang import analyzer as go_analysis

import state.constants as constants
import state.runtime_state as state

import utils.cli_utils as cli
import utils.config_utils as cutils
import utils.file_utils as futils
import utils.result_utils as result
import utils.rules_utils as rutils
import utils.string_utils as strutils
import utils.suppression_utils as supp
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
        "  dakshscra.py -l RF\n\n"
        "Notes:\n"
        "  - If -f is not provided, default filetypes for selected platform(s) are used.\n"
        "  - Use -r auto to detect file types and auto-apply relevant platform rules.\n"
        "  - Use -recon alone to detect technology stack without scanning.\n"
        "  - Use -rs (or --recon-strict) with -recon for high-confidence recon output."
    ),
)

scan_group = args.add_argument_group("Scan options")
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
                        help='List rules [R] or rules + filetypes [RF]')

mode_group.add_argument('-recon', action='store_true', dest='recon',
                        help='Run reconnaissance (platform/framework/language detection)')

mode_group.add_argument('-rs', '-recons', '--recon-strict', action='store_true', dest='recon_strict',
                        help='Strict recon filter (use with -recon): high-confidence framework/platform detections only')

mode_group.add_argument('-estimate', action='store_true', dest='estimate',
                        help='Estimate code review effort based on codebase size')

output_group.add_argument('-rpt', '--report', type=str, action='store', dest='report_format',
                          default='html,pdf', metavar='FORMATS',
                          help='Report types: html, pdf, or html,pdf')

advanced_group.add_argument('--analysis', '--analyse', action='store_true', dest='analysis',
                            help='Run experimental data/control flow analysis')

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

advanced_group.add_argument('--state-file', type=str, dest='state_file',
                            default='', metavar='PATH',
                            help='Custom scan state/checkpoint file path')

advanced_group.add_argument('--state-disable', action='store_true', dest='state_disable',
                            help='Disable scan state checkpointing for this run')

advanced_group.add_argument('--state-enable', action='store_true', dest='state_enable',
                            help='Force enable scan state checkpointing for this run')

# Display help if no arguments are passed
if len(sys.argv) < 2:
    args.print_help()
    sys.exit(1)

# Parse arguments with error handling
results = args.parse_args()

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

state_cfg = cutils.get_state_management_config()
state_enabled = (state_cfg["enabled"] and not results.state_disable) or results.state_enable
state_file_path = results.state_file.strip() if results.state_file else state_cfg["default_state_file"]
if not Path(state_file_path).is_absolute():
    state_file_path = str(Path(state.root_dir) / state_file_path)

scan_state_mgr = ScanStateManager(
    state_file=state_file_path,
    enabled=state_enabled,
    persist_after_seconds=state_cfg["persist_after_seconds"],
    persist_interval_seconds=state_cfg["persist_interval_seconds"],
    cleanup_on_success=state_cfg["cleanup_on_success"],
)

should_preserve_runtime = bool(results.resume_scan)
if not should_preserve_runtime:
    futils.dir_cleanup("runtime")
    futils.dir_cleanup("runtime/platform")
    futils.dir_cleanup("reports/html")
    futils.dir_cleanup("reports/pdf")
    futils.dir_cleanup("reports/json")
    futils.dir_cleanup_recursive("reports/analysis")

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

# Priority #1 - recon/estimate only
if (results.recon or results.estimate) and results.target_dir and not results.rule_file:
    print(constants.AUTHOR_BANNER.format(version=version))
    if not path.isdir(results.target_dir):
        print("\nInvalid target directory :" + results.target_dir + "\n")
        cli.tool_usage("invalid_dir")
        sys.exit(1)
    targetdir = results.target_dir
    if results.recon and not results.estimate:
        rec.recon(targetdir, False, strict_mode=results.recon_strict)
        sys.exit(1)
    elif results.estimate and not results.recon:
        _, recSummary = rec.recon(targetdir, False, strict_mode=results.recon_strict)
        estimate.effort_estimator(recSummary)
        sys.exit(1)
    else:
        _, recSummary = rec.recon(targetdir, False, strict_mode=results.recon_strict)
        estimate.effort_estimator(recSummary)
        sys.exit(1)

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

    result.update_scan_summary("inputs_received.rule_selected", display_rule_file)
    result.update_scan_summary("inputs_received.filetypes_selected", display_file_types)
    result.update_scan_summary("inputs_received.target_directory", results.target_dir)

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

# Auto-detect rule types
if original_rule_file and original_rule_file.lower() == "auto":
    print("     [-] Auto-detecting applicable platform types... ", end="", flush=True)
    spinner("start")
    detected = discover.auto_detect_rule_types(results.target_dir)
    results.rule_file = detected
    results.file_types = detected
    spinner("stop")
    print(f"     [-] Detected Platform(s) : {detected}")

codebase = results.file_types

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
total_rules_loaded = sum(map(int, rule_counts)) + common_rules_total

cli.section_print(f"[*] Rules Loaded")
print(f"     [-] Platform Rules       : {platform_rules_total}")
print(f"     [-] Common Rules         : {common_rules_total}")
print(f"     [-] Total Rules Loaded   : {total_rules_loaded}")

result.update_scan_summary("inputs_received.platform_specific_rules", platform_rules_total)
result.update_scan_summary("inputs_received.common_rules", str(common_rules_total))
result.update_scan_summary("inputs_received.total_rules_loaded", str(total_rules_loaded))

resume_progress = {}
if results.rule_file:
    scan_fingerprint = {
        "target_dir": str(results.target_dir),
        "rule_file": str(results.rule_file),
        "file_types": str(results.file_types),
        "recon": bool(results.recon),
        "recon_strict": bool(results.recon_strict),
    }
    scan_config = {
        "state_file": str(state_file_path),
        "state_enabled": bool(state_enabled),
        "persist_after_seconds": state_cfg["persist_after_seconds"],
        "persist_interval_seconds": state_cfg["persist_interval_seconds"],
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
state.start_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

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
        rec.recon(results.target_dir, True, strict_mode=results.recon_strict)
        sCnt += 1
        cli.section_print(f"[*] [Stage {sCnt}] File Path Discovery")
        master_file_paths, platform_file_paths = discover.discover_files(codebase, sourcepath, 1)
    else:
        cli.section_print(f"[*] [Stage {sCnt}] File Path Discovery")
        master_file_paths, platform_file_paths = discover.discover_files(codebase, sourcepath, 1)

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

# Platform-specific rules
if results.rule_file.lower() not in ['common']:
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
            completed_platforms.add(platform.upper())
            scan_state_mgr.mark_platform_completed(platform.upper())
            scan_state_mgr.update_stage("pattern_matching", "running", {
                "completed_platforms": sorted(completed_platforms),
                "common_rules_done": common_rules_done,
            })

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
os.unlink(master_file_paths)
scan_state_mgr.mark_path_analysis_completed()

cli.section_print(f"[*] Scanning Timeline")
print("    [-] Scan start time     : " + str(state.start_timestamp))
end_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
print("    [-] Scan end time       : " + str(end_timestamp))
hours, rem = divmod(time.time() - state.start_time, 3600)
minutes, seconds = divmod(rem, 60)
seconds, milliseconds = str(seconds).split('.')
scan_duration = "{:0>2}Hr:{:0>2}Min:{:0>2}s:{}ms".format(int(hours), int(minutes), seconds, milliseconds[:3])
print(f"    [-] Scan completed in   : {scan_duration}")

result.update_scan_summary("scanning_timeline.scan_start_time", state.start_timestamp)
result.update_scan_summary("scanning_timeline.scan_end_time", end_timestamp)
result.update_scan_summary("scanning_timeline.scan_duration", scan_duration)

parser.gen_scan_summary_text(state.scanSummary_Fpath)

if results.baseline_generate:
    baseline_count = supp.build_baseline_from_findings(state.outputAoI_JSON, state.suppressionBaseline)
    print(f"     [-] Baseline generated   : {baseline_count} entries")

###### [Stage 4] Generate Reports ######
scan_state_mgr.update_stage("reporting", "running")
valid_formats = {"html", "pdf"}
requested_formats = results.report_format.lower().replace(" ", "").split(",")
selected_formats = [fmt for fmt in requested_formats if fmt in valid_formats]

if selected_formats:
    report.gen_report(formats=",".join(selected_formats))
else:
    print("[!] No valid report format selected. Defaulting to 'html,pdf'.")
    report.gen_report(formats="html,pdf")
scan_state_mgr.update_stage("reporting", "completed")

# Experimental: dataflow/control flow analysis per platform
if results.analysis:
    analyzers = {
        "python": py_analysis.run,
        "php": php_analysis.run,
        "javascript": js_analysis.run,
        "java": java_analysis.run,
        "dotnet": dotnet_analysis.run,
        "golang": go_analysis.run,
    }
    platform_aliases = {
        "py": "python",
        "python": "python",
        "php": "php",
        "js": "javascript",
        "javascript": "javascript",
        "node": "javascript",
        "nodejs": "javascript",
        "java": "java",
        "dotnet": "dotnet",
        ".net": "dotnet",
        "csharp": "dotnet",
        "c#": "dotnet",
        "go": "golang",
        "golang": "golang",
    }
    selected_platforms = {
        platform_aliases.get(r.strip().lower(), r.strip().lower())
        for r in results.rule_file.split(",")
        if r.strip()
    }
    for platform, runner in analyzers.items():
        if platform in selected_platforms and runner:
            try:
                flow_json, flow_html = runner(sourcepath)
                print(f"     [-] {platform.capitalize()} dataflow report (JSON):", re.sub(str(state.root_dir), "", str(flow_json)))
                print(f"     [-] {platform.capitalize()} dataflow report (HTML):", re.sub(str(state.root_dir), "", str(flow_html)))
            except Exception as exc:
                print(f"[!] {platform.capitalize()} dataflow analysis failed: {exc}")

cutils.update_project_config("","")     # Clean up project details in the config file
scan_state_mgr.mark_completed()
scan_state_mgr.uninstall_signal_handlers()
