# Standard libraries
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from timeit import default_timer as timer

# Local application imports
from core import rdl
import state.runtime_state as state
import utils.file_utils as futils
import utils.suppression_utils as supp
from utils.log_utils import get_logger

logger = get_logger(__name__)

_TAINT_SIGNAL_PATTERN = re.compile(
    r"(\$_(get|post|request|cookie|server)|request\.getparameter|getparameter\(|requestparameters|"
    r"document\.cookie|location\.|innerhtml|document\.write|req\.(query|body|params)|"
    r"intent\.get\w*extra|sharedpreferences|gettext\(\)|querystring|argv|args\[)",
    re.IGNORECASE,
)

_SINK_SIGNAL_PATTERN = re.compile(
    r"(mysqli?_query|preparestatement|execute(query|update)?|runtime\s*\.\s*getruntime\s*\(\)\s*\.\s*exec|"
    r"processbuilder|eval\s*\(|exec\s*\(|shell_exec|popen|system\s*\(|document\.write|"
    r"innerhtml|outerhtml|loadurl|contentresolver\.query|unserialize\s*\()",
    re.IGNORECASE,
)

_DYNAMIC_CONSTRUCTION_PATTERN = re.compile(
    r"(\.\s*\$|\+\s*\$|\$\{|concat\s*\(|string\.format|append\s*\(|\$query\b|\$sql\b|"
    r"template\s*literal|f\"|f')",
    re.IGNORECASE,
)

_VARIABLE_ARG_CALL_PATTERN = re.compile(r"\w+\s*\([^)]*\$[a-z_]\w*[^)]*\)", re.IGNORECASE)


def _derive_issue_scope(category_name, platform_name):
    """
    Infer finding scope for reporting without changing existing output structure.
    """
    category_text = (category_name or "").lower()
    platform_text = (platform_name or "").lower()

    if "framework-specific" in category_text:
        return "framework_specific"
    if "platform-specific" in category_text:
        return "platform_specific"
    if platform_text == "common":
        return "common"

    framework_like = {
        "reactnative", "flutter", "xamarin", "ionic", "nativescript", "cordova"
    }
    if platform_text in framework_like:
        return "framework_specific"

    return "platform_specific"


def _clamp_score(score, low=0, high=100):
    return max(low, min(high, int(round(score))))


def _confidence_level(score):
    if score >= 80:
        return "high"
    if score >= 60:
        return "medium"
    return "low"


def _compute_source_confidence_score(evidence, has_regex=False, has_rdl=False, has_descriptions=False):
    """
    Heuristic confidence score for source-code matches.
    """
    evidence = evidence or []
    evidence_count = len(evidence)
    unique_files = len({ev.get("file", "") for ev in evidence if isinstance(ev, dict)})

    # Confidence should represent precision of the match, not only the number of hits.
    score = 28
    score += min(10, evidence_count * 2)
    score += min(6, unique_files * 2)
    if has_regex:
        score += 8
    if has_rdl:
        score += 6
    if has_descriptions:
        score += 2

    placeholder_hits = 0
    taint_lines = 0
    sink_lines = 0
    direct_taint_to_sink_lines = 0
    dynamic_query_lines = 0
    sink_only_lines = 0

    for ev in evidence:
        if not isinstance(ev, dict):
            continue
        code = str(ev.get("code", "")).strip().lower()
        if code in {"[rdl condition matched]", "[rdl matched]"}:
            placeholder_hits += 1
            continue

        has_taint_signal = bool(_TAINT_SIGNAL_PATTERN.search(code))
        has_sink_signal = bool(_SINK_SIGNAL_PATTERN.search(code))
        has_dynamic_signal = bool(_DYNAMIC_CONSTRUCTION_PATTERN.search(code))

        if has_taint_signal:
            taint_lines += 1
        if has_sink_signal:
            sink_lines += 1
        if has_sink_signal and has_taint_signal:
            direct_taint_to_sink_lines += 1
        if has_sink_signal and has_dynamic_signal:
            dynamic_query_lines += 1
        if has_sink_signal and not has_taint_signal and _VARIABLE_ARG_CALL_PATTERN.search(code):
            sink_only_lines += 1

    score += min(28, direct_taint_to_sink_lines * 12)
    score += min(16, taint_lines * 4)
    score += min(12, dynamic_query_lines * 4)
    score -= min(18, placeholder_hits * 6)
    score -= min(18, sink_only_lines * 4)

    # Do not mark as high confidence without direct taint-to-sink proof.
    if direct_taint_to_sink_lines == 0:
        score -= 10
        score = min(score, 74)
        if evidence_count >= 12:
            score -= 6

    # Penalize noisy broad matches where most evidence is sink-only wrappers.
    if sink_lines > 0 and sink_only_lines >= sink_lines:
        score -= 8

    return _clamp_score(score, low=10, high=96)


def _compute_paths_confidence_score(path_count):
    """
    Heuristic confidence score for filepath-based rules.
    """
    count = path_count if isinstance(path_count, int) and path_count > 0 else 0
    score = 50 + min(36, count * 6)
    return _clamp_score(score, low=35, high=96)


def source_parser(rule_input, targetfile, outputfile=None, findings_json_path=None, progress_callback=None):
    """
    Parses rules from XML files and applies them to target files.
    Supports both individual Path and dictionary of Paths as input.

    Parameters:
        rule_input (dict or Path): Rule file paths or a single Path to an XML file.
        targetfile (str): File containing paths of target source files.
        outputfile (str): File to write scan results.

    Returns:
        tuple: (matched_rules, unmatched_rules) - Lists of rule titles for matched and unmatched patterns.
    """

    if isinstance(rule_input, dict):
        rule_paths = rule_input.values()
    elif isinstance(rule_input, Path):
        rule_paths = [rule_input]
    else:
        raise TypeError(f"Expected a dict or Path, but got {type(rule_input)}")

    f_scanout = outputfile
    f_targetfiles = targetfile
    findings_json = []
    if findings_json_path and Path(findings_json_path).exists():
        try:
            findings_json = json.loads(Path(findings_json_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            findings_json = []

    iCnt = 0
    rule_no = state.rCnt
    error_count = 0
    matched_rules = []
    unmatched_rules = []

    for rule_path in rule_paths:
        try:
            xmltree = ET.parse(rule_path)
            root = xmltree.getroot()
        except ET.ParseError as exc:
            logger.error("Failed to parse rules file %s: %s", rule_path, exc)
            continue

        platform_name = rule_path.stem.upper()
        rule_no = 0

        if f_scanout:
            f_scanout.write(f"\n--- {platform_name} Findings ---\n")

        for category in root:
            category_name = category.get('name')
            if category_name:
                print(f"         [-] Category: {category_name}")

            for rule in category:
                rule_title = (rule.findtext("name") or "").strip()
                pattern_text = (rule.findtext("regex") or "").strip()
                rdl_text = (rule.findtext("rdl") or "").strip()
                rule_desc = (rule.findtext("rule_desc") or "").strip()
                vuln_desc = (rule.findtext("vuln_desc") or "").strip()
                dev_note = (rule.findtext("developer") or "").strip()
                rev_note = (rule.findtext("reviewer") or "").strip()
                exclude_text = (rule.findtext("exclude") or "").strip()

                if not rule_title or (not pattern_text and not rdl_text):
                    logger.warning("Skipping malformed rule in %s under category %s", rule_path, category_name)
                    continue

                pattern = None
                if pattern_text:
                    try:
                        pattern = re.compile(pattern_text)
                    except re.error as exc:
                        logger.error("Invalid regex in rule %s (%s): %s", rule_title, rule_path, exc)
                        unmatched_rules.append(rule_title)
                        continue

                exclude = None
                if exclude_text:
                    try:
                        exclude = re.compile(exclude_text, re.IGNORECASE)
                    except re.error as exc:
                        logger.error("Invalid exclude regex in rule %s (%s): %s", rule_title, rule_path, exc)
                        exclude = None

                if str(state.verbosity) in ('1', '2'):
                    print(f"         [-] Applying Rule: {rule_title}", end='\r')
                else:
                    sys.stdout.write("\033[K")
                    print(f"         [-] Applying Rule: {rule_title}")

                finding_index = None
                rule_has_unsuppressed_match = False

                for file_index, eachfilepath in enumerate(f_targetfiles, start=1):
                    filepath = eachfilepath.rstrip()
                    iCnt += 1

                    if str(state.verbosity) == '1':
                        if len(filepath) > 50:
                            print('\t Parsing file: ' + "[" + str(iCnt) + "] " + futils.get_short_path(filepath), end='\r')
                        else:
                            print('\t Parsing file: ' + "[" + str(iCnt) + "] " + filepath, end='\r')
                    else:
                        print('\t Parsing file: ' + "[" + str(iCnt) + "] " + futils.get_source_file_path(state.sourcedir, filepath), end='\r')

                    sys.stdout.write("\033[K")

                    try:
                        with futils.readfile_FallbackEncoding(filepath) as fo_target:
                            content = fo_target.read()
                    except (FileNotFoundError, PermissionError, UnicodeError, IOError) as exc:
                        print(f"Error processing {filepath}: {exc}")
                        error_count += 1
                        if callable(progress_callback):
                            progress_callback({
                                "scope": "source_parser",
                                "platform": platform_name,
                                "category": category_name,
                                "rule_title": rule_title,
                                "file_index": file_index,
                                "filepath": filepath,
                                "status": "read_error",
                                "error_count": error_count,
                            })
                        continue

                    file_lines = content.splitlines()
                    candidate_evidence = []

                    if pattern is not None:
                        for linecount, line in enumerate(file_lines, start=1):
                            if len(line) > 500:
                                continue
                            if not pattern.search(line):
                                continue
                            if exclude and exclude.search(line):
                                continue
                            candidate_evidence.append((linecount, line))

                    if rdl_text and rdl.evaluate_rdl(rdl_text, content):
                        flag_pattern = rdl.extract_flag_pattern(rdl_text)
                        rdl_evidence_added = False
                        if flag_pattern:
                            try:
                                flag_regex = re.compile(flag_pattern, re.IGNORECASE)
                                for linecount, line in enumerate(file_lines, start=1):
                                    if len(line) > 500:
                                        continue
                                    if not flag_regex.search(line):
                                        continue
                                    if exclude and exclude.search(line):
                                        continue
                                    candidate_evidence.append((linecount, line))
                                    rdl_evidence_added = True
                            except re.error as exc:
                                logger.error("Invalid FLAG regex in RDL for rule %s (%s): %s", rule_title, rule_path, exc)
                        if not rdl_evidence_added and not flag_pattern and file_lines:
                            candidate_evidence.append((1, "[RDL condition matched]"))

                    if not candidate_evidence:
                        continue

                    rel_path = futils.get_source_file_path(state.sourcedir, filepath)
                    seen_lines = set()
                    for linecount, line in candidate_evidence:
                        if linecount in seen_lines:
                            continue
                        seen_lines.add(linecount)

                        short_line = (line[:75] + '..') if len(line) > 300 else line
                        if supp.is_suppressed(
                            state.suppressions,
                            platform_name,
                            rule_title,
                            category_name,
                            rel_path,
                            linecount,
                            short_line.strip(),
                        ):
                            state.suppressedFindingsCnt += 1
                            continue

                        if finding_index is None:
                            if rule_no > 0 and f_scanout:
                                f_scanout.write("\n\n")
                            rule_no += 1
                            state.rulesMatchCnt += 1
                            matched_rules.append(rule_title)
                            rule_has_unsuppressed_match = True

                            if f_scanout:
                                f_scanout.write(
                                    f"\n{platform_name}-{rule_no}. Rule Title: {rule_title}\n"
                                    f"\n\t Rule Description  : {rule_desc}"
                                    f"\n\t Issue Description : {vuln_desc}"
                                    f"\n\t Developer Note    : {dev_note}"
                                    f"\n\t Reviewer Note     : {rev_note}\n"
                                )

                            findings_json.append({
                                "platform": platform_name,
                                "rule_id": f"{platform_name}-{rule_no}",
                                "rule_title": rule_title,
                                "category": category_name,
                                "issue_scope": _derive_issue_scope(category_name, platform_name),
                                "rule_desc": rule_desc,
                                "issue_desc": vuln_desc,
                                "developer_note": dev_note,
                                "reviewer_note": rev_note,
                                "confidence_score": 0,
                                "confidence_level": "low",
                                "evidence": []
                            })
                            finding_index = len(findings_json) - 1

                        if f_scanout:
                            f_scanout.write(
                                f"\n\t -> Source File: {rel_path}\n"
                                f"\t\t [{linecount}] {short_line}"
                            )
                        findings_json[finding_index]["evidence"].append({
                            "file": rel_path,
                            "line": linecount,
                            "code": short_line.strip()
                        })
                        score = _compute_source_confidence_score(
                            findings_json[finding_index].get("evidence", []),
                            has_regex=bool(pattern_text),
                            has_rdl=bool(rdl_text),
                            has_descriptions=bool(rule_desc or vuln_desc),
                        )
                        findings_json[finding_index]["confidence_score"] = score
                        findings_json[finding_index]["confidence_level"] = _confidence_level(score)

                    if callable(progress_callback):
                        progress_callback({
                            "scope": "source_parser",
                            "platform": platform_name,
                            "category": category_name,
                            "rule_title": rule_title,
                            "file_index": file_index,
                            "filepath": filepath,
                            "matched_evidence_count": len(candidate_evidence),
                            "rules_match_count": state.rulesMatchCnt,
                            "suppressed_count": state.suppressedFindingsCnt,
                        })

                f_targetfiles.seek(0)
                state.rCnt = rule_no
                iCnt = 0

                if not rule_has_unsuppressed_match:
                    unmatched_rules.append(rule_title)

    matched_rules = list(set(matched_rules))
    unmatched_rules = list(set(unmatched_rules))
    state.parseErrorCnt += error_count

    if findings_json_path:
        try:
            out_path = Path(findings_json_path)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(findings_json, indent=2), encoding="utf-8")
        except OSError as exc:
            logger.error("Failed to write findings JSON %s: %s", findings_json_path, exc)

    return matched_rules, unmatched_rules





def paths_parser(rule_path, targetfile, outputfile=None, rule_no=None, findings_json_path=None, progress_callback=None):
    """
    Parses file paths and matches them against specified patterns from an XML rule file.

    This routine reads the XML rules, checks each file path from the target file against 
    the defined regex patterns, and categorizes them into matched and unmatched rules.

    Parameters:
        rule_path (str): Path to the XML file containing matching rules.
        targetfile (file-like object): File object containing paths to be scanned.
        outputfile (file-like object): File object for writing matched results.
        rule_no (int): The initial rule number for matched output.

    Returns:
        tuple: A list of matched rules and a list of unmatched rules.
    """

    matched_rules = []       # List to store matched patterns
    unmatched_rules = []     # List to store unmatched patterns

    # Load rules from XML file
    try:
        xmltree = ET.parse(rule_path)
        rule = xmltree.getroot()
    except ET.ParseError as exc:
        logger.error("Failed to parse file path rules %s: %s", rule_path, exc)
        return matched_rules, unmatched_rules

    f_scanout = outputfile
    f_targetfilepaths = targetfile
    pFlag = False

    rule_no = rule_no or 0
    findings_json = []
    if findings_json_path and Path(findings_json_path).exists():
        try:
            findings_json = json.loads(Path(findings_json_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            findings_json = []

    for r in rule:
        #rule_no += 1
        #f_scanout.write(f"{rule_no}. Rule Title: {r.find('name').text}\n")

        pattern = r.find("regex").text
        pattern_name = r.find("name").text

        for file_index, eachfilepath in enumerate(f_targetfilepaths, start=1):  # Read each line (file path) in the file
            filepath = eachfilepath.rstrip()    # strip out '\r' or '\n' from the file paths
            filepath = futils.get_source_file_path(state.sourcedir, filepath)

            if re.findall(pattern, filepath, flags=re.IGNORECASE):   # If there is a match
                if pFlag == False:
                    rule_no += 1
                    state.rulesPathsMatchCnt += 1
                    matched_rules.append(pattern_name)  # Add matched patterns to the list
                    if f_scanout:
                        f_scanout.write(f"{rule_no}. Rule Title: {r.find('name').text}\n")
                        f_scanout.write(("\tFile Path: " + filepath) + "\n")
                    print("     [-] File Path Rule:" + pattern_name)

                    findings_json.append({
                        "rule_title": pattern_name,
                        "filepath": [filepath],
                        "confidence_score": _compute_paths_confidence_score(1),
                        "confidence_level": _confidence_level(_compute_paths_confidence_score(1)),
                    })

                    sys.stdout.write("\033[F") #back to previous line
                    sys.stdout.write("\033[K") #clear line to prevent overlap of texts
                    
                    pFlag = True
                else: 
                    if f_scanout:
                        f_scanout.write(("\tFile Path: " + filepath) + "\n")
                    findings_json[-1]["filepath"].append(filepath)
                    path_count = len(findings_json[-1]["filepath"])
                    path_score = _compute_paths_confidence_score(path_count)
                    findings_json[-1]["confidence_score"] = path_score
                    findings_json[-1]["confidence_level"] = _confidence_level(path_score)
                
            else:
                unmatched_rules.append(pattern_name)  # Add unmatched items to the list

            if callable(progress_callback):
                progress_callback({
                    "scope": "paths_parser",
                    "rule_title": pattern_name,
                    "file_index": file_index,
                    "filepath": filepath,
                    "matched_rules_count": len(matched_rules),
                    "paths_match_count": state.rulesPathsMatchCnt,
                })

        pFlag = False
        f_targetfilepaths.seek(0, 0)

    # Remove duplicates from unmatched items list
    unmatched_rules = list(set(unmatched_rules))

    if findings_json_path:
        try:
            out_path = Path(findings_json_path)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(json.dumps(findings_json, indent=2), encoding="utf-8")
        except OSError as exc:
            logger.error("Failed to write path findings JSON %s: %s", findings_json_path, exc)

    return matched_rules, unmatched_rules




def gen_scan_summary_text(file_path):
    """
    Generates a summary report from JSON scan data and writes it to a text file.

    This routine reads the specified JSON file, extracts relevant input and detection 
    summary information, and formats it for output to a summary text file.

    Parameters:
        file_path (str): Path to the JSON file containing scan data.

    Returns:
        None: The function writes the summary directly to a specified output file.
    """

    def format_file_extensions(file_extensions_dict):
        formatted_file_extensions = ""
        for language, extensions in file_extensions_dict.items():
            formatted_file_extensions += f"{language}: {', '.join(extensions)}\n"
        return formatted_file_extensions

    def format_key_value(key, value, indent_level=0, is_sub_key=False):
        indent = "    " * indent_level
        prefix = "[-] " if is_sub_key else "[+] "
        return f"{indent}{prefix}{key}: {value}\n"

    with open(file_path, 'r') as file:
        json_data = json.load(file)

    # JSON-only summary write (copy scan summary to reports json summary)
    json_output_path = Path(state.outputSummary_JSON)
    try:
        json_output_path.parent.mkdir(parents=True, exist_ok=True)
        json_output_path.write_text(json.dumps(json_data, indent=2), encoding="utf-8")
    except OSError as exc:
        logger.error("Failed to write JSON summary %s: %s", json_output_path, exc)


# Backward-compatible aliases for legacy callers.
sourceParser = source_parser
pathsParser = paths_parser
genScanSummaryText = gen_scan_summary_text
