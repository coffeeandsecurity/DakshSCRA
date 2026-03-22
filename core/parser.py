# Standard libraries
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from timeit import default_timer as timer

# Local application imports
from core import rdl_engine
import state.runtime_state as state
import utils.file_utils as futils
import utils.suppression_utils as supp
from utils.log_utils import get_logger

logger = get_logger(__name__)


def _resolve_logic_file(rule_path, logic_ref):
    if not logic_ref:
        return None
    ref_path = Path(logic_ref)
    if ref_path.is_absolute():
        return ref_path
    base = Path(state.root_dir) / "rules" / "scanning"
    candidate = (base / ref_path).resolve()
    return candidate


def _build_logic_meta(engine, logic_ref, logic_result=None, comparison=None):
    if not engine:
        return {}
    meta = {
        "logic_engine": engine,
    }
    if logic_ref:
        meta["logic_source"] = logic_ref
    if logic_result:
        if logic_result.get("reason"):
            meta["logic_reason"] = logic_result["reason"]
        if logic_result.get("trace"):
            meta["logic_trace"] = logic_result["trace"]
        if logic_result.get("consulted_files"):
            meta["logic_consulted_files"] = logic_result["consulted_files"]
        if logic_result.get("outcome"):
            meta["logic_outcome"] = logic_result["outcome"]
    if comparison:
        meta["logic_comparison"] = comparison
    return meta


def _merge_logic_meta(target, meta):
    if not isinstance(target, dict) or not isinstance(meta, dict):
        return
    for key in ("logic_engine", "logic_source", "logic_reason", "logic_outcome"):
        if meta.get(key) and not target.get(key):
            target[key] = meta[key]
    for key in ("logic_trace", "logic_consulted_files"):
        values = meta.get(key) or []
        if not values:
            continue
        merged = list(target.get(key, []))
        for value in values:
            if value not in merged:
                merged.append(value)
        target[key] = merged
    if meta.get("logic_comparison") and not target.get("logic_comparison"):
        target["logic_comparison"] = meta["logic_comparison"]


def _extract_rdl_logic_evidence_pattern(rdl_text):
    """
    Derive a line/file evidence regex from an external .rdl script.
    Prefer direct match operators that anchor the rule to content in the current file.
    """
    if not rdl_text:
        return None

    for raw_line in rdl_text.splitlines():
        line = (raw_line or "").strip()
        if not line or line.startswith("#"):
            continue
        upper = line.upper()
        if upper.startswith("WHEN PRESENT "):
            return line[len("WHEN PRESENT "):].strip() or None
        if upper.startswith("WHEN CURRENT_FILE_MATCHES "):
            return line[len("WHEN CURRENT_FILE_MATCHES "):].strip() or None

    return None

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


def _parse_scan_config(rule_element):
    """
    Parse the optional <scan_config> block from a rule element.
    Returns a dict of all scan_config fields with safe defaults.
    Missing block or missing individual fields all fall back to defaults.
    """
    sc = rule_element.find("scan_config")
    defaults = {
        "match_mode": "line",
        "context_type": "none",
        "context_lines_before": 0,
        "context_lines_after": 0,
        "context_pattern": "",
        "context_depth": 10,
        "aggregate": "none",
        "report_format": "default",
        "highlight_enabled": True,
        "highlight_target": "match",
        "highlight_groups": "",
        "highlight_pattern": "",
        "highlight_color": "red",
        "marks": [],
    }
    if sc is None:
        return defaults

    def _text(tag, default=""):
        el = sc.find(tag)
        return el.text.strip() if el is not None and el.text else default

    def _int(tag, default=0):
        val = _text(tag, str(default))
        try:
            return int(val)
        except (ValueError, TypeError):
            return default

    def _bool(tag, default=True):
        val = _text(tag, "true" if default else "false").lower()
        return val not in ("false", "0", "no")

    marks = []
    marks_el = sc.find("marks")
    if marks_el is not None:
        for mark_el in marks_el.findall("mark"):
            color = mark_el.get("color", "red")
            spec = mark_el.text.strip() if mark_el.text else "match"
            marks.append({"color": color, "spec": spec})

    lines_before = _int("context_lines_before", 0)
    lines_after = _int("context_lines_after", 0)
    # Auto-infer context_type: if context line counts are set but context_type
    # is not explicitly specified, default to "lines" rather than "none".
    explicit_ctx_type = _text("context_type", "")
    if explicit_ctx_type:
        ctx_type = explicit_ctx_type
    elif lines_before > 0 or lines_after > 0:
        ctx_type = "lines"
    else:
        ctx_type = "none"

    return {
        "match_mode": _text("match_mode", "line"),
        "context_type": ctx_type,
        "context_lines_before": lines_before,
        "context_lines_after": lines_after,
        "context_pattern": _text("context_pattern", ""),
        "context_depth": _int("context_depth", 10),
        "aggregate": _text("aggregate", "none"),
        "report_format": _text("report_format", "default"),
        "highlight_enabled": _bool("highlight_enabled", True),
        "highlight_target": _text("highlight_target", "match"),
        "highlight_groups": _text("highlight_groups", ""),
        "highlight_pattern": _text("highlight_pattern", ""),
        "highlight_color": _text("highlight_color", "red"),
        "marks": marks,
    }


def _collect_context_lines(file_lines, linecount, lines_before, lines_after):
    """
    Return (before, after) as lists of {"line": int, "code": str} dicts.
    linecount is 1-based. file_lines is a 0-based list of strings.
    """
    idx = linecount - 1  # convert to 0-based
    total = len(file_lines)

    before = []
    if lines_before > 0:
        start = max(0, idx - lines_before)
        for i in range(start, idx):
            before.append({"line": i + 1, "code": file_lines[i]})

    after = []
    if lines_after > 0:
        end = min(total, idx + 1 + lines_after)
        for i in range(idx + 1, end):
            after.append({"line": i + 1, "code": file_lines[i]})

    return before, after


def _match_full_file(pattern, content, file_lines, exclude):
    """
    Apply pattern to full file content with MULTILINE|DOTALL.
    Returns list of (linecount, matched_text, groups_dict) tuples.
    linecount is the 1-based line number of the match start.
    groups_dict holds named capture groups from the match (may be empty).
    """
    try:
        full_pattern = re.compile(pattern.pattern, re.MULTILINE | re.DOTALL)
    except re.error:
        full_pattern = pattern

    results = []
    for m in full_pattern.finditer(content):
        # Determine line number of match start
        linecount = content.count('\n', 0, m.start()) + 1
        # Get the matched text (first line only for display)
        matched_text = m.group(0)
        first_line = matched_text.split('\n', 1)[0]

        if exclude and exclude.search(first_line):
            continue

        groups = m.groupdict() if m.groupdict() else {}
        # Remove None values from named groups
        groups = {k: v for k, v in groups.items() if v is not None}

        results.append((linecount, first_line, groups))

    return results


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


FILEPATH_RULE_GUIDANCE = {
    "Authentication": {
        "brief_desc": "Marks file paths likely involved in login, sign-in, token issuance, or identity verification flows.",
        "attack_desc": "If accurate, these areas are commonly tied to authentication bypass, weak credential handling, insecure token issuance, brute-force exposure, or account takeover paths.",
        "developer_note": "Check that strong authentication controls are in place: secure password handling, MFA where required, lockout or throttling, secure token/session issuance, and no trust in client-side identity assertions.",
        "reviewer_note": "Review how identities are established, challenged, and persisted. Focus on login bypass, credential stuffing resistance, token tampering, password reset abuse, and trust-boundary mistakes around identity state.",
    },
    "Authorization": {
        "brief_desc": "Marks paths likely responsible for permission checks, policy enforcement, role mapping, or access control decisions.",
        "attack_desc": "If accurate, these areas are often linked to privilege escalation, IDOR/BOLA, missing server-side authorization, role confusion, or policy bypass vulnerabilities.",
        "developer_note": "Verify that authorization is enforced server-side on every sensitive action and object reference, with deny-by-default behavior and consistent policy evaluation.",
        "reviewer_note": "Check whether access decisions can be bypassed through alternate routes, direct object references, stale role state, hidden endpoints, or client-controlled privilege indicators.",
    },
    "Session Management": {
        "brief_desc": "Marks files related to session creation, cookies, tokens, or persistence of authenticated state.",
        "attack_desc": "If accurate, these areas may expose session fixation, token replay, insecure cookie settings, weak expiry logic, or stolen-session reuse opportunities.",
        "developer_note": "Confirm secure cookie flags, rotation on privilege change, bounded lifetime, logout invalidation, CSRF protections where relevant, and secure storage of session identifiers.",
        "reviewer_note": "Inspect how session IDs or tokens are issued, renewed, invalidated, and bound to the user context. Look for fixation, replay, insecure transport, and weak revocation paths.",
    },
    "Admin Section": {
        "brief_desc": "Marks paths that likely expose administrative panels, routes, or elevated-management functionality.",
        "attack_desc": "If accurate, these areas may lead to admin-panel exposure, privilege escalation, weak segregation of duties, or high-impact post-auth compromise paths.",
        "developer_note": "Ensure admin functions are isolated, strongly authorized, audited, and not merely hidden by routing or UI controls.",
        "reviewer_note": "Check whether admin endpoints are discoverable, weakly protected, or reachable through alternate routes. Look for missing role checks, unsafe defaults, and sensitive bulk actions.",
    },
    "User Section": {
        "brief_desc": "Marks user-facing account, profile, or account-management paths.",
        "attack_desc": "If accurate, these areas often intersect with IDOR, profile tampering, insecure account updates, broken ownership checks, or account-enumeration issues.",
        "developer_note": "Verify ownership checks, input validation, anti-automation controls for sensitive account actions, and safe handling of user-controlled profile data.",
        "reviewer_note": "Inspect whether one user can act on another user’s records, profiles, or settings by changing identifiers, routes, or hidden form parameters.",
    },
    "Input Validation": {
        "brief_desc": "Marks validator, sanitizer, or input-handling paths that likely mediate untrusted data before sensitive use.",
        "attack_desc": "If accurate, these areas may be tied to injection flaws, business-logic abuse, parser confusion, canonicalization bugs, or inconsistent validation across entry points.",
        "developer_note": "Check that validation is server-side, context-aware, centralized where possible, and paired with output encoding or parameterization rather than used as the only defense.",
        "reviewer_note": "Compare validation across endpoints and input channels. Look for mismatches, weak normalization, allowlist gaps, and alternate routes that bypass the validator.",
    },
    "API": {
        "brief_desc": "Marks routes, handlers, controllers, or endpoint code likely implementing an API surface.",
        "attack_desc": "If accurate, these areas often relate to authn/authz gaps, mass assignment, BOLA/IDOR, excessive data exposure, rate-limit abuse, and unsafe object parsing.",
        "developer_note": "Verify endpoint authentication, authorization, schema validation, output filtering, error handling, and abuse controls such as pagination and rate limiting.",
        "reviewer_note": "Review API trust boundaries end to end. Look for broken object-level authorization, insecure defaults, hidden endpoints, weak rate limits, and overexposed response data.",
    },
    "Libraries | Extensions | Plugins": {
        "brief_desc": "Marks extension, plugin, addon, or library paths that may introduce third-party or modular attack surface.",
        "attack_desc": "If accurate, these areas may bring supply-chain risk, unsafe extension loading, vulnerable dependencies, privilege extension abuse, or weak trust boundaries around plugins.",
        "developer_note": "Check plugin loading rules, extension trust boundaries, dependency provenance, update hygiene, and whether optional modules inherit excessive privileges.",
        "reviewer_note": "Review how third-party components are loaded, configured, and isolated. Focus on unsafe defaults, inherited privileges, stale components, and unreviewed extension hooks.",
    },
    "CAPTCHA": {
        "brief_desc": "Marks files related to CAPTCHA or anti-automation controls.",
        "attack_desc": "If accurate, these areas may be relevant to automation bypass, weak challenge validation, replay of challenge tokens, or ineffective bot resistance.",
        "developer_note": "Verify server-side verification, challenge freshness, correct binding to the intended action, and fallback handling that does not silently disable anti-automation checks.",
        "reviewer_note": "Check whether the CAPTCHA decision is enforced server-side, whether tokens are reusable, and whether alternate flows avoid or downgrade the challenge.",
    },
    "File Upload": {
        "brief_desc": "Marks upload, attachment, or file-ingestion paths where user-controlled content enters the system.",
        "attack_desc": "If accurate, these areas often relate to unrestricted upload, malicious file execution, path traversal, content-type confusion, storage poisoning, or parser exploit chains.",
        "developer_note": "Ensure size/type checks, content validation, path hardening, random storage names, access restrictions, and non-executable storage locations are consistently enforced.",
        "reviewer_note": "Review upload validation, storage paths, post-upload processing, and whether uploaded files can be executed, rendered unsafely, or used to traverse internal paths.",
    },
    "Payment Functionality": {
        "brief_desc": "Marks paths related to billing, checkout, invoices, payments, or transaction workflows.",
        "attack_desc": "If accurate, these areas may expose amount tampering, replay, trust in client-side totals, payment-state confusion, or abuse of callbacks and settlement flows.",
        "developer_note": "Check server-side recalculation of sensitive values, callback verification, idempotency, fraud controls, and strict separation between display data and settlement decisions.",
        "reviewer_note": "Inspect trust boundaries around totals, discounts, callbacks, settlement state, and order/payment reconciliation. Look for replay, race conditions, and client-side trust.",
    },
    "Logging": {
        "brief_desc": "Marks logging, audit, or trace-related paths that may record user actions, failures, or sensitive system events.",
        "attack_desc": "If accurate, these areas may lead to sensitive-data logging, log injection/forgery, weak audit trails, or incident-response blind spots.",
        "developer_note": "Check that logs avoid secrets, normalize attacker-controlled fields, preserve security-relevant audit events, and protect log integrity and retention.",
        "reviewer_note": "Review whether untrusted input can forge log entries, whether secrets or tokens are recorded, and whether critical events are missing, inconsistent, or easily bypassed.",
    },
    "Exception Handling": {
        "brief_desc": "Marks error, exception, or fault-handling paths that shape failures and diagnostics.",
        "attack_desc": "If accurate, these areas may expose stack traces, internal paths, sensitive state, inconsistent fail-open behavior, or bypass of normal security flows during error handling.",
        "developer_note": "Verify exceptions fail closed, sensitive errors are sanitized, security checks are not skipped on error paths, and logging remains useful without leaking secrets.",
        "reviewer_note": "Inspect what users, clients, and logs receive on failure. Look for information disclosure, swallowed auth errors, fallback behavior, and inconsistent transaction rollback.",
    },
    "Database Interaction": {
        "brief_desc": "Marks data-access or query-layer paths likely responsible for reading, writing, or shaping database operations.",
        "attack_desc": "If accurate, these areas may expose SQL/NoSQL injection, weak transaction boundaries, unsafe dynamic queries, mass assignment, or sensitive data over-fetching.",
        "developer_note": "Check parameterization, ORM-safe APIs, transaction handling, least-privilege database access, and controlled selection or update of sensitive fields.",
        "reviewer_note": "Review query construction and persistence behavior for untrusted input influence, unsafe dynamic clauses, weak ownership checks, and overbroad record exposure.",
    },
}


def _file_path_rule_meta(rule_elem):
    name = (rule_elem.findtext("name") or "").strip()
    guidance = FILEPATH_RULE_GUIDANCE.get(name, {})
    rule_desc = (rule_elem.findtext("rule_desc") or "").strip()
    vuln_desc = (rule_elem.findtext("vuln_desc") or "").strip()
    developer = (rule_elem.findtext("developer") or "").strip()
    reviewer = (rule_elem.findtext("reviewer") or "").strip()
    return {
        "brief_desc": guidance.get("brief_desc", rule_desc),
        "attack_desc": guidance.get("attack_desc", vuln_desc),
        "developer_note": guidance.get("developer_note", developer),
        "reviewer_note": guidance.get("reviewer_note", reviewer),
        "rule_desc": rule_desc,
        "vuln_desc": vuln_desc,
    }


def source_parser(rule_input, targetfile, outputfile=None, findings_json_path=None, suppressed_json_path=None, progress_callback=None):
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

    # Derive suppressed_json_path from findings_json_path if not explicitly provided
    if suppressed_json_path is None and findings_json_path:
        suppressed_json_path = str(Path(findings_json_path).parent / "suppressed_findings.json")

    suppressed_json = []
    if suppressed_json_path and Path(suppressed_json_path).exists():
        try:
            suppressed_json = json.loads(Path(suppressed_json_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, TypeError, ValueError):
            suppressed_json = []

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
                rdl_ref = (rule.findtext("rdl_ref") or "").strip()
                rule_desc = (rule.findtext("rule_desc") or "").strip()
                vuln_desc = (rule.findtext("vuln_desc") or "").strip()
                dev_note = (rule.findtext("developer") or "").strip()
                rev_note = (rule.findtext("reviewer") or "").strip()
                exclude_text = (rule.findtext("exclude") or "").strip()
                scan_cfg = _parse_scan_config(rule)

                if not rule_title or (not pattern_text and not rdl_ref):
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
                logic_file_path = _resolve_logic_file(rule_path, rdl_ref) if rdl_ref else None
                rdl_logic_text = ""
                if logic_file_path and logic_file_path.exists():
                    try:
                        rdl_logic_text = rdl_engine.load_rdl(logic_file_path)
                    except OSError as exc:
                        logger.error("Failed to read RDL file %s for rule %s: %s", logic_file_path, rule_title, exc)
                        rdl_logic_text = ""
                rdl_logic_evidence_pattern = _extract_rdl_logic_evidence_pattern(rdl_logic_text)

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
                    # candidate_evidence: list of (linecount, line, groups_dict)
                    candidate_evidence = []

                    use_file_mode = (scan_cfg["match_mode"] == "file")

                    if pattern is not None:
                        if use_file_mode:
                            for linecount, line, groups in _match_full_file(pattern, content, file_lines, exclude):
                                candidate_evidence.append((linecount, line, groups))
                        else:
                            for linecount, line in enumerate(file_lines, start=1):
                                if len(line) > 500:
                                    continue
                                if not pattern.search(line):
                                    continue
                                if exclude and exclude.search(line):
                                    continue
                                m = pattern.search(line)
                                groups = m.groupdict() if m else {}
                                groups = {k: v for k, v in groups.items() if v is not None}
                                candidate_evidence.append((linecount, line, groups))

                    rdl_result = None
                    use_rdl_logic = bool(rdl_logic_text)
                    if use_rdl_logic:
                        rdl_result = rdl_engine.evaluate_rdl_with_reason(
                            rdl_logic_text,
                            file_text=content,
                            file_path=filepath,
                            project_root=state.sourcedir,
                        )

                    active_logic_meta = {}
                    active_logic_passes = None
                    active_logic_reason = ""

                    if use_rdl_logic and rdl_result is not None:
                        active_logic_passes = bool(rdl_result.get("passes"))
                        active_logic_reason = rdl_result.get("fail_reason", "")
                        active_logic_meta = _build_logic_meta(
                            "rdl",
                            rdl_ref,
                            logic_result=rdl_result,
                        )

                    if use_rdl_logic:
                        if active_logic_passes:
                            # RDL passed — add FLAG evidence not already in candidate_evidence
                            flag_pattern_rdl = pattern_text or rdl_logic_evidence_pattern
                            rdl_evidence_added = False
                            if flag_pattern_rdl:
                                try:
                                    flag_regex = re.compile(flag_pattern_rdl, re.IGNORECASE)
                                    for linecount, line in enumerate(file_lines, start=1):
                                        if len(line) > 500:
                                            continue
                                        if not flag_regex.search(line):
                                            continue
                                        if exclude and exclude.search(line):
                                            continue
                                        if not any(ev[0] == linecount for ev in candidate_evidence):
                                            candidate_evidence.append((linecount, line, {}))
                                        rdl_evidence_added = True
                                except re.error as exc:
                                    logger.error("Invalid FLAG regex in RDL for rule %s (%s): %s", rule_title, rule_path, exc)
                            if not rdl_evidence_added and not flag_pattern_rdl and file_lines:
                                candidate_evidence.append((1, "[RDL condition matched]", {}))

                        elif suppressed_json_path and active_logic_reason not in (
                            "FLAG pattern not found in file", "Invalid FLAG pattern in RDL"
                        ):
                            # RDL IF() condition rejected candidates — record them as suppressed FPs.
                            # Build evidence from regex matches plus any FLAG line-level matches
                            # (so RDL-only rules with no <regex> also produce suppressed entries).
                            rdl_suppressed_evidence = list(candidate_evidence)
                            flag_pattern_rdl = pattern_text or rdl_logic_evidence_pattern
                            if flag_pattern_rdl:
                                try:
                                    flag_regex = re.compile(flag_pattern_rdl, re.IGNORECASE)
                                    for linecount, line in enumerate(file_lines, start=1):
                                        if len(line) > 500:
                                            continue
                                        if not flag_regex.search(line):
                                            continue
                                        if exclude and exclude.search(line):
                                            continue
                                        if not any(ev[0] == linecount for ev in rdl_suppressed_evidence):
                                            rdl_suppressed_evidence.append((linecount, line, {}))
                                except re.error:
                                    pass

                            if rdl_suppressed_evidence:
                                rdl_condition = f"RDL:{rdl_ref}"
                                logic_text = rdl_logic_text

                                rel_path = futils.get_source_file_path(state.sourcedir, filepath)
                                ctx_type = scan_cfg["context_type"]
                                lines_before = scan_cfg["context_lines_before"]
                                lines_after = scan_cfg["context_lines_after"]

                                for linecount, line, groups in rdl_suppressed_evidence:
                                    short_line = (line[:75] + '..') if len(line) > 300 else line
                                    sup_entry = {
                                        "id": f"sup_{len(suppressed_json) + 1}",
                                        "platform": platform_name,
                                        "rule_title": rule_title,
                                        "category": category_name,
                                        "file": rel_path,
                                        "line": linecount,
                                        "code": short_line.strip(),
                                        "rdl_text": logic_text,
                                        "rdl_condition": rdl_condition,
                                        "suppression_reason": active_logic_reason,
                                        "suppressed_at": None,
                                        "status": "suppressed",
                                    }
                                    _merge_logic_meta(sup_entry, active_logic_meta)
                                    if ctx_type == "lines" and (lines_before > 0 or lines_after > 0):
                                        ctx_before, ctx_after = _collect_context_lines(
                                            file_lines, linecount, lines_before, lines_after
                                        )
                                        if ctx_before:
                                            sup_entry["context_before"] = ctx_before
                                        if ctx_after:
                                            sup_entry["context_after"] = ctx_after
                                    suppressed_json.append(sup_entry)
                                    state.suppressedFindingsCnt += 1
                                # Clear candidates so they don't appear in active findings
                                candidate_evidence = []

                    if not candidate_evidence:
                        continue

                    rel_path = futils.get_source_file_path(state.sourcedir, filepath)
                    seen_lines = set()
                    ctx_type = scan_cfg["context_type"]
                    lines_before = scan_cfg["context_lines_before"]
                    lines_after = scan_cfg["context_lines_after"]
                    do_aggregate = (scan_cfg["aggregate"] == "file")

                    # For aggregate:file, collect all passing evidence first, then emit one entry
                    file_evidence_items = []

                    for linecount, line, groups in candidate_evidence:
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

                        ev_item = {
                            "file": rel_path,
                            "line": linecount,
                            "code": short_line.strip(),
                        }

                        if ctx_type == "named_groups" and groups:
                            ev_item["groups"] = groups
                        elif ctx_type == "lines" and (lines_before > 0 or lines_after > 0):
                            ctx_before, ctx_after = _collect_context_lines(
                                file_lines, linecount, lines_before, lines_after
                            )
                            if ctx_before:
                                ev_item["context_before"] = ctx_before
                            if ctx_after:
                                ev_item["context_after"] = ctx_after
                        elif ctx_type == "backward" and scan_cfg["context_pattern"]:
                            try:
                                back_regex = re.compile(scan_cfg["context_pattern"])
                                depth = scan_cfg["context_depth"]
                                idx = linecount - 1
                                for i in range(idx - 1, max(-1, idx - depth - 1), -1):
                                    bm = back_regex.search(file_lines[i])
                                    if bm:
                                        groups_back = bm.groups()
                                        ev_item["context_label"] = groups_back[0] if groups_back else bm.group(0)
                                        break
                            except re.error:
                                pass

                        file_evidence_items.append(ev_item)

                    if not file_evidence_items:
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
                            "scan_config": scan_cfg,
                            "evidence": [],
                        })
                        _merge_logic_meta(findings_json[-1], active_logic_meta)
                        finding_index = len(findings_json) - 1

                    if do_aggregate:
                        # All matches in this file collapse into one aggregate evidence entry
                        agg_entry = {
                            "file": rel_path,
                            "aggregated": True,
                            "matches": [
                                {"line": ev["line"], "code": ev["code"], **
                                 ({"groups": ev["groups"]} if "groups" in ev else {})}
                                for ev in file_evidence_items
                            ],
                        }
                        if f_scanout:
                            for ev in file_evidence_items:
                                f_scanout.write(f"\n\t -> Source File: {rel_path}\n\t\t [{ev['line']}] {ev['code']}")
                        findings_json[finding_index]["evidence"].append(agg_entry)
                    else:
                        for ev_item in file_evidence_items:
                            if f_scanout:
                                f_scanout.write(
                                    f"\n\t -> Source File: {rel_path}\n"
                                    f"\t\t [{ev_item['line']}] {ev_item['code']}"
                                )
                            findings_json[finding_index]["evidence"].append(ev_item)
                    _merge_logic_meta(findings_json[finding_index], active_logic_meta)

                    score = _compute_source_confidence_score(
                        findings_json[finding_index].get("evidence", []),
                        has_regex=bool(pattern_text),
                        has_rdl=bool(rdl_ref),
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

    if suppressed_json_path and suppressed_json:
        try:
            sup_path = Path(suppressed_json_path)
            sup_path.parent.mkdir(parents=True, exist_ok=True)
            sup_path.write_text(json.dumps(suppressed_json, indent=2), encoding="utf-8")
        except OSError as exc:
            logger.error("Failed to write suppressed findings JSON %s: %s", suppressed_json_path, exc)

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

        pattern_name = (r.findtext("name") or "").strip()
        pattern_text = (r.findtext("regex") or "").strip()
        rdl_ref = (r.findtext("rdl_ref") or "").strip()
        exclude_text = (r.findtext("exclude") or "").strip()
        rule_meta = _file_path_rule_meta(r)
        logic_file_path = _resolve_logic_file(rule_path, rdl_ref) if rdl_ref else None
        rdl_logic_text = ""
        if logic_file_path and logic_file_path.exists():
            try:
                rdl_logic_text = rdl_engine.load_rdl(logic_file_path)
            except OSError as exc:
                logger.error("Failed to read file path RDL file %s for rule %s: %s", logic_file_path, pattern_name, exc)
                rdl_logic_text = ""

        pattern = None
        if pattern_text:
            try:
                pattern = re.compile(pattern_text, re.IGNORECASE)
            except re.error as exc:
                logger.error("Invalid file path regex in rule %s (%s): %s", pattern_name, rule_path, exc)
                unmatched_rules.append(pattern_name)
                continue

        exclude = None
        if exclude_text:
            try:
                exclude = re.compile(exclude_text, re.IGNORECASE)
            except re.error as exc:
                logger.error("Invalid file path exclude regex in rule %s (%s): %s", pattern_name, rule_path, exc)
                exclude = None

        for file_index, eachfilepath in enumerate(f_targetfilepaths, start=1):  # Read each line (file path) in the file
            filepath = eachfilepath.rstrip()    # strip out '\r' or '\n' from the file paths
            filepath = futils.get_source_file_path(state.sourcedir, filepath)
            match_path = filepath
            if state.sourcedir:
                try:
                    match_path = Path(filepath).resolve().relative_to(Path(state.sourcedir).resolve()).as_posix()
                except Exception:
                    match_path = str(filepath).replace("\\", "/")
            rule_match_text = "/" + str(match_path).lstrip("/")
            if exclude and exclude.search(filepath):
                unmatched_rules.append(pattern_name)
                continue

            matched = False
            active_logic_meta = {}
            if rdl_logic_text:
                rdl_result = rdl_engine.evaluate_rdl_with_reason(
                    rdl_logic_text,
                    file_text=rule_match_text,
                    file_path=rule_match_text,
                    project_root=state.sourcedir,
                )
                matched = bool(rdl_result.get("passes"))
                active_logic_meta = _build_logic_meta(
                    "rdl",
                    rdl_ref,
                    logic_result=rdl_result,
                )
            elif pattern is not None:
                matched = bool(pattern.search(rule_match_text))

            if matched:   # If there is a match
                if pFlag == False:
                    rule_no += 1
                    state.rulesPathsMatchCnt += 1
                    matched_rules.append(pattern_name)  # Add matched patterns to the list
                    if f_scanout:
                        f_scanout.write(f"{rule_no}. Rule Title: {r.find('name').text}\n")
                        f_scanout.write(("\tFile Path: " + match_path) + "\n")
                    print("     [-] File Path Rule:" + pattern_name)

                    findings_json.append({
                        "rule_title": pattern_name,
                        "filepath": [match_path],
                        "confidence_score": _compute_paths_confidence_score(1),
                        "confidence_level": _confidence_level(_compute_paths_confidence_score(1)),
                        **rule_meta,
                    })
                    _merge_logic_meta(findings_json[-1], active_logic_meta)

                    sys.stdout.write("\033[F") #back to previous line
                    sys.stdout.write("\033[K") #clear line to prevent overlap of texts
                    
                    pFlag = True
                else: 
                    if f_scanout:
                        f_scanout.write(("\tFile Path: " + match_path) + "\n")
                    findings_json[-1]["filepath"].append(match_path)
                    _merge_logic_meta(findings_json[-1], active_logic_meta)
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
