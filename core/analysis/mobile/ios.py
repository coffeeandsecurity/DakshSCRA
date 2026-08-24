# Standard libraries
from pathlib import Path
from typing import Any, Dict, List
import re
import xml.etree.ElementTree as ET

import state.runtime_state as state
from core.analysis.mobile.common import annotate_flows, first_match_line, flow, line_text, output_dir
from core.analysis.report import write_reports


PLIST_BOOL_KEYS = {"true", "false"}
SWIFT_HANDLER_RE = re.compile(
    r"\b(?:application\s*\([^)]*open\s+url|scene\s*\([^)]*openURLContexts|onOpenURL\s*\(|continue\s+userActivity)",
    re.IGNORECASE,
)
INPUT_PATTERNS = [
    ("custom url", re.compile(r"\burl\b|\burlContexts\b|\bopenURLContexts\b", re.IGNORECASE)),
    ("universal link", re.compile(r"\buserActivity\.webpageURL\b|\bNSUserActivityTypeBrowsingWeb\b", re.IGNORECASE)),
]
GUARD_PATTERNS = [
    re.compile(r"\b(?:scheme|host)\s*==\s*[\"']", re.IGNORECASE),
    re.compile(r"\bhasPrefix\s*\(\s*[\"']https?://", re.IGNORECASE),
    re.compile(r"\b(?:allowedSchemes|allowedHosts|allowlist|whitelist)\b", re.IGNORECASE),
    re.compile(r"\bcanOpenURL\s*\(", re.IGNORECASE),
    re.compile(r"\b(?:isAuthenticated|requireAuth|session|tokenValidator)\b", re.IGNORECASE),
]
EVAL_JS_RE = re.compile(r"\.evaluateJavaScript\s*\(", re.IGNORECASE)
OPEN_URL_RE = re.compile(r"\bUIApplication\.(?:shared|sharedApplication\(\))\.(?:open|openURL)\s*\(", re.IGNORECASE)
CERT_BYPASS_RE = re.compile(
    r"(?:didReceive\s+challenge|completionHandler\s*\(\s*\.useCredential|NSURLSessionAuthChallengeDisposition\.useCredential|URLCredential\s*\(\s*trust\s*:)",
    re.IGNORECASE,
)


def _guard_present(lines: List[str], start: int, end: int) -> bool:
    upper = end or len(lines)
    for idx in range(max(1, start), upper + 1):
        if any(pattern.search(lines[idx - 1]) for pattern in GUARD_PATTERNS):
            return True
    return False


def _plist_value(node: ET.Element) -> Any:
    tag = str(node.tag or "").split("}")[-1]
    if tag == "dict":
        result: Dict[str, Any] = {}
        children = list(node)
        idx = 0
        while idx < len(children):
            key_node = children[idx]
            if str(key_node.tag).split("}")[-1] != "key" or key_node.text is None:
                idx += 1
                continue
            key = str(key_node.text).strip()
            value_node = children[idx + 1] if idx + 1 < len(children) else None
            result[key] = _plist_value(value_node) if value_node is not None else None
            idx += 2
        return result
    if tag == "array":
        return [_plist_value(child) for child in list(node)]
    if tag in PLIST_BOOL_KEYS:
        return tag == "true"
    return str(node.text or "").strip()


def _load_plist(plist_path: Path) -> Dict[str, Any]:
    try:
        root = ET.parse(plist_path).getroot()
    except ET.ParseError:
        return {}
    dict_node = root.find("dict")
    if dict_node is None:
        return {}
    value = _plist_value(dict_node)
    return value if isinstance(value, dict) else {}


def _plist_files(source_root: Path) -> List[Path]:
    matches = sorted({*source_root.rglob("Info.plist"), *source_root.rglob("*.entitlements")})
    return [path for path in matches if path.is_file()]


def _swift_files(source_root: Path) -> List[Path]:
    files: List[Path] = []
    for glob in ("*.swift", "*.m", "*.mm"):
        files.extend(list(source_root.rglob(glob)))
    return sorted({path for path in files if path.is_file()})


def _ats_flows(source_root: Path, plist_files: List[Path]) -> List[Dict]:
    flows: List[Dict] = []
    for plist_path in plist_files:
        data = _load_plist(plist_path)
        ats = data.get("NSAppTransportSecurity")
        if not isinstance(ats, dict) or not ats.get("NSAllowsArbitraryLoads"):
            continue
        try:
            lines = plist_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        line_no = first_match_line(lines, re.compile(r"NSAllowsArbitraryLoads"), 1) or 1
        flows.append(
            flow(
                source_root=source_root,
                file_path=plist_path,
                function="Info.plist",
                sink="ats arbitrary loads",
                description="The iOS app disables ATS by allowing arbitrary network loads.",
                explanation="ATS relaxation permits cleartext or weakly protected network traffic, increasing MITM exposure.",
                path=[
                    {
                        "file": None,
                        "line": line_no,
                        "role": "source",
                        "code": "[ios config] NSAppTransportSecurity is configured in Info.plist.",
                        "source_symbol": "ios_config",
                        "variables": ["ios_config"],
                    },
                    {
                        "file": None,
                        "line": line_no,
                        "role": "sink",
                        "code": line_text(lines, line_no, "NSAllowsArbitraryLoads"),
                    },
                ],
                methods=["NETWORK"],
                uris=["https://developer.apple.com/documentation/bundleresources/information_property_list/nsapptransportsecurity"],
                params=["NSAllowsArbitraryLoads"],
                attack_label="Insecure Transport",
                attack_reason="The app explicitly allows arbitrary network loads through ATS configuration.",
            )
        )
    return flows


def _scheme_candidates(plist_data: Dict[str, Any]) -> List[str]:
    schemes: List[str] = []
    for item in plist_data.get("CFBundleURLTypes", []) or []:
        if not isinstance(item, dict):
            continue
        for scheme in item.get("CFBundleURLSchemes", []) or []:
            token = str(scheme or "").strip()
            if token:
                schemes.append(token)
    return schemes


def _handler_flows(source_root: Path, source_files: List[Path], plist_files: List[Path], progress_callback=None, total_items=0) -> List[Dict]:
    flows: List[Dict] = []
    schemes: List[str] = []
    for plist_path in plist_files:
        schemes.extend(_scheme_candidates(_load_plist(plist_path)))
    attack_uri = f"{schemes[0]}://action?payload=<PAYLOAD>" if schemes else "app://action?payload=<PAYLOAD>"

    for index, file_path in enumerate(source_files, start=1):
        if callable(progress_callback):
            progress_callback({
                "platform": "ios", "phase": "parsing_files", "status": "running",
                "current_index": index, "total_items": total_items,
                "current_file": str(file_path),
            })
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        handler_line = first_match_line(lines, SWIFT_HANDLER_RE, 1)
        if not handler_line:
            continue
        input_hit = {}
        for label, pattern in INPUT_PATTERNS:
            line_no = first_match_line(lines, pattern, handler_line, min(len(lines), handler_line + 40))
            if line_no:
                input_hit = {"label": label, "line": line_no, "code": line_text(lines, line_no, label)}
                break
        if not input_hit:
            input_hit = {
                "label": "deep link input",
                "line": handler_line,
                "code": line_text(lines, handler_line, "open url handler"),
            }
        guard_present = _guard_present(lines, handler_line, min(len(lines), handler_line + 60))

        if not guard_present:
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="deep_link_handler",
                    sink="ios deep link exposure",
                    description="The iOS deep-link handler accepts external URL input without visible scheme/host or auth validation.",
                    explanation="Custom scheme or universal-link handlers should validate the incoming destination and enforce authz before performing sensitive actions.",
                    path=[
                        {
                            "file": None,
                            "line": handler_line,
                            "role": "source",
                            "code": "[ios entrypoint] External URL or universal link reaches the application handler.",
                            "source_symbol": "external_url",
                            "variables": ["external_url"],
                        },
                        {
                            "file": None,
                            "line": input_hit["line"],
                            "role": "param",
                            "code": input_hit["code"],
                            "source_symbol": "url",
                            "variables": ["url"],
                        },
                        {
                            "file": None,
                            "line": input_hit["line"],
                            "role": "sink",
                            "code": "No scheme/host or auth guard detected in handler window.",
                        },
                    ],
                    confidence="medium",
                    methods=["URL"],
                    uris=[attack_uri],
                    params=[input_hit["label"]],
                    attack_label="Deep Link Exposure",
                    attack_reason="An attacker-controlled URL can reach a handler with no obvious validation gate.",
                    attack_example=attack_uri,
                )
            )

        eval_line = first_match_line(lines, EVAL_JS_RE, handler_line, min(len(lines), handler_line + 80))
        if eval_line and not guard_present:
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="deep_link_handler",
                    sink="ios evaluatejavascript sink",
                    description="External URL input reaches `evaluateJavaScript` in an iOS deep-link handler.",
                    explanation="User-controlled URL data reaching JavaScript execution in `WKWebView` can lead to script injection or bridge abuse.",
                    path=[
                        {
                            "file": None,
                            "line": handler_line,
                            "role": "source",
                            "code": "[ios entrypoint] Deep link or universal link invoked by another app or Safari.",
                            "source_symbol": "external_url",
                            "variables": ["external_url"],
                        },
                        {
                            "file": None,
                            "line": input_hit["line"],
                            "role": "param",
                            "code": input_hit["code"],
                            "source_symbol": "url",
                            "variables": ["url"],
                        },
                        {
                            "file": None,
                            "line": eval_line,
                            "role": "sink",
                            "code": line_text(lines, eval_line, ".evaluateJavaScript("),
                        },
                    ],
                    methods=["URL"],
                    uris=[attack_uri],
                    params=[input_hit["label"]],
                    attack_label="WebView JavaScript Injection",
                    attack_reason="A deep link reaches WebView script execution without a visible validation barrier.",
                    attack_example=attack_uri,
                )
            )

        open_line = first_match_line(lines, OPEN_URL_RE, handler_line, min(len(lines), handler_line + 80))
        if open_line and not guard_present:
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="deep_link_handler",
                    sink="ios openurl sink",
                    description="External URL input reaches `UIApplication.open` without visible destination validation.",
                    explanation="Opening attacker-influenced URLs can cause open-redirect style abuse or hand off privileged custom schemes to other apps.",
                    path=[
                        {
                            "file": None,
                            "line": handler_line,
                            "role": "source",
                            "code": "[ios entrypoint] Deep link or universal link invoked by external input.",
                            "source_symbol": "external_url",
                            "variables": ["external_url"],
                        },
                        {
                            "file": None,
                            "line": input_hit["line"],
                            "role": "param",
                            "code": input_hit["code"],
                            "source_symbol": "url",
                            "variables": ["url"],
                        },
                        {
                            "file": None,
                            "line": open_line,
                            "role": "sink",
                            "code": line_text(lines, open_line, "UIApplication.shared.open"),
                        },
                    ],
                    confidence="medium",
                    methods=["URL"],
                    uris=[attack_uri],
                    params=[input_hit["label"]],
                    attack_label="Unvalidated URL Opening",
                    attack_reason="An attacker-controlled URL reaches `UIApplication.open` without visible scheme or host checks.",
                    attack_example=attack_uri,
                )
            )
    return flows


def _cert_flows(source_root: Path, source_files: List[Path]) -> List[Dict]:
    flows: List[Dict] = []
    for file_path in source_files:
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        line_no = first_match_line(lines, CERT_BYPASS_RE, 1)
        if not line_no:
            continue
        flows.append(
            flow(
                source_root=source_root,
                file_path=file_path,
                function="urlsession_delegate",
                sink="ios certificate validation bypass",
                description="Custom iOS TLS challenge handling appears to trust server certificates without strict validation.",
                explanation="Returning `.useCredential` with server trust can disable normal certificate verification and expose the app to MITM attacks.",
                path=[
                    {
                        "file": None,
                        "line": line_no,
                        "role": "source",
                        "code": "[ios network] TLS server trust challenge reached custom validation code.",
                        "source_symbol": "network_peer",
                        "variables": ["network_peer"],
                    },
                    {
                        "file": None,
                        "line": line_no,
                        "role": "sink",
                        "code": line_text(lines, line_no, "didReceive challenge"),
                    },
                ],
                methods=["HTTPS"],
                uris=["https://<HOST>"],
                params=["serverTrust"],
                attack_label="Certificate Validation Bypass",
                attack_reason="The TLS challenge handler appears to accept untrusted certificates.",
                attack_example="https://<HOST>",
            )
        )
    return flows


def analyze_ios_flows(source_root: Path, progress_callback=None) -> List[Dict]:
    plist_files = _plist_files(source_root)
    source_files = _swift_files(source_root)
    total = len(plist_files) + len(source_files)
    if callable(progress_callback):
        progress_callback({
            "platform": "ios", "phase": "queueing", "status": "running",
            "current_index": 0, "total_items": total, "current_file": "",
        })
    flows = []
    flows.extend(_ats_flows(source_root, plist_files))
    flows.extend(_handler_flows(source_root, source_files, plist_files, progress_callback=progress_callback, total_items=total))
    flows.extend(_cert_flows(source_root, source_files))
    if callable(progress_callback):
        progress_callback({
            "platform": "ios", "phase": "completed", "status": "completed",
            "current_index": total, "total_items": total, "current_file": "",
            "flow_count": len(flows),
        })
    return annotate_flows(flows, platform="ios", variant="semantic")


def run(source_root: Path, progress_callback=None):
    flows = analyze_ios_flows(source_root, progress_callback=progress_callback)
    out_dir = output_dir(state.reports_dirpath, "ios")
    return write_reports(flows, out_dir, title="iOS Dataflow Analysis", platform="ios")
