# Standard libraries
from pathlib import Path
from typing import Dict, List
import re

import state.runtime_state as state
from core.analysis.mobile.common import annotate_flows, first_match_line, flow, line_text, output_dir
from core.analysis.report import write_reports


METHOD_CHANNEL_RE = re.compile(r"\bsetMethodCallHandler\s*\(")
CALL_METHOD_GUARD_RE = re.compile(r"\b(?:call\.method\s*==|switch\s*\(\s*call\.method|case\s+[\"'])", re.IGNORECASE)
CALL_ARGS_GUARD_RE = re.compile(r"\b(?:call\.arguments\s+is|call\.arguments\s+as|containsKey\s*\(|\bis\s+Map\b|\bis\s+String\b)", re.IGNORECASE)
WEBVIEW_LOAD_RE = re.compile(r"\b(?:loadRequest|loadHtmlString|loadFlutterAsset)\s*\(")
WEBVIEW_JS_RE = re.compile(r"\bJavaScriptMode\.unrestricted\b")
WEBVIEW_GUARD_RE = re.compile(r"\b(?:NavigationDelegate|onNavigationRequest|uri\.scheme\s*==|startsWith\s*\(\s*[\"']https://|allowlist|whitelist)\b", re.IGNORECASE)
CERT_BYPASS_RE = re.compile(r"\bbadCertificateCallback\b", re.IGNORECASE)
CERT_TRUE_RE = re.compile(r"(?:=>\s*true\b|return\s+true\b)")
HTTP_LITERAL_RE = re.compile(r"[\"']http://[^\"']+[\"']")
REMOTE_URI_LITERAL_RE = re.compile(r"[\"']https?://[^\"']+[\"']")
SPAWN_URI_RE = re.compile(r"\bIsolate\.spawnUri\s*\(")


def _dart_files(source_root: Path) -> List[Path]:
    return sorted({path for path in source_root.rglob("*.dart") if path.is_file()})


def _method_channel_flows(source_root: Path, dart_files: List[Path], progress_callback=None, total_items=0) -> List[Dict]:
    flows: List[Dict] = []
    for index, file_path in enumerate(dart_files, start=1):
        if callable(progress_callback):
            progress_callback({
                "platform": "flutter", "phase": "parsing_files", "status": "running",
                "current_index": index, "total_items": total_items,
                "current_file": str(file_path),
            })
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        handler_line = first_match_line(lines, METHOD_CHANNEL_RE, 1)
        if not handler_line:
            continue
        end_line = min(len(lines), handler_line + 40)
        method_guard = first_match_line(lines, CALL_METHOD_GUARD_RE, handler_line, end_line)
        args_guard = first_match_line(lines, CALL_ARGS_GUARD_RE, handler_line, end_line)
        if method_guard and args_guard:
            continue
        flows.append(
            flow(
                source_root=source_root,
                file_path=file_path,
                function="MethodChannel",
                sink="flutter methodchannel unvalidated handler",
                description="A Flutter MethodChannel handler processes calls without visible method-name and argument validation.",
                explanation="Bridge handlers should gate `call.method` and validate `call.arguments` before reaching native or privileged actions.",
                path=[
                    {
                        "file": None,
                        "line": handler_line,
                        "role": "source",
                        "code": "[flutter bridge] External channel invocation reaches setMethodCallHandler.",
                        "source_symbol": "method_channel",
                        "variables": ["method_channel"],
                    },
                    {
                        "file": None,
                        "line": handler_line,
                        "role": "param",
                        "code": line_text(lines, handler_line, "setMethodCallHandler("),
                        "source_symbol": "call.arguments",
                        "variables": ["call.method", "call.arguments"],
                    },
                    {
                        "file": None,
                        "line": end_line,
                        "role": "sink",
                        "code": "No method/argument validation detected in handler window.",
                    },
                ],
                confidence="medium",
                methods=["CHANNEL"],
                uris=["flutter://method-channel"],
                params=["call.method", "call.arguments"],
                attack_label="Bridge Exposure",
                attack_reason="An attacker-controlled bridge invocation can reach a handler with weak validation.",
                attack_example="channel.invokeMethod('<METHOD>', {'arg':'<PAYLOAD>'})",
            )
        )
    return flows


def _webview_flows(source_root: Path, dart_files: List[Path]) -> List[Dict]:
    flows: List[Dict] = []
    for file_path in dart_files:
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        js_line = first_match_line(lines, WEBVIEW_JS_RE, 1)
        load_line = first_match_line(lines, WEBVIEW_LOAD_RE, 1)
        guard_line = first_match_line(lines, WEBVIEW_GUARD_RE, 1)

        if js_line and not guard_line:
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="WebViewController",
                    sink="flutter webview unrestricted javascript",
                    description="A Flutter WebView enables unrestricted JavaScript without visible navigation or scheme restrictions.",
                    explanation="Unrestricted JavaScript combined with weak navigation controls increases WebView script-injection and bridge-abuse risk.",
                    path=[
                        {
                            "file": None,
                            "line": js_line,
                            "role": "source",
                            "code": "[flutter config] WebView JavaScript mode configured for content loading.",
                            "source_symbol": "webview_config",
                            "variables": ["webview_config"],
                        },
                        {
                            "file": None,
                            "line": js_line,
                            "role": "sink",
                            "code": line_text(lines, js_line, "JavaScriptMode.unrestricted"),
                        },
                    ],
                    confidence="medium",
                    methods=["WEBVIEW"],
                    uris=["https://<WEBVIEW-URL>"],
                    params=["javascriptMode"],
                    attack_label="WebView JavaScript Exposure",
                    attack_reason="The WebView permits unrestricted script execution with no visible navigation guard.",
                )
            )

        if load_line and not guard_line:
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="WebViewController",
                    sink="flutter webview user controlled url",
                    description="A Flutter WebView loads a URL without visible scheme or origin validation.",
                    explanation="Unvalidated WebView navigation can allow phishing content, `javascript:` URLs, or unsafe local/resource access.",
                    path=[
                        {
                            "file": None,
                            "line": load_line,
                            "role": "source",
                            "code": "[flutter input] Application-controlled or external URL reaches WebView navigation.",
                            "source_symbol": "web_url",
                            "variables": ["web_url"],
                        },
                        {
                            "file": None,
                            "line": load_line,
                            "role": "sink",
                            "code": line_text(lines, load_line, "loadRequest("),
                        },
                    ],
                    confidence="medium",
                    methods=["WEBVIEW"],
                    uris=["https://<WEBVIEW-URL>"],
                    params=["url"],
                    attack_label="WebView Navigation Exposure",
                    attack_reason="A user-controlled URL reaches WebView loading without a visible validation hook.",
                    attack_example="https://attacker.example/path?payload=<PAYLOAD>",
                )
            )
    return flows


def _cert_flows(source_root: Path, dart_files: List[Path]) -> List[Dict]:
    flows: List[Dict] = []
    for file_path in dart_files:
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        line_no = first_match_line(lines, CERT_BYPASS_RE, 1)
        if not line_no:
            continue
        end_line = min(len(lines), line_no + 12)
        true_line = first_match_line(lines, CERT_TRUE_RE, line_no, end_line)
        if not true_line:
            continue
        flows.append(
            flow(
                source_root=source_root,
                file_path=file_path,
                function="HttpClient",
                sink="flutter certificate validation bypass",
                description="A Flutter HTTP client accepts invalid certificates through `badCertificateCallback`.",
                explanation="Returning `true` from certificate callbacks disables normal TLS trust checks and enables MITM attacks.",
                path=[
                    {
                        "file": None,
                        "line": line_no,
                        "role": "source",
                        "code": "[flutter network] TLS peer certificate reaches custom callback.",
                        "source_symbol": "server_certificate",
                        "variables": ["server_certificate"],
                    },
                    {
                        "file": None,
                        "line": true_line,
                        "role": "sink",
                        "code": line_text(lines, true_line, "return true"),
                    },
                ],
                methods=["HTTPS"],
                uris=["https://<HOST>"],
                params=["badCertificateCallback"],
                attack_label="Certificate Validation Bypass",
                attack_reason="The TLS callback explicitly accepts invalid certificates.",
                attack_example="https://<HOST>",
            )
        )
    return flows


def _transport_and_spawn_flows(source_root: Path, dart_files: List[Path]) -> List[Dict]:
    flows: List[Dict] = []
    for file_path in dart_files:
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        http_line = first_match_line(lines, HTTP_LITERAL_RE, 1)
        if http_line:
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="network_request",
                    sink="flutter insecure http endpoint",
                    description="A Flutter code path uses a cleartext `http://` endpoint.",
                    explanation="Cleartext transport exposes mobile traffic to interception and tampering on hostile networks.",
                    path=[
                        {
                            "file": None,
                            "line": http_line,
                            "role": "source",
                            "code": "[flutter config] Network endpoint declared in application code.",
                            "source_symbol": "endpoint",
                            "variables": ["endpoint"],
                        },
                        {
                            "file": None,
                            "line": http_line,
                            "role": "sink",
                            "code": line_text(lines, http_line, "http://"),
                        },
                    ],
                    confidence="medium",
                    methods=["HTTP"],
                    uris=["http://<HOST>"],
                    params=["endpoint"],
                    attack_label="Insecure Transport",
                    attack_reason="The app builds requests to a cleartext endpoint.",
                    attack_example="http://<HOST>",
                )
            )

        spawn_line = first_match_line(lines, SPAWN_URI_RE, 1)
        if spawn_line:
            remote_line = first_match_line(lines, REMOTE_URI_LITERAL_RE, spawn_line, min(len(lines), spawn_line + 10))
            if remote_line:
                flows.append(
                    flow(
                        source_root=source_root,
                        file_path=file_path,
                        function="Isolate.spawnUri",
                        sink="flutter remote isolate uri",
                        description="`Isolate.spawnUri` is invoked with a remote HTTP(S) URI.",
                        explanation="Spawning an isolate from a remote URI can load and execute untrusted Dart code at runtime.",
                        path=[
                            {
                                "file": None,
                                "line": spawn_line,
                                "role": "source",
                                "code": "[flutter input] Remote URI selected for isolate loading.",
                                "source_symbol": "remote_uri",
                                "variables": ["remote_uri"],
                            },
                            {
                                "file": None,
                                "line": remote_line,
                                "role": "sink",
                                "code": line_text(lines, remote_line, "Isolate.spawnUri("),
                            },
                        ],
                        methods=["URI"],
                        uris=["https://attacker.example/app.dart"],
                        params=["uri"],
                        attack_label="Remote Dart Execution",
                        attack_reason="The app can load Dart code from a remote URI at runtime.",
                        attack_example="https://attacker.example/app.dart",
                    )
                )
    return flows


def analyze_flutter_flows(source_root: Path, progress_callback=None) -> List[Dict]:
    dart_files = _dart_files(source_root)
    total = len(dart_files)
    if callable(progress_callback):
        progress_callback({
            "platform": "flutter", "phase": "queueing", "status": "running",
            "current_index": 0, "total_items": total, "current_file": "",
        })
    flows = []
    flows.extend(_method_channel_flows(source_root, dart_files, progress_callback=progress_callback, total_items=total))
    flows.extend(_webview_flows(source_root, dart_files))
    flows.extend(_cert_flows(source_root, dart_files))
    flows.extend(_transport_and_spawn_flows(source_root, dart_files))
    if callable(progress_callback):
        progress_callback({
            "platform": "flutter", "phase": "completed", "status": "completed",
            "current_index": total, "total_items": total, "current_file": "",
            "flow_count": len(flows),
        })
    return annotate_flows(flows, platform="flutter", variant="semantic")


def run(source_root: Path, progress_callback=None):
    flows = analyze_flutter_flows(source_root, progress_callback=progress_callback)
    out_dir = output_dir(state.reports_dirpath, "flutter")
    return write_reports(flows, out_dir, title="Flutter Dataflow Analysis", platform="flutter")
