# Standard libraries
from pathlib import Path
from typing import List
import re

import state.runtime_state as state
from core.analysis.javascript.analyzer import analyze_js_flows
from core.analysis.mobile.common import annotate_flows, collect_files, first_match_line, flow, line_text, output_dir
from core.analysis.report import write_reports


HTTP_RE = re.compile(r"http://", re.IGNORECASE)
TLS_BYPASS_RE = re.compile(r"\b(?:allowInvalidCertificates|InsecureSkipVerify|trustAll)\b", re.IGNORECASE)
WEBVIEW_RE = re.compile(r"<WebView\b|webView\.src\s*=|evaluateJavaScript\s*\(|\bjavaScriptEnabled\b", re.IGNORECASE)
# No trailing \b on startsWith(...https?:// - see maui.py's WEBVIEW_GUARD_RE fix for why.
WEBVIEW_GUARD_RE = re.compile(r"\b(?:allowlist|whitelist|onShouldOverrideUrlLoading|event\.url)\b|\bstartsWith\s*\(\s*[\"']https?://", re.IGNORECASE)


def _semantic_flows(source_root: Path) -> List[dict]:
    flows: List[dict] = []
    files = collect_files(source_root, ("*.js", "*.ts", "*.xml", "*.html"))
    for file_path in files:
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        tls_line = first_match_line(lines, TLS_BYPASS_RE)
        if tls_line:
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="network_client",
                    sink="nativescript certificate validation bypass",
                    description="NativeScript networking code appears to bypass TLS certificate validation.",
                    explanation="Trust-all or invalid-certificate flags disable normal TLS trust checks and enable MITM attacks.",
                    path=[
                        {"file": None, "line": tls_line, "role": "source", "code": "[nativescript network] TLS peer reaches custom trust handling.", "source_symbol": "server_certificate", "variables": ["server_certificate"]},
                        {"file": None, "line": tls_line, "role": "sink", "code": line_text(lines, tls_line, "allowInvalidCertificates")},
                    ],
                    methods=["HTTPS"],
                    uris=["https://<HOST>"],
                    params=["certificate_validation"],
                    attack_label="Certificate Validation Bypass",
                    attack_reason="The networking client accepts invalid certificates.",
                )
            )

        webview_line = first_match_line(lines, WEBVIEW_RE)
        if webview_line and not first_match_line(lines, WEBVIEW_GUARD_RE, webview_line, min(len(lines), webview_line + 25)):
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="WebView",
                    sink="nativescript webview trust boundary exposure",
                    description="NativeScript WebView content is loaded or scripted without visible source validation.",
                    explanation="Dynamic WebView sources and script execution should be restricted to trusted origins to avoid injection or phishing flows.",
                    path=[
                        {"file": None, "line": webview_line, "role": "source", "code": "[nativescript webview] Web content enters the embedded browser context.", "source_symbol": "web_content", "variables": ["web_content"]},
                        {"file": None, "line": webview_line, "role": "sink", "code": line_text(lines, webview_line, "WebView")},
                    ],
                    confidence="medium",
                    methods=["WEBVIEW"],
                    uris=["https://attacker.example"],
                    params=["src", "script"],
                    attack_label="WebView JavaScript Exposure",
                    attack_reason="The WebView path lacks a visible allowlist or navigation guard.",
                )
            )

        http_line = first_match_line(lines, HTTP_RE)
        if http_line:
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="network_request",
                    sink="nativescript insecure http endpoint",
                    description="NativeScript code references a cleartext HTTP endpoint.",
                    explanation="Requests to `http://` endpoints are vulnerable to interception and tampering on mobile networks.",
                    path=[
                        {"file": None, "line": http_line, "role": "source", "code": "[nativescript config] Endpoint declared in app code.", "source_symbol": "endpoint", "variables": ["endpoint"]},
                        {"file": None, "line": http_line, "role": "sink", "code": line_text(lines, http_line, "http://")},
                    ],
                    confidence="medium",
                    methods=["HTTP"],
                    uris=["http://<HOST>"],
                    params=["endpoint"],
                    attack_label="Insecure Transport",
                    attack_reason="The app references a cleartext endpoint.",
                )
            )
    return flows


def analyze_nativescript_flows(source_root: Path, progress_callback=None):
    flows = annotate_flows(analyze_js_flows(source_root, progress_callback=progress_callback), platform="nativescript", variant="javascript")
    flows.extend(annotate_flows(_semantic_flows(source_root), platform="nativescript", variant="semantic"))
    return flows


def run(source_root: Path, progress_callback=None):
    flows = analyze_nativescript_flows(source_root, progress_callback=progress_callback)
    out_dir = output_dir(state.reports_dirpath, "nativescript")
    return write_reports(flows, out_dir, title="NativeScript Dataflow Analysis", platform="nativescript")
