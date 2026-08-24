# Standard libraries
from pathlib import Path
from typing import List
import re

import state.runtime_state as state
from core.analysis.dotnet.analyzer import analyze_dotnet_flows
from core.analysis.mobile.common import annotate_flows, collect_files, first_match_line, flow, line_text, output_dir
from core.analysis.report import write_reports


TLS_BYPASS_RE = re.compile(r"\b(?:ServerCertificateCustomValidationCallback|ServicePointManager\.ServerCertificateValidationCallback)\b", re.IGNORECASE)
RETURN_TRUE_RE = re.compile(r"=>\s*true\b|return\s+true\b", re.IGNORECASE)
WEBVIEW_RE = re.compile(r"\b(?:WebView|HybridWebView|EvaluateJavaScriptAsync|JavaScriptEnabled\s*=\s*true|EnableJavascript\s*=\s*true)\b", re.IGNORECASE)
# No trailing \b on StartsWith("https:// - see maui.py's identical fix for why.
WEBVIEW_GUARD_RE = re.compile(r"\b(?:Uri\.TryCreate|CanOpenAsync|allowlist|whitelist|Navigating)\b|\bStartsWith\s*\(\s*\"https://", re.IGNORECASE)
HTTP_RE = re.compile(r"http://", re.IGNORECASE)


def _semantic_flows(source_root: Path) -> List[dict]:
    flows: List[dict] = []
    files = collect_files(source_root, ("*.cs", "*.xaml", "*.xml"))
    for file_path in files:
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        tls_line = first_match_line(lines, TLS_BYPASS_RE)
        if tls_line:
            true_line = first_match_line(lines, RETURN_TRUE_RE, tls_line, min(len(lines), tls_line + 12)) or tls_line
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="HttpClient",
                    sink="xamarin certificate validation bypass",
                    description="Xamarin/.NET mobile networking code bypasses TLS certificate validation.",
                    explanation="Callbacks that accept invalid certificates disable normal trust checks and expose the app to MITM attacks.",
                    path=[
                        {"file": None, "line": tls_line, "role": "source", "code": "[xamarin network] TLS peer certificate reaches custom validation code.", "source_symbol": "server_certificate", "variables": ["server_certificate"]},
                        {"file": None, "line": true_line, "role": "sink", "code": line_text(lines, true_line, "=> true")},
                    ],
                    methods=["HTTPS"],
                    uris=["https://<HOST>"],
                    params=["certificate_validation"],
                    attack_label="Certificate Validation Bypass",
                    attack_reason="The app appears to accept invalid certificates.",
                )
            )

        webview_line = first_match_line(lines, WEBVIEW_RE)
        if webview_line and not first_match_line(lines, WEBVIEW_GUARD_RE, webview_line, min(len(lines), webview_line + 25)):
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="WebView",
                    sink="xamarin webview trust boundary exposure",
                    description="Xamarin WebView scripting or content loading is enabled without visible destination validation.",
                    explanation="Embedded browser flows should restrict origins and script execution to trusted content paths.",
                    path=[
                        {"file": None, "line": webview_line, "role": "source", "code": "[xamarin webview] Web content enters the embedded browser context.", "source_symbol": "web_content", "variables": ["web_content"]},
                        {"file": None, "line": webview_line, "role": "sink", "code": line_text(lines, webview_line, "WebView")},
                    ],
                    confidence="medium",
                    methods=["WEBVIEW"],
                    uris=["https://attacker.example"],
                    params=["url", "javascript"],
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
                    sink="xamarin insecure http endpoint",
                    description="Xamarin code references a cleartext HTTP endpoint.",
                    explanation="Requests to `http://` endpoints are vulnerable to interception and tampering.",
                    path=[
                        {"file": None, "line": http_line, "role": "source", "code": "[xamarin config] Endpoint declared in app code or config.", "source_symbol": "endpoint", "variables": ["endpoint"]},
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


def analyze_xamarin_flows(source_root: Path, progress_callback=None):
    flows = annotate_flows(analyze_dotnet_flows(source_root, progress_callback=progress_callback), platform="xamarin", variant="dotnet")
    flows.extend(annotate_flows(_semantic_flows(source_root), platform="xamarin", variant="semantic"))
    return flows


def run(source_root: Path, progress_callback=None):
    flows = analyze_xamarin_flows(source_root, progress_callback=progress_callback)
    out_dir = output_dir(state.reports_dirpath, "xamarin")
    return write_reports(flows, out_dir, title="Xamarin Dataflow Analysis", platform="xamarin")
