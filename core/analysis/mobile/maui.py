# Standard libraries
from pathlib import Path
from typing import List
import re

import state.runtime_state as state
from core.analysis.dotnet.analyzer import analyze_dotnet_flows
from core.analysis.mobile.common import annotate_flows, collect_files, first_match_line, flow, line_text, output_dir
from core.analysis.report import write_reports


MAUI_MARKER_RE = re.compile(r"\b(?:UseMaui|MauiProgram|Microsoft\.Maui|BlazorWebView|HybridWebView)\b", re.IGNORECASE)
TLS_BYPASS_RE = re.compile(r"\b(?:ServerCertificateCustomValidationCallback|ServicePointManager\.ServerCertificateValidationCallback)\b", re.IGNORECASE)
RETURN_TRUE_RE = re.compile(r"=>\s*true\b|return\s+true\b", re.IGNORECASE)
WEBVIEW_RE = re.compile(r"\b(?:BlazorWebView|WebView|HybridWebView|EvaluateJavaScriptAsync)\b", re.IGNORECASE)
# No trailing \b on the StartsWith("https://ALTERNATIVE: it ends in "/",
# a non-word char, and the very next char in real code (a closing quote)
# is non-word too - \b requires one side of the boundary to be a word
# character, so a trailing \b here silently never matches "https://".
WEBVIEW_GUARD_RE = re.compile(r"\b(?:Uri\.TryCreate|Navigating|allowlist|whitelist)\b|\bStartsWith\s*\(\s*\"https://", re.IGNORECASE)
OPEN_URL_RE = re.compile(r"\b(?:Launcher\.Default\.OpenAsync|Browser\.Default\.OpenAsync)\s*\(", re.IGNORECASE)
OPEN_URL_GUARD_RE = re.compile(r"\b(?:Uri\.TryCreate|allowlist|whitelist)\b|\bStartsWith\s*\(\s*\"https://", re.IGNORECASE)
HTTP_RE = re.compile(r"http://", re.IGNORECASE)


def _project_uses_maui(files: List[Path]) -> bool:
    """Project-level gate: only a project that actually references MAUI
    anywhere (MauiProgram.cs, UseMaui(), etc.) should get MAUI-specific
    semantic-flow analysis. Previously this check only applied to .csproj
    files - a .cs/.xaml file with no marker in it still got fully
    analyzed even in a plain ASP.NET or Xamarin project with no MAUI
    marker anywhere, because the "not .csproj" case fell through with no
    gate at all."""
    for file_path in files:
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if MAUI_MARKER_RE.search(text):
            return True
    return False


def _semantic_flows(source_root: Path) -> List[dict]:
    flows: List[dict] = []
    files = collect_files(source_root, ("*.cs", "*.csproj", "*.xaml"))
    if not _project_uses_maui(files):
        return flows

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
                    sink="maui certificate validation bypass",
                    description=".NET MAUI networking code bypasses TLS certificate validation.",
                    explanation="Callbacks that accept invalid certificates disable normal trust checks and expose the mobile app to MITM attacks.",
                    path=[
                        {"file": None, "line": tls_line, "role": "source", "code": "[maui network] TLS peer certificate reaches custom validation code.", "source_symbol": "server_certificate", "variables": ["server_certificate"]},
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
                    sink="maui webview trust boundary exposure",
                    description=".NET MAUI embedded web view usage lacks visible destination or script restrictions.",
                    explanation="BlazorWebView, HybridWebView, and other embedded browser paths should restrict content origins and script/native bridging.",
                    path=[
                        {"file": None, "line": webview_line, "role": "source", "code": "[maui webview] Web content enters the embedded browser context.", "source_symbol": "web_content", "variables": ["web_content"]},
                        {"file": None, "line": webview_line, "role": "sink", "code": line_text(lines, webview_line, "WebView")},
                    ],
                    confidence="medium",
                    methods=["WEBVIEW"],
                    uris=["https://attacker.example"],
                    params=["url", "script"],
                    attack_label="WebView JavaScript Exposure",
                    attack_reason="The WebView path lacks a visible allowlist or navigation guard.",
                )
            )

        open_line = first_match_line(lines, OPEN_URL_RE)
        if open_line and not first_match_line(lines, OPEN_URL_GUARD_RE, open_line, min(len(lines), open_line + 20)):
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="Launcher.OpenAsync",
                    sink="maui openurl sink",
                    description=".NET MAUI opens dynamic URLs without visible validation.",
                    explanation="Opening attacker-controlled URLs can trigger phishing flows or hand off to unsafe custom-scheme handlers.",
                    path=[
                        {"file": None, "line": open_line, "role": "source", "code": "[maui input] A dynamic URL reaches app or browser launch code.", "source_symbol": "external_url", "variables": ["external_url"]},
                        {"file": None, "line": open_line, "role": "sink", "code": line_text(lines, open_line, "Launcher.Default.OpenAsync(")},
                    ],
                    confidence="medium",
                    methods=["URL"],
                    uris=["https://attacker.example"],
                    params=["url"],
                    attack_label="Unvalidated URL Opening",
                    attack_reason="A dynamic URL is opened without a visible allowlist gate.",
                )
            )

        http_line = first_match_line(lines, HTTP_RE)
        if http_line:
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="network_request",
                    sink="maui insecure http endpoint",
                    description=".NET MAUI code references a cleartext HTTP endpoint.",
                    explanation="Requests to `http://` endpoints are vulnerable to interception and tampering on mobile networks.",
                    path=[
                        {"file": None, "line": http_line, "role": "source", "code": "[maui config] Endpoint declared in app code or config.", "source_symbol": "endpoint", "variables": ["endpoint"]},
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


def analyze_maui_flows(source_root: Path, progress_callback=None):
    flows = annotate_flows(analyze_dotnet_flows(source_root, progress_callback=progress_callback), platform="maui", variant="dotnet")
    flows.extend(annotate_flows(_semantic_flows(source_root), platform="maui", variant="semantic"))
    return flows


def run(source_root: Path, progress_callback=None):
    flows = analyze_maui_flows(source_root, progress_callback=progress_callback)
    out_dir = output_dir(state.reports_dirpath, "maui")
    return write_reports(flows, out_dir, title=".NET MAUI Dataflow Analysis", platform="maui")
