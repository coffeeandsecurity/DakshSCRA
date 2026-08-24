# Standard libraries
from pathlib import Path
from typing import List
import re

import state.runtime_state as state
from core.analysis.javascript.analyzer import analyze_js_flows
from core.analysis.mobile.common import annotate_flows, collect_files, first_match_line, flow, line_text, output_dir
from core.analysis.report import write_reports


HTTP_RE = re.compile(r"http://", re.IGNORECASE)
OPEN_RE = re.compile(r"\b(?:InAppBrowser|cordova\.InAppBrowser|Browser\.open|window\.open)\s*\(", re.IGNORECASE)
OPEN_GUARD_RE = re.compile(r"\b(?:allowlist|whitelist|startsWith\s*\(\s*[\"']https?://|new URL\s*\()", re.IGNORECASE)
WILDCARD_RE = re.compile(r"<(?:allow-navigation|access)\b[^>]*(?:href|origin)=\"\*\"", re.IGNORECASE)
CSP_RE = re.compile(r"unsafe-inline|unsafe-eval", re.IGNORECASE)
CLEARTEXT_RE = re.compile(r"(?:cleartextTrafficPermitted\s*[:=]\s*true|NSAllowsArbitraryLoads)", re.IGNORECASE)


def _semantic_flows(source_root: Path) -> List[dict]:
    flows: List[dict] = []
    files = collect_files(source_root, ("*.js", "*.jsx", "*.ts", "*.tsx", "*.html", "*.xml", "*.json"))
    for file_path in files:
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        wildcard_line = first_match_line(lines, WILDCARD_RE)
        if wildcard_line:
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="hybrid_config",
                    sink="ionic wildcard navigation policy",
                    description="Ionic/Capacitor configuration permits wildcard navigation or origin access.",
                    explanation="Wildcard allowlists expand the hybrid WebView trust boundary to untrusted content.",
                    path=[
                        {"file": None, "line": wildcard_line, "role": "source", "code": "[ionic config] Hybrid navigation policy declared in app config.", "source_symbol": "hybrid_config", "variables": ["hybrid_config"]},
                        {"file": None, "line": wildcard_line, "role": "sink", "code": line_text(lines, wildcard_line, "<allow-navigation href=\"*\"")},
                    ],
                    confidence="high",
                    methods=["WEBVIEW"],
                    uris=["https://attacker.example"],
                    params=["allow-navigation", "access origin"],
                    attack_label="WebView Trust Boundary Exposure",
                    attack_reason="Wildcard policies permit untrusted web content into the app shell.",
                )
            )

        csp_line = first_match_line(lines, CSP_RE)
        if csp_line:
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="CSP",
                    sink="ionic unsafe csp directives",
                    description="Ionic web assets include unsafe CSP directives.",
                    explanation="Unsafe CSP directives significantly weaken script-execution restrictions inside hybrid WebViews.",
                    path=[
                        {"file": None, "line": csp_line, "role": "source", "code": "[ionic webview] CSP governs script execution inside the hybrid shell.", "source_symbol": "csp", "variables": ["csp"]},
                        {"file": None, "line": csp_line, "role": "sink", "code": line_text(lines, csp_line, "unsafe-inline")},
                    ],
                    confidence="medium",
                    methods=["WEBVIEW"],
                    params=["csp"],
                    attack_label="WebView JavaScript Exposure",
                    attack_reason="Unsafe CSP directives increase XSS and script-injection impact.",
                )
            )

        open_line = first_match_line(lines, OPEN_RE)
        if open_line and not first_match_line(lines, OPEN_GUARD_RE, open_line, min(len(lines), open_line + 20)):
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="browser_open",
                    sink="ionic openurl sink",
                    description="Ionic browser plugin usage opens dynamic URLs without visible validation.",
                    explanation="Unvalidated browser-opening flows can redirect users to attacker-controlled content or custom-scheme handlers.",
                    path=[
                        {"file": None, "line": open_line, "role": "source", "code": "[ionic input] A dynamic URL reaches browser-opening code.", "source_symbol": "external_url", "variables": ["external_url"]},
                        {"file": None, "line": open_line, "role": "sink", "code": line_text(lines, open_line, "Browser.open(")},
                    ],
                    confidence="medium",
                    methods=["URL"],
                    uris=["https://attacker.example"],
                    params=["url"],
                    attack_label="Unvalidated URL Opening",
                    attack_reason="A dynamic browser target is opened without a visible allowlist.",
                    attack_example="https://attacker.example",
                )
            )

        cleartext_line = first_match_line(lines, CLEARTEXT_RE)
        if cleartext_line:
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="transport_config",
                    sink="ionic cleartext transport permitted",
                    description="Ionic/Capacitor platform configuration permits cleartext network transport.",
                    explanation="Transport relaxations such as ATS disablement or Android cleartext permission weaken channel confidentiality and integrity.",
                    path=[
                        {"file": None, "line": cleartext_line, "role": "source", "code": "[ionic config] Platform transport security configured for the hybrid app.", "source_symbol": "transport_config", "variables": ["transport_config"]},
                        {"file": None, "line": cleartext_line, "role": "sink", "code": line_text(lines, cleartext_line, "NSAllowsArbitraryLoads")},
                    ],
                    confidence="high",
                    methods=["NETWORK"],
                    params=["transport"],
                    attack_label="Insecure Transport",
                    attack_reason="The hybrid app configuration relaxes network transport protections.",
                )
            )

        http_line = first_match_line(lines, HTTP_RE)
        if http_line:
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="network_request",
                    sink="ionic insecure http endpoint",
                    description="Ionic code or config references a cleartext HTTP endpoint.",
                    explanation="Requests to `http://` endpoints are vulnerable to interception and tampering.",
                    path=[
                        {"file": None, "line": http_line, "role": "source", "code": "[ionic config] Endpoint declared in app code or config.", "source_symbol": "endpoint", "variables": ["endpoint"]},
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


def analyze_ionic_flows(source_root: Path, progress_callback=None):
    flows = annotate_flows(analyze_js_flows(source_root, progress_callback=progress_callback), platform="ionic", variant="javascript")
    flows.extend(annotate_flows(_semantic_flows(source_root), platform="ionic", variant="semantic"))
    return flows


def run(source_root: Path, progress_callback=None):
    flows = analyze_ionic_flows(source_root, progress_callback=progress_callback)
    out_dir = output_dir(state.reports_dirpath, "ionic")
    return write_reports(flows, out_dir, title="Ionic Dataflow Analysis", platform="ionic")
