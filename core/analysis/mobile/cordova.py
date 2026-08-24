# Standard libraries
from pathlib import Path
from typing import List
import re

import state.runtime_state as state
from core.analysis.javascript.analyzer import analyze_js_flows
from core.analysis.mobile.common import annotate_flows, collect_files, first_match_line, flow, line_text, output_dir
from core.analysis.report import write_reports


HTTP_RE = re.compile(r"http://", re.IGNORECASE)
OPEN_RE = re.compile(r"\b(?:window\.open|cordova\.InAppBrowser\.open)\s*\(", re.IGNORECASE)
OPEN_GUARD_RE = re.compile(r"\b(?:allowlist|whitelist|startsWith\s*\(\s*[\"']https?://|new URL\s*\()", re.IGNORECASE)
BRIDGE_RE = re.compile(r"\b(?:cordova\.exec|addJavascriptInterface)\s*\(", re.IGNORECASE)
CSP_RE = re.compile(r"unsafe-inline|unsafe-eval", re.IGNORECASE)
WILDCARD_RE = re.compile(r"<(?:allow-navigation|access)\b[^>]*(?:href|origin)=\"\*\"", re.IGNORECASE)


def _semantic_flows(source_root: Path) -> List[dict]:
    flows: List[dict] = []
    files = collect_files(source_root, ("*.js", "*.ts", "*.html", "config.xml"))
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
                    function="config.xml",
                    sink="cordova wildcard navigation policy",
                    description="Cordova configuration permits wildcard navigation or network origins.",
                    explanation="Wildcard origin and navigation policies allow untrusted content into the app WebView trust boundary.",
                    path=[
                        {"file": None, "line": wildcard_line, "role": "source", "code": "[cordova config] Cordova web content policy declared in config.xml.", "source_symbol": "cordova_config", "variables": ["cordova_config"]},
                        {"file": None, "line": wildcard_line, "role": "sink", "code": line_text(lines, wildcard_line, "<allow-navigation href=\"*\" />")},
                    ],
                    confidence="high",
                    methods=["WEBVIEW"],
                    uris=["https://attacker.example"],
                    params=["allow-navigation", "access origin"],
                    attack_label="WebView Trust Boundary Exposure",
                    attack_reason="Wildcard navigation or origin policies permit untrusted web content.",
                )
            )

        csp_line = first_match_line(lines, CSP_RE)
        if csp_line:
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="CSP",
                    sink="cordova unsafe csp directives",
                    description="Cordova web assets include unsafe CSP directives.",
                    explanation="`unsafe-inline` and `unsafe-eval` materially increase script-injection exploitability inside hybrid WebViews.",
                    path=[
                        {"file": None, "line": csp_line, "role": "source", "code": "[cordova webview] Content Security Policy controls script execution in the WebView.", "source_symbol": "csp", "variables": ["csp"]},
                        {"file": None, "line": csp_line, "role": "sink", "code": line_text(lines, csp_line, "unsafe-inline")},
                    ],
                    confidence="medium",
                    methods=["WEBVIEW"],
                    uris=[],
                    params=["csp"],
                    attack_label="WebView JavaScript Exposure",
                    attack_reason="Unsafe CSP directives weaken the browser-side script boundary.",
                )
            )

        open_line = first_match_line(lines, OPEN_RE)
        if open_line and not first_match_line(lines, OPEN_GUARD_RE, open_line, min(len(lines), open_line + 20)):
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="InAppBrowser",
                    sink="cordova openurl sink",
                    description="Cordova browser-opening code accepts dynamic URLs without visible validation.",
                    explanation="Unvalidated `window.open` or `InAppBrowser.open` targets can drive phishing or malicious redirect flows.",
                    path=[
                        {"file": None, "line": open_line, "role": "source", "code": "[cordova input] A dynamic URL reaches a browser-opening API.", "source_symbol": "external_url", "variables": ["external_url"]},
                        {"file": None, "line": open_line, "role": "sink", "code": line_text(lines, open_line, "window.open(")},
                    ],
                    confidence="medium",
                    methods=["URL"],
                    uris=["https://attacker.example"],
                    params=["url"],
                    attack_label="Unvalidated URL Opening",
                    attack_reason="A browser plugin opens a dynamic URL without a visible allowlist gate.",
                    attack_example="https://attacker.example",
                )
            )

        bridge_line = first_match_line(lines, BRIDGE_RE)
        if bridge_line:
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="cordova.exec",
                    sink="cordova javascript bridge exposure",
                    description="Cordova JavaScript-native bridge usage is present and should be treated as a trust boundary.",
                    explanation="Bridge entrypoints expose native capabilities to web content and become exploitable when untrusted content is reachable.",
                    path=[
                        {"file": None, "line": bridge_line, "role": "source", "code": "[cordova bridge] Web content can invoke native bridge capabilities.", "source_symbol": "web_content", "variables": ["web_content"]},
                        {"file": None, "line": bridge_line, "role": "sink", "code": line_text(lines, bridge_line, "cordova.exec(")},
                    ],
                    confidence="medium",
                    methods=["CHANNEL"],
                    uris=["cordova://bridge"],
                    params=["plugin", "action", "args"],
                    attack_label="Bridge Exposure",
                    attack_reason="The Cordova bridge is active and should be constrained to trusted content paths.",
                )
            )

        http_line = first_match_line(lines, HTTP_RE)
        if http_line:
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="network_request",
                    sink="cordova insecure http endpoint",
                    description="Cordova code or config references a cleartext HTTP endpoint.",
                    explanation="Hybrid app traffic sent to `http://` endpoints is vulnerable to interception and tampering.",
                    path=[
                        {"file": None, "line": http_line, "role": "source", "code": "[cordova config] Endpoint declared in app assets or config.", "source_symbol": "endpoint", "variables": ["endpoint"]},
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


def analyze_cordova_flows(source_root: Path, progress_callback=None):
    flows = annotate_flows(analyze_js_flows(source_root, progress_callback=progress_callback), platform="cordova", variant="javascript")
    flows.extend(annotate_flows(_semantic_flows(source_root), platform="cordova", variant="semantic"))
    return flows


def run(source_root: Path, progress_callback=None):
    flows = analyze_cordova_flows(source_root, progress_callback=progress_callback)
    out_dir = output_dir(state.reports_dirpath, "cordova")
    return write_reports(flows, out_dir, title="Cordova Dataflow Analysis", platform="cordova")
