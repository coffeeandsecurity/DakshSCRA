# Standard libraries
from pathlib import Path
from typing import List
import re

import state.runtime_state as state
from core.analysis.javascript.analyzer import analyze_js_flows
from core.analysis.mobile.common import annotate_flows, collect_files, first_match_line, flow, line_text, output_dir
from core.analysis.report import write_reports


HTTP_RE = re.compile(r"[\"']http://[^\"']+[\"']", re.IGNORECASE)
OPEN_URL_RE = re.compile(r"\bLinking\.openURL\s*\(", re.IGNORECASE)
# No trailing \b on the startsWith(...https?:// or "new URL(" alternatives -
# both end in a non-word char ("/" or "("), and \b can silently fail to
# match depending on what character follows (see maui.py's identical fix).
OPEN_URL_GUARD_RE = re.compile(r"\b(?:canOpenURL|allowlist|whitelist)\b|\bstartsWith\s*\(\s*[\"']https?://|\bnew URL\s*\(", re.IGNORECASE)
MESSAGE_RE = re.compile(r"\b(?:addEventListener\s*\(\s*['\"]message['\"]|onMessage\s*=)", re.IGNORECASE)
ORIGIN_GUARD_RE = re.compile(r"\b(?:event\.origin|originWhitelist|onShouldStartLoadWithRequest|allowlist|whitelist)\b", re.IGNORECASE)
WEBVIEW_RE = re.compile(r"<WebView|react-native-webview", re.IGNORECASE)
JS_ENABLED_RE = re.compile(r"javaScriptEnabled\s*=\s*\{?\s*true\}?", re.IGNORECASE)
SOURCE_URI_RE = re.compile(r"source\s*=\s*\{\{?\s*uri\s*:", re.IGNORECASE)
WILDCARD_ORIGIN_RE = re.compile(r"originWhitelist\s*=\s*\{?\s*\[\s*[\"']\*[\"']", re.IGNORECASE)
REACT_METHOD_RE = re.compile(r"@ReactMethod\b")
REACT_GUARD_RE = re.compile(r"\b(?:checkSelfPermission|checkCallingPermission|enforceCallingPermission|isAuthenticated|requireAuth|auth)\b", re.IGNORECASE)


def _js_semantic_flows(source_root: Path) -> List[dict]:
    flows: List[dict] = []
    source_files = collect_files(source_root, ("*.js", "*.jsx", "*.ts", "*.tsx"))
    for file_path in source_files:
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        http_line = first_match_line(lines, HTTP_RE)
        if http_line:
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="network_request",
                    sink="reactnative insecure http endpoint",
                    description="React Native code references a cleartext HTTP endpoint.",
                    explanation="Mobile traffic to `http://` endpoints can be intercepted or modified on hostile networks.",
                    path=[
                        {"file": None, "line": http_line, "role": "source", "code": "[reactnative config] Endpoint declared in app code.", "source_symbol": "endpoint", "variables": ["endpoint"]},
                        {"file": None, "line": http_line, "role": "sink", "code": line_text(lines, http_line, "http://")},
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

        open_line = first_match_line(lines, OPEN_URL_RE)
        if open_line and not first_match_line(lines, OPEN_URL_GUARD_RE, open_line, min(len(lines), open_line + 20)):
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="Linking.openURL",
                    sink="reactnative openurl sink",
                    description="`Linking.openURL` is used without visible scheme or host validation.",
                    explanation="Opening attacker-controlled URLs can trigger phishing flows or invoke unexpected custom schemes.",
                    path=[
                        {"file": None, "line": open_line, "role": "source", "code": "[reactnative input] URL value reaches external app-opening code.", "source_symbol": "external_url", "variables": ["external_url"]},
                        {"file": None, "line": open_line, "role": "sink", "code": line_text(lines, open_line, "Linking.openURL(")},
                    ],
                    confidence="medium",
                    methods=["URL"],
                    uris=["https://attacker.example/path"],
                    params=["url"],
                    attack_label="Unvalidated URL Opening",
                    attack_reason="A dynamic URL reaches `Linking.openURL` without an allowlist gate.",
                    attack_example="https://attacker.example/path",
                )
            )

        message_line = first_match_line(lines, MESSAGE_RE)
        if message_line and not first_match_line(lines, ORIGIN_GUARD_RE, message_line, min(len(lines), message_line + 30)):
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="postMessage_handler",
                    sink="reactnative message bridge without origin validation",
                    description="A React Native WebView message handler processes messages without visible origin validation.",
                    explanation="WebView bridge messages should validate `event.origin` or equivalent navigation trust before invoking native actions.",
                    path=[
                        {"file": None, "line": message_line, "role": "source", "code": "[reactnative bridge] Web content can send a postMessage event to the app.", "source_symbol": "web_message", "variables": ["web_message"]},
                        {"file": None, "line": message_line, "role": "sink", "code": line_text(lines, message_line, "onMessage/addEventListener('message')")},
                    ],
                    confidence="medium",
                    methods=["WEBVIEW"],
                    uris=["https://attacker.example"],
                    params=["event.data"],
                    attack_label="Bridge Exposure",
                    attack_reason="The WebView message bridge lacks a visible origin trust check.",
                    attack_example="window.ReactNativeWebView.postMessage('<PAYLOAD>')",
                )
            )

        webview_line = first_match_line(lines, WEBVIEW_RE)
        if webview_line:
            wildcard_line = first_match_line(lines, WILDCARD_ORIGIN_RE, webview_line, min(len(lines), webview_line + 40))
            source_line = first_match_line(lines, SOURCE_URI_RE, webview_line, min(len(lines), webview_line + 40))
            js_line = first_match_line(lines, JS_ENABLED_RE, webview_line, min(len(lines), webview_line + 40))
            guard_line = first_match_line(lines, ORIGIN_GUARD_RE, webview_line, min(len(lines), webview_line + 40))
            if (wildcard_line or source_line or js_line) and not guard_line:
                sink_line = wildcard_line or source_line or js_line
                flows.append(
                    flow(
                        source_root=source_root,
                        file_path=file_path,
                        function="WebView",
                        sink="reactnative webview trust boundary exposure",
                        description="A React Native WebView loads content or enables script execution without visible origin restrictions.",
                        explanation="WebView origin wildcards or dynamic `source={{uri}}` flows can expose the JS bridge and app state to untrusted content.",
                        path=[
                            {"file": None, "line": webview_line, "role": "source", "code": "[reactnative webview] Web content enters the app WebView trust boundary.", "source_symbol": "web_content", "variables": ["web_content"]},
                            {"file": None, "line": sink_line, "role": "sink", "code": line_text(lines, sink_line, "<WebView")},
                        ],
                        confidence="medium",
                        methods=["WEBVIEW"],
                        uris=["https://attacker.example"],
                        params=["uri", "originWhitelist"],
                        attack_label="WebView JavaScript Exposure",
                        attack_reason="The WebView accepts untrusted content without a visible origin policy or navigation gate.",
                        attack_example="https://attacker.example",
                    )
                )
    return flows


def _native_bridge_flows(source_root: Path) -> List[dict]:
    flows: List[dict] = []
    native_files = collect_files(source_root, ("*.java", "*.kt"))
    for file_path in native_files:
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        react_line = first_match_line(lines, REACT_METHOD_RE)
        if react_line and not first_match_line(lines, REACT_GUARD_RE, react_line, min(len(lines), react_line + 25)):
            flows.append(
                flow(
                    source_root=source_root,
                    file_path=file_path,
                    function="ReactMethod",
                    sink="reactnative native bridge without permission check",
                    description="A native `@ReactMethod` is exposed without visible permission or authentication checks.",
                    explanation="React Native bridge methods can be invoked from JavaScript contexts and should gate privileged native actions.",
                    path=[
                        {"file": None, "line": react_line, "role": "source", "code": "[reactnative bridge] JavaScript can invoke the exposed native module method.", "source_symbol": "bridge_call", "variables": ["bridge_call"]},
                        {"file": None, "line": react_line, "role": "sink", "code": line_text(lines, react_line, "@ReactMethod")},
                    ],
                    confidence="medium",
                    methods=["CHANNEL"],
                    uris=["reactnative://bridge"],
                    params=["method", "arguments"],
                    attack_label="Bridge Exposure",
                    attack_reason="The native bridge entrypoint lacks a visible caller validation gate.",
                    attack_example="NativeModules.Module.method('<PAYLOAD>')",
                )
            )
    return flows


def analyze_reactnative_flows(source_root: Path, progress_callback=None):
    flows = annotate_flows(analyze_js_flows(source_root, progress_callback=progress_callback), platform="reactnative", variant="javascript")
    flows.extend(annotate_flows(_js_semantic_flows(source_root) + _native_bridge_flows(source_root), platform="reactnative", variant="semantic"))
    return flows


def run(source_root: Path, progress_callback=None):
    flows = analyze_reactnative_flows(source_root, progress_callback=progress_callback)
    out_dir = output_dir(state.reports_dirpath, "reactnative")
    return write_reports(flows, out_dir, title="React Native Dataflow Analysis", platform="reactnative")
