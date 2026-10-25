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
    from core.mobile_model import views, block_end, url_guarded, build_scope
    flows = []
    for file_path in collect_files(source_root, ("*.js", "*.jsx", "*.ts", "*.tsx")):
        try:
            text = file_path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        comments, code = views(file_path, text)
        lines = text.splitlines()
        candidates = []
        for hit in HTTP_RE.finditer(comments):
            candidates.append((hit.start(), 'reactnative insecure http endpoint', 'Cleartext endpoint reference; resolve actual network use and selected build.'))
        for hit in OPEN_URL_RE.finditer(code):
            end = block_end(code, hit.end()-1, '(', ')')
            argument = comments[hit.end():end-1].strip() if end else ''
            if re.fullmatch(r'["\']https://[^"\']+["\']', argument):
                continue
            if not url_guarded(comments, code, hit.start(), argument):
                candidates.append((hit.start(), 'reactnative openurl sink', 'External URL operation: verify a rejecting scheme/host policy on this value before use. Parsing and capability checks alone do not authorize it.'))
        for hit in MESSAGE_RE.finditer(comments):
            if code[hit.start():hit.start()+1].strip():
                candidates.append((hit.start(), 'reactnative message bridge without origin validation', 'Web message callback: resolve sender/navigation trust and authorization of each privileged action. Nearby property names do not prove an effective check.'))
        for hit in re.finditer(r'<WebView\b', code):
            # Stop at this JSX element; a later WebView cannot protect this one.
            end = comments.find('/>', hit.end())
            if end < 0:
                end = comments.find('>', hit.end())
            segment = comments[hit.start():end+2] if end >= 0 else comments[hit.start():hit.start()+2000]
            if any(pattern.search(segment) for pattern in (WILDCARD_ORIGIN_RE, SOURCE_URI_RE, JS_ENABLED_RE)):
                candidates.append((hit.start(), 'reactnative webview trust boundary exposure', 'WebView content/script surface: evaluate its actual origin list and navigation callback. A wildcard or a callback that accepts every navigation is not a restriction.'))
        for offset, sink, description in candidates:
            line = text.count('\n', 0, offset)+1
            item = flow(source_root=source_root, file_path=file_path, function=sink,
                        sink=sink, description=description, explanation=description,
                        path=[dict(file=None,line=line,role='source',code='[mobile review] Source influence and active callers require verification.'),
                              dict(file=None,line=line,role='sink',code=line_text(lines,line,''))],
                        confidence='low', methods=['REVIEW'], params=['value'])
            item.update(build_scope=build_scope(file_path), analysis_kind='heuristic',
                        control_status='unresolved', configuration_status='source_configuration')
            flows.append(item)
    return flows


def _native_bridge_flows(source_root: Path) -> List[dict]:
    from core.mobile_model import views
    flows=[]
    for file_path in collect_files(source_root, ('*.java','*.kt')):
        try:
            text=file_path.read_text(encoding='utf-8',errors='replace')
        except OSError:
            continue
        comments,code=views(file_path,text)
        for hit in REACT_METHOD_RE.finditer(code):
            line=text.count('\n',0,hit.start())+1
            description='Native bridge export: resolve exact module registration, argument schema and authorization of privileged operations. An annotation alone does not establish exposure to an external caller.'
            flows.append(flow(source_root=source_root,file_path=file_path,function='ReactMethod',
                sink='reactnative native bridge review',description=description,explanation=description,
                path=[dict(file=None,line=line,role='source',code='[bridge review] Resolve caller and selected registration.'),
                      dict(file=None,line=line,role='sink',code=text.splitlines()[line-1])],
                confidence='low',methods=['CHANNEL'],params=['method','arguments']))
    return flows


def analyze_reactnative_flows(source_root: Path, progress_callback=None):
    flows = annotate_flows(analyze_js_flows(source_root, progress_callback=progress_callback), platform="reactnative", variant="javascript")
    flows.extend(annotate_flows(_js_semantic_flows(source_root) + _native_bridge_flows(source_root), platform="reactnative", variant="semantic"))
    return flows


def run(source_root: Path, progress_callback=None):
    flows = analyze_reactnative_flows(source_root, progress_callback=progress_callback)
    out_dir = output_dir(state.reports_dirpath, "reactnative")
    return write_reports(flows, out_dir, title="React Native Dataflow Analysis", platform="reactnative")
