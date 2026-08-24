# Standard libraries
from pathlib import Path
from typing import Dict, List
import xml.etree.ElementTree as ET
import re

import state.runtime_state as state
from core.analysis.java.analyzer import analyze_java_flows
from core.analysis.kotlin.analyzer import analyze_kotlin_flows
from core.analysis.mobile.common import annotate_flows, output_dir
from core.analysis.report import write_reports

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")
PACKAGE_RE = re.compile(r"^\s*package\s+([A-Za-z0-9_\.]+)", re.MULTILINE)
METHOD_DEF_RE = re.compile(r"^\s*(?:(?:public|private|protected|internal|override|suspend|open|final|abstract|static)\s+)*fun\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(|^\s*(?:(?:public|private|protected|static|final|synchronized|native|abstract)\s+)*(?:[A-Za-z_][\w<>\[\]\.,\?]*\s+)+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
CALL_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")
ENTRY_METHODS = {
    "activity": ("onCreate(", "onNewIntent(", "onStart(", "onResume("),
    "service": ("onStartCommand(", "onBind(", "onHandleIntent("),
    "receiver": ("onReceive(",),
    "provider": ("query(", "insert(", "update(", "delete(", "openFile(", "call("),
}
INPUT_PATTERNS = [
    ("intent extra", re.compile(r"(?:getIntent\(\)\.|intent\.)get(?:String|Boolean|Int|Long|Parcelable)?Extra\s*\(")),
    ("bundle extra", re.compile(r"(?:extras|Bundle)\.(?:getString|getInt|getLong|getBoolean|getParcelable)\s*\(")),
    ("intent data", re.compile(r"(?:getIntent\(\)\.|intent\.)getData(?:String)?\s*\(")),
    ("intent uri", re.compile(r"(?:getIntent\(\)\.|intent\.)get(?:Data|Scheme|Action)\s*\(")),
]
PROVIDER_INPUT_PATTERNS = [
    ("provider selection", re.compile(r"\bselection\b|\bselectionArgs\b")),
    ("provider uri", re.compile(r"\buri\b|\bgetPathSegments\s*\(")),
]
GUARD_PATTERNS = [
    re.compile(r"checkCallingPermission\s*\("),
    re.compile(r"enforceCallingPermission\s*\("),
    re.compile(r"checkCallingOrSelfPermission\s*\("),
    re.compile(r"enforceCallingOrSelfPermission\s*\("),
    re.compile(r"checkSelfPermission\s*\("),
    re.compile(r"Binder\.getCallingUid\s*\("),
    re.compile(r"getCallingUid\s*\("),
    re.compile(r"isAuthenticated\s*\("),
    re.compile(r"requireAuth(?:entication)?\s*\("),
    re.compile(r"auth(?:Manager|Service|Token|Session)", re.IGNORECASE),
]
SINK_PATTERNS = [
    ("exported component webview sink", "javascript_injection", re.compile(r"(?:loadUrl|evaluateJavascript|addJavascriptInterface)\s*\("), "JavaScript-capable WebView sink"),
    ("exported component sql sink", "sql_injection", re.compile(r"(?:rawQuery|execSQL|SQLiteQueryBuilder|compileStatement)\s*\("), "SQLite execution sink"),
    ("exported component command sink", "command_injection", re.compile(r"(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\()"), "Process execution sink"),
    ("pendingintent mutable sink", "pendingintent_injection", re.compile(r"PendingIntent\.(?:getBroadcast|getActivity|getService|getForegroundService)\s*\("), "Mutable PendingIntent sink"),
]
PROVIDER_SINK_PATTERNS = [
    ("content provider sql sink", "sql_injection", re.compile(r"(?:rawQuery|execSQL|SQLiteQueryBuilder|queryBuilder|SQLiteDatabase\.(?:query|rawQuery|execSQL))"), "Provider-backed SQL sink"),
]
RECEIVER_SINK_PATTERNS = [
    ("broadcast command sink", "command_injection", re.compile(r"(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\()"), "Broadcast-triggered command sink"),
    ("broadcast webview sink", "javascript_injection", re.compile(r"(?:loadUrl|evaluateJavascript|addJavascriptInterface)\s*\("), "Broadcast-triggered WebView sink"),
]
PENDING_INTENT_IMMUTABLE_RE = re.compile(r"FLAG_IMMUTABLE|PendingIntentCompat")
BINDER_STUB_RE = re.compile(r"(?:extends\s+\w+\.Stub\b|:\s*[A-Za-z0-9_\.]+\.Stub\s*\()")
BROADCAST_SEND_RE = re.compile(r"\b(?:sendBroadcast|sendStickyBroadcast|sendOrderedBroadcast)\s*\(")
IGNORED_CALLS = {
    "if", "for", "while", "when", "switch", "return", "fun", "class", "super", "this",
    "loadUrl", "evaluateJavascript", "addJavascriptInterface", "rawQuery", "execSQL",
    "query", "insert", "update", "delete", "onCreate", "onReceive", "onStartCommand",
    "getStringExtra", "getData", "getAction", "getString", "getInt", "getBoolean", "getParcelable",
}


def _rel_path(file_path: Path, source_root: Path) -> str:
    try:
        return str(file_path.relative_to(source_root)).replace("\\", "/")
    except ValueError:
        return str(file_path).replace("\\", "/")


def _line_no(lines: List[str], *needles: str) -> int:
    candidates = [str(item or "").strip() for item in needles if str(item or "").strip()]
    for idx, line in enumerate(lines, start=1):
        if all(token in line for token in candidates):
            return idx
    for idx, line in enumerate(lines, start=1):
        if any(token in line for token in candidates):
            return idx
    return 1


def _android_attr(element: ET.Element, name: str) -> str:
    return str(element.get(f"{ANDROID_NS}{name}") or "").strip()


def _bool_attr(element: ET.Element, name: str, default: bool = False) -> bool:
    raw = _android_attr(element, name).lower()
    if raw == "true":
        return True
    if raw == "false":
        return False
    return default


def _component_is_exported(component: ET.Element) -> bool:
    exported = _android_attr(component, "exported").lower()
    if exported == "true":
        return True
    if exported == "false":
        return False
    return component.find("intent-filter") is not None


def _permission_guard(component: ET.Element) -> str:
    for name in ("permission", "readPermission", "writePermission"):
        value = _android_attr(component, name)
        if value:
            return value
    return ""


def _component_kind(tag: str) -> str:
    normalized = str(tag or "").split("}")[-1]
    if normalized == "activity-alias":
        return "activity"
    return normalized


def _manifest_package(root: ET.Element) -> str:
    return str(root.get("package") or "").strip()


def _package_from_text(text: str) -> str:
    match = PACKAGE_RE.search(text or "")
    return str(match.group(1) or "").strip() if match else ""


def _resolve_component_name(component_name: str, manifest_package: str) -> str:
    token = str(component_name or "").strip()
    if not token:
        return ""
    if token.startswith("."):
        return f"{manifest_package}{token}" if manifest_package else token.lstrip(".")
    if "." not in token and manifest_package:
        return f"{manifest_package}.{token}"
    return token


def _source_index(source_root: Path) -> Dict[str, Path]:
    index: Dict[str, Path] = {}
    for glob in ("*.kt", "*.java"):
        for file_path in source_root.rglob(glob):
            try:
                text = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            package_name = _package_from_text(text)
            stem = file_path.stem
            fqcn = f"{package_name}.{stem}" if package_name else stem
            for key in {stem, fqcn, f".{stem}"}:
                index.setdefault(key, file_path)
    return index


def _source_cache(source_root: Path) -> Dict[Path, List[str]]:
    cache: Dict[Path, List[str]] = {}
    for glob in ("*.kt", "*.java"):
        for file_path in source_root.rglob(glob):
            try:
                cache[file_path] = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
    return cache


def _method_index(source_cache: Dict[Path, List[str]]) -> Dict[str, List[Dict]]:
    index: Dict[str, List[Dict]] = {}
    for file_path, lines in source_cache.items():
        for idx, line in enumerate(lines, start=1):
            match = METHOD_DEF_RE.search(line)
            if not match:
                continue
            name = str(match.group(1) or match.group(2) or "").strip()
            if not name:
                continue
            index.setdefault(name, []).append({"file": file_path, "line": idx, "lines": lines})
    return index


def _find_component_source(component_name: str, manifest_package: str, source_map: Dict[str, Path]) -> Path:
    resolved = _resolve_component_name(component_name, manifest_package)
    for key in (component_name, resolved, Path(resolved).name if resolved else "", f".{Path(resolved).name}" if resolved else ""):
        token = str(key or "").strip()
        if token and token in source_map:
            return source_map[token]
    return None


def _first_match_line(lines: List[str], pattern: re.Pattern, start: int = 1) -> int:
    for idx in range(max(1, start), len(lines) + 1):
        if pattern.search(lines[idx - 1]):
            return idx
    return 0


def _first_text_line(lines: List[str], tokens: List[str], start: int = 1) -> int:
    for idx in range(max(1, start), len(lines) + 1):
        line = lines[idx - 1]
        if any(token in line for token in tokens):
            return idx
    return 0


def _entry_line(lines: List[str], kind: str) -> int:
    return _first_text_line(lines, list(ENTRY_METHODS.get(kind, ())), start=1) or 1


def _input_read(lines: List[str], start: int = 1) -> Dict:
    for label, pattern in INPUT_PATTERNS:
        line = _first_match_line(lines, pattern, start=start)
        if line:
            return {"label": label, "line": line, "code": lines[line - 1].strip()}
    return {}


def _provider_input_read(lines: List[str], start: int = 1) -> Dict:
    for label, pattern in PROVIDER_INPUT_PATTERNS:
        line = _first_match_line(lines, pattern, start=start)
        if line:
            return {"label": label, "line": line, "code": lines[line - 1].strip()}
    return {}


def _guard_present(lines: List[str], start: int = 1, end: int = 0) -> bool:
    upper = end or len(lines)
    window = lines[max(0, start - 1):upper]
    for line in window:
        if any(pattern.search(line) for pattern in GUARD_PATTERNS):
            return True
    return False


def _sink_hit(lines: List[str], patterns: List, start: int = 1) -> Dict:
    best = {}
    for sink_name, kind, pattern, label in patterns:
        line = _first_match_line(lines, pattern, start=start)
        if not line:
            continue
        if not best or line < best["line"]:
            best = {
                "sink_name": sink_name,
                "kind": kind,
                "label": label,
                "line": line,
                "code": lines[line - 1].strip(),
            }
    return best


def _resolve_helper_chain(lines: List[str], start_line: int, method_index: Dict[str, List[Dict]], patterns: List, max_depth: int = 3, seen=None) -> Dict:
    seen = set(seen or set())
    for idx in range(max(1, start_line), len(lines) + 1):
        line = lines[idx - 1]
        for match in CALL_RE.finditer(line):
            name = str(match.group(1) or "").strip()
            if not name or name in IGNORED_CALLS:
                continue
            for candidate in method_index.get(name, []):
                key = (str(candidate.get("file")), int(candidate.get("line") or 0), name)
                if key in seen:
                    continue
                candidate_lines = candidate.get("lines", [])
                sink_hit = _sink_hit(candidate_lines, patterns, start=int(candidate.get("line") or 1))
                if sink_hit:
                    return {
                        "hops": [
                            {
                                "helper_name": name,
                                "helper_line": idx,
                                "helper_code": line.strip(),
                                "callee_file": candidate["file"],
                                "callee_line": candidate["line"],
                            }
                        ],
                        "sink_hit": sink_hit,
                    }
                if max_depth > 1:
                    nested = _resolve_helper_chain(
                        candidate_lines,
                        int(candidate.get("line") or 1),
                        method_index,
                        patterns,
                        max_depth=max_depth - 1,
                        seen=seen | {key},
                    )
                    if nested:
                        return {
                            "hops": [
                                {
                                    "helper_name": name,
                                    "helper_line": idx,
                                    "helper_code": line.strip(),
                                    "callee_file": candidate["file"],
                                    "callee_line": candidate["line"],
                                },
                                *(nested.get("hops") or []),
                            ],
                            "sink_hit": nested.get("sink_hit", {}),
                        }
    return {}


def _flow_template(
    *,
    file_path: str,
    source_line: int,
    sink_line: int,
    source_code: str,
    sink_code: str,
    sink_name: str,
    description: str,
    explanation: str,
    function: str,
    input_surface: Dict,
    attack_vectors: List[Dict],
) -> Dict:
    path = [
        {
            "file": file_path,
            "line": source_line,
            "role": "source",
            "code": source_code,
            "source_symbol": "external_app",
            "variables": ["external_app"],
        },
        {
            "file": file_path,
            "line": sink_line,
            "role": "sink",
            "code": sink_code,
        },
    ]
    return {
        "file": file_path,
        "line": sink_line,
        "function": function,
        "sink": sink_name,
        "description": description,
        "explanation": explanation,
        "path": path,
        "trace_status": "complete",
        "confidence": "high",
        "xref": [],
        "input_surface": input_surface,
        "attack_vectors": attack_vectors,
    }


def _source_backed_flow(
    *,
    source_root: Path,
    file_path: Path,
    component_name: str,
    component_kind: str,
    sink_hit: Dict,
    input_hit: Dict,
    guard_present: bool,
    surface_example: str,
    sink_summary: str,
    helper_handoff: Dict = None,
) -> Dict:
    rel_path = _rel_path(file_path, source_root)
    lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    entry_line = _entry_line(lines, component_kind)
    input_line = int(input_hit.get("line") or entry_line)
    active_sink = (helper_handoff or {}).get("sink_hit") or sink_hit
    hops = (helper_handoff or {}).get("hops") or []
    sink_file_path = hops[-1]["callee_file"] if hops else file_path
    sink_line = int(active_sink.get("line") or input_line)
    input_label = str(input_hit.get("label") or "intent input")
    input_code = str(input_hit.get("code") or f"[android input] {input_label}")
    guard_text = "No caller validation or authentication guard was found near the entrypoint." if not guard_present else "Entry code contains permission/auth checks, but the sink remains reachable in this path."
    sink_name = str(active_sink.get("sink_name") or sink_summary)
    description = (
        f"Exported {component_kind} `{component_name}` reads attacker-controlled {input_label} and reaches {sink_summary.lower()}."
    )
    explanation = (
        f"External apps can invoke `{component_name}`. The handler reads {input_label} and then reaches {sink_summary.lower()}. "
        f"{guard_text}"
    )
    path = [
        {
            "file": rel_path,
            "line": entry_line,
            "role": "source",
            "code": f"[android entrypoint] Exported {component_kind} `{component_name}` invoked by external app.",
            "source_symbol": "external_app",
            "variables": ["external_app"],
        },
        {
            "file": rel_path,
            "line": input_line,
            "role": "param",
            "code": input_code,
            "source_symbol": "intent.data" if "data" in input_label else "intent.extra",
            "variables": ["intent_input"],
        },
    ]
    for hop in hops:
        path.append(
            {
                "file": rel_path if hop is hops[0] else _rel_path(hop.get("callee_file"), source_root),
                "line": int(hop.get("helper_line") or input_line),
                "role": "call",
                "code": str(hop.get("helper_code") or ""),
                "symbol": str(hop.get("helper_name") or ""),
                "target_symbol": str(hop.get("helper_name") or ""),
                "variables": ["intent_input", str(hop.get("helper_name") or "")],
            }
        )
    path.append(
        {
            "file": _rel_path(sink_file_path, source_root),
            "line": sink_line,
            "role": "sink",
            "code": str(active_sink.get("code") or sink_name),
        },
    )
    return {
        "file": _rel_path(sink_file_path, source_root),
        "line": sink_line,
        "function": component_name,
        "sink": sink_name,
        "description": description,
        "explanation": explanation,
        "path": path,
        "trace_status": "complete",
        "confidence": "high" if not guard_present else "medium",
        "xref": [],
        "input_surface": {
            "channel": "mobile-app",
            "methods": ["INTENT"],
            "uris": [surface_example] if surface_example.startswith(("http", "custom", "content")) else [],
            "params": [input_label],
            "derived_params": [],
            "examples": [surface_example],
        },
        "attack_vectors": [
            {
                "kind": "mobile",
                "label": sink_summary,
                "reason": f"An external app can supply crafted intent input that reaches {sink_summary.lower()}.",
                "examples": [surface_example],
                "taint_symbols": ["intent_input"],
            }
        ],
    }


def _provider_source_flow(
    *,
    source_root: Path,
    file_path: Path,
    component_name: str,
    sink_hit: Dict,
    authorities: str,
    guard_present: bool,
    input_hit: Dict = None,
    helper_handoff: Dict = None,
) -> Dict:
    rel_path = _rel_path(file_path, source_root)
    lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    entry_line = _entry_line(lines, "provider")
    active_sink = (helper_handoff or {}).get("sink_hit") or sink_hit
    hops = (helper_handoff or {}).get("hops") or []
    sink_file_path = hops[-1]["callee_file"] if hops else file_path
    sink_line = int(active_sink.get("line") or entry_line)
    explanation = (
        f"External apps can query provider `{component_name}` through authority `{authorities}`. "
        f"The provider implementation reaches {active_sink.get('label', 'a sensitive sink').lower()}. "
        f"{'No caller validation was found near the provider methods.' if not guard_present else 'Caller validation markers exist, but the sink remains reachable in the provider path.'}"
    )
    path = [
        {
            "file": rel_path,
            "line": entry_line,
            "role": "source",
            "code": f"[android provider] External ContentResolver request reaches `{component_name}`.",
            "source_symbol": "content_resolver",
            "variables": ["content_resolver"],
        },
    ]
    if input_hit:
        path.append(
            {
                "file": rel_path,
                "line": int(input_hit.get("line") or entry_line),
                "role": "param",
                "code": str(input_hit.get("code") or ""),
                "source_symbol": "provider_input",
                "variables": ["provider_input"],
            }
        )
    for hop in hops:
        path.append(
            {
                "file": rel_path if hop is hops[0] else _rel_path(hop.get("callee_file"), source_root),
                "line": int(hop.get("helper_line") or input_hit.get("line") or entry_line) if input_hit else int(hop.get("helper_line") or entry_line),
                "role": "call",
                "code": str(hop.get("helper_code") or ""),
                "symbol": str(hop.get("helper_name") or ""),
                "target_symbol": str(hop.get("helper_name") or ""),
                "variables": ["provider_input", str(hop.get("helper_name") or "")],
            }
        )
    path.append(
        {
            "file": _rel_path(sink_file_path, source_root),
            "line": sink_line,
            "role": "sink",
            "code": str(active_sink.get("code") or ""),
        },
    )
    return {
        "file": _rel_path(sink_file_path, source_root),
        "line": sink_line,
        "function": component_name,
        "sink": str(active_sink.get("sink_name") or "content provider sql sink"),
        "description": f"Externally reachable content provider `{component_name}` routes caller-controlled input into {str(active_sink.get('label') or 'SQL execution').lower()}.",
        "explanation": explanation,
        "path": path,
        "trace_status": "complete",
        "confidence": "high" if not guard_present else "medium",
        "xref": [],
        "input_surface": {
            "channel": "mobile-app",
            "methods": ["CONTENT_PROVIDER"],
            "uris": [f"content://{authorities}"] if authorities else [],
            "params": [str(input_hit.get("label") or "uri path") if input_hit else "uri path"],
            "derived_params": [],
            "examples": [f"adb shell content query --uri content://{authorities} --where \"_id=<PAYLOAD>\""] if authorities else [],
        },
        "attack_vectors": [
            {
                "kind": "mobile",
                "label": "Provider to SQL path",
                "reason": "A hostile app can exercise the provider entrypoint and influence downstream database operations.",
                "examples": [f"adb shell content query --uri content://{authorities} --where \"_id=<PAYLOAD>\""] if authorities else [],
                "taint_symbols": ["content_resolver"],
            }
        ],
    }


def _binder_service_flow(source_root: Path, file_path: Path, component_name: str, authorities: str = "") -> Dict:
    rel_path = _rel_path(file_path, source_root)
    lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    binder_line = _first_match_line(lines, BINDER_STUB_RE, start=1) or 1
    return {
        "file": rel_path,
        "line": binder_line,
        "function": component_name,
        "sink": "binder caller validation missing",
        "description": f"Exported Android service `{component_name}` exposes a Binder/AIDL stub without validating the caller identity.",
        "explanation": "An external app can bind to the exported service and invoke Binder methods. No calling UID/PID or permission enforcement was detected near the Binder stub implementation.",
        "path": [
            {
                "file": rel_path,
                "line": _entry_line(lines, "service"),
                "role": "source",
                "code": f"[android binder] External app binds to exported service `{component_name}`.",
                "source_symbol": "binder_client",
                "variables": ["binder_client"],
            },
            {
                "file": rel_path,
                "line": binder_line,
                "role": "sink",
                "code": lines[binder_line - 1].strip() if binder_line <= len(lines) else "extends Stub",
            },
        ],
        "trace_status": "complete",
        "confidence": "high",
        "xref": [],
        "input_surface": {
            "channel": "mobile-app",
            "methods": ["BINDER"],
            "uris": [],
            "params": ["Binder method arguments"],
            "derived_params": [],
            "examples": [f"Bind to exported service `{component_name}` and invoke remote methods"],
        },
        "attack_vectors": [
            {
                "kind": "mobile",
                "label": "Binder caller spoofing",
                "reason": "A hostile app can call exported Binder methods without caller identity validation.",
                "examples": [f"Bind to exported service `{component_name}` and invoke remote methods"],
                "taint_symbols": ["binder_client"],
            }
        ],
    }


def _exported_component_flows(manifest_path: Path, source_root: Path, root: ET.Element, lines: List[str], source_map: Dict[str, Path], manifest_package: str, method_index: Dict[str, List[Dict]]) -> List[Dict]:
    flows: List[Dict] = []
    rel_path = _rel_path(manifest_path, source_root)
    app = root.find("application")
    if app is None:
        return flows

    for component in app:
        tag = _component_kind(component.tag)
        if tag not in COMPONENT_TAGS:
            continue
        if not _component_is_exported(component):
            continue

        permission = _permission_guard(component)
        component_name = _android_attr(component, "name") or tag
        source_line = _line_no(lines, component_name)
        exported_line = _line_no(lines, component_name, "android:exported")

        # Exported provider with no permission is handled separately.
        if tag == "provider" and not permission:
            continue
        if permission:
            continue

        sink_name = "exported component"
        description = f"Externally reachable Android {tag} `{component_name}` is exported without a permission guard."
        explanation = (
            f"The manifest exposes `{component_name}` to other applications. "
            "No component-level permission is declared, so an external app can invoke it directly."
        )
        sink_code = f"<{tag} android:name=\"{component_name}\" android:exported=\"true\">"
        source_code = f"[android entrypoint] External intent can reach exported {tag} `{component_name}`."
        attack_vectors = [
            {
                "kind": "mobile",
                "label": f"ADB start {tag}",
                "reason": "An external app or tester can launch this exported component directly.",
                "examples": [f"adb shell am start -n <pkg>/{component_name}"],
                "taint_symbols": ["external_app"],
            }
        ]
        input_surface = {
            "channel": "mobile-app",
            "methods": ["INTENT"],
            "uris": [],
            "params": ["intent extras"],
            "derived_params": [],
            "examples": [f"adb shell am start -n <pkg>/{component_name} --es input <PAYLOAD>"],
        }
        flows.append(
            _flow_template(
                file_path=rel_path,
                source_line=source_line,
                sink_line=exported_line,
                source_code=source_code,
                sink_code=sink_code,
                sink_name=sink_name,
                description=description,
                explanation=explanation,
                function=component_name,
                input_surface=input_surface,
                attack_vectors=attack_vectors,
            )
        )

        source_file = _find_component_source(component_name, manifest_package, source_map)
        if not source_file:
            continue
        try:
            source_lines = source_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        input_hit = _input_read(source_lines, start=1)
        if not input_hit and tag == "receiver":
            input_hit = {
                "label": "broadcast intent",
                "line": _entry_line(source_lines, "receiver"),
                "code": "onReceive(context, intent)",
            }
        if tag == "service" and _first_match_line(source_lines, BINDER_STUB_RE, start=1) and not _guard_present(source_lines, start=1, end=min(len(source_lines), 120)):
            flows.append(_binder_service_flow(source_root, source_file, component_name))
        if not input_hit:
            continue
        sink_hit = _sink_hit(source_lines, SINK_PATTERNS, start=int(input_hit.get("line") or 1))
        helper_handoff = {}
        if not sink_hit:
            helper_handoff = _resolve_helper_chain(source_lines, int(input_hit.get("line") or 1), method_index, SINK_PATTERNS)
            sink_hit = helper_handoff.get("sink_hit", {})
        if not sink_hit:
            continue
        guard = _guard_present(source_lines, start=max(1, int(input_hit.get("line") or 1) - 8), end=min(len(source_lines), int(sink_hit.get("line") or len(source_lines)) + 8))
        example = f"adb shell am start -n <pkg>/{component_name} --es input <PAYLOAD>"
        if "data" in str(input_hit.get("label") or ""):
            example = f"adb shell am start -a android.intent.action.VIEW -n <pkg>/{component_name} -d 'custom://host/<PAYLOAD>'"
        flows.append(
            _source_backed_flow(
                source_root=source_root,
                file_path=source_file,
                component_name=component_name,
                component_kind=tag,
                sink_hit=sink_hit,
                input_hit=input_hit,
                guard_present=guard,
                surface_example=example,
                sink_summary=str(sink_hit.get("label") or "Sensitive sink"),
                helper_handoff=helper_handoff or None,
            )
        )
    return flows


def _provider_flows(manifest_path: Path, source_root: Path, root: ET.Element, lines: List[str], source_map: Dict[str, Path], manifest_package: str, method_index: Dict[str, List[Dict]]) -> List[Dict]:
    flows: List[Dict] = []
    rel_path = _rel_path(manifest_path, source_root)
    app = root.find("application")
    if app is None:
        return flows

    for component in app.findall("provider"):
        authorities = _android_attr(component, "authorities")
        component_name = _android_attr(component, "name") or authorities or "provider"
        if not _component_is_exported(component):
            continue
        if _permission_guard(component):
            continue

        source_line = _line_no(lines, component_name or authorities or "<provider")
        sink_line = _line_no(lines, component_name or authorities or "<provider", "authorities")
        sink_name = "content provider exposure"
        description = f"Exported content provider `{component_name}` exposes authority `{authorities or 'unknown'}` without read/write permissions."
        explanation = (
            "An external application can interact with this provider through ContentResolver APIs. "
            "No provider permission, readPermission, or writePermission guard is declared."
        )
        sink_code = f"<provider android:name=\"{component_name}\" android:authorities=\"{authorities}\">"
        source_code = f"[android entrypoint] External ContentResolver calls can reach provider `{component_name}`."
        attack_vectors = [
            {
                "kind": "mobile",
                "label": "ContentResolver query",
                "reason": "Other apps can query or mutate provider data when no provider permission is required.",
                "examples": [f"adb shell content query --uri content://{authorities}"],
                "taint_symbols": ["external_app"],
            }
        ]
        input_surface = {
            "channel": "mobile-app",
            "methods": ["CONTENT_PROVIDER"],
            "uris": [f"content://{authorities}"] if authorities else [],
            "params": ["selection", "projection", "uri path"],
            "derived_params": [],
            "examples": [f"adb shell content query --uri content://{authorities} --where \"_id=<PAYLOAD>\""] if authorities else [],
        }
        flows.append(
            _flow_template(
                file_path=rel_path,
                source_line=source_line,
                sink_line=sink_line,
                source_code=source_code,
                sink_code=sink_code,
                sink_name=sink_name,
                description=description,
                explanation=explanation,
                function=component_name,
                input_surface=input_surface,
                attack_vectors=attack_vectors,
            )
        )

        source_file = _find_component_source(component_name, manifest_package, source_map)
        if not source_file:
            continue
        try:
            source_lines = source_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        input_hit = _provider_input_read(source_lines, start=1)
        start_line = int(input_hit.get("line") or 1)
        sink_hit = _sink_hit(source_lines, PROVIDER_SINK_PATTERNS, start=start_line)
        helper_handoff = {}
        if not sink_hit:
            helper_handoff = _resolve_helper_chain(source_lines, start_line, method_index, PROVIDER_SINK_PATTERNS)
            sink_hit = helper_handoff.get("sink_hit", {})
        if not sink_hit:
            continue
        guard = _guard_present(source_lines, start=max(1, start_line - 10), end=min(len(source_lines), int(sink_hit.get("line") or len(source_lines)) + 10))
        flows.append(
            _provider_source_flow(
                source_root=source_root,
                file_path=source_file,
                component_name=component_name,
                sink_hit=sink_hit,
                authorities=authorities,
                guard_present=guard,
                input_hit=input_hit,
                helper_handoff=helper_handoff or None,
            )
        )
    return flows


def _deep_link_flows(manifest_path: Path, source_root: Path, root: ET.Element, lines: List[str], source_map: Dict[str, Path], manifest_package: str, method_index: Dict[str, List[Dict]]) -> List[Dict]:
    flows: List[Dict] = []
    rel_path = _rel_path(manifest_path, source_root)
    app = root.find("application")
    if app is None:
        return flows

    for component in app:
        tag = _component_kind(component.tag)
        if tag not in {"activity", "activity-alias"}:
            continue
        component_name = _android_attr(component, "name") or tag
        exported = _component_is_exported(component)
        for intent_filter in component.findall("intent-filter"):
            has_view = any(_android_attr(action, "name") == "android.intent.action.VIEW" for action in intent_filter.findall("action"))
            if not has_view:
                continue
            datas = intent_filter.findall("data")
            hosts = [_android_attr(item, "host") for item in datas if _android_attr(item, "host")]
            schemes = [_android_attr(item, "scheme") for item in datas if _android_attr(item, "scheme")]
            if not exported:
                continue
            if _bool_attr(intent_filter, "autoVerify", default=False):
                continue

            source_line = _line_no(lines, component_name, "android.intent.action.VIEW")
            sink_line = _line_no(lines, component_name, "android.intent.action.VIEW")
            sink_name = "deep link exposure"
            host_summary = ", ".join(hosts[:3]) or "any host"
            scheme_summary = ", ".join(schemes[:3]) or "custom/unrestricted scheme"
            uri_example = f"{(schemes[0] if schemes else 'https')}://{(hosts[0] if hosts else 'example.com')}/<PAYLOAD>"
            description = f"Deep-linkable activity `{component_name}` accepts VIEW intents for {scheme_summary} without app-link verification."
            explanation = (
                "An external app, browser, or malicious link can route a VIEW intent into this activity. "
                "The manifest exposes a deep-link entrypoint, but the intent-filter is not marked with autoVerify."
            )
            sink_code = f"<intent-filter><action android:name=\"android.intent.action.VIEW\"/></intent-filter>"
            source_code = f"[android deeplink] External VIEW intent can target `{component_name}` for host(s) {host_summary}."
            attack_vectors = [
                {
                    "kind": "mobile",
                    "label": "Malicious deep link",
                    "reason": "A browser or another app can invoke the handler with attacker-controlled URI data.",
                    "examples": [f"adb shell am start -a android.intent.action.VIEW -d '{uri_example}'"],
                    "taint_symbols": ["intent.data"],
                }
            ]
            input_surface = {
                "channel": "mobile-app",
                "methods": ["VIEW_INTENT"],
                "uris": [uri_example],
                "params": ["intent.data", "query params", "path segments"],
                "derived_params": [],
                "examples": [f"adb shell am start -a android.intent.action.VIEW -d '{uri_example}'"],
            }
            flows.append(
                _flow_template(
                    file_path=rel_path,
                    source_line=source_line,
                    sink_line=sink_line,
                    source_code=source_code,
                    sink_code=sink_code,
                    sink_name=sink_name,
                    description=description,
                    explanation=explanation,
                    function=component_name,
                    input_surface=input_surface,
                    attack_vectors=attack_vectors,
                )
            )

            source_file = _find_component_source(component_name, manifest_package, source_map)
            if not source_file:
                continue
            try:
                source_lines = source_file.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            input_hit = _input_read(source_lines, start=1)
            if not input_hit or "data" not in str(input_hit.get("label") or ""):
                continue
            sink_hit = _sink_hit(source_lines, SINK_PATTERNS, start=int(input_hit.get("line") or 1))
            helper_handoff = {}
            if not sink_hit:
                helper_handoff = _resolve_helper_chain(source_lines, int(input_hit.get("line") or 1), method_index, SINK_PATTERNS)
                sink_hit = helper_handoff.get("sink_hit", {})
            if not sink_hit:
                continue
            guard = _guard_present(source_lines, start=max(1, int(input_hit.get("line") or 1) - 8), end=min(len(source_lines), int(sink_hit.get("line") or len(source_lines)) + 8))
            flows.append(
                _source_backed_flow(
                    source_root=source_root,
                    file_path=source_file,
                    component_name=component_name,
                    component_kind=tag,
                    sink_hit=sink_hit,
                    input_hit=input_hit,
                    guard_present=guard,
                    surface_example=f"adb shell am start -a android.intent.action.VIEW -d '{uri_example}'",
                    sink_summary=str(sink_hit.get("label") or "Sensitive sink"),
                    helper_handoff=helper_handoff or None,
                )
            )
    return flows


def _cleartext_flows(manifest_path: Path, source_root: Path, root: ET.Element, lines: List[str]) -> List[Dict]:
    flows: List[Dict] = []
    rel_path = _rel_path(manifest_path, source_root)
    app = root.find("application")
    if app is None:
        return flows
    if not _bool_attr(app, "usesCleartextTraffic", default=False):
        return flows

    line = _line_no(lines, "usesCleartextTraffic")
    sink_name = "cleartext transport"
    description = "The application manifest enables cleartext traffic, allowing network attackers to tamper with or observe app traffic."
    explanation = (
        "The manifest sets usesCleartextTraffic=true. "
        "Any HTTP endpoint used by the app can be exposed to interception or manipulation on hostile networks."
    )
    sink_code = "<application android:usesCleartextTraffic=\"true\">"
    source_code = "[network attacker] Adversary can interfere with cleartext HTTP traffic used by the app."
    attack_vectors = [
        {
            "kind": "network",
            "label": "MITM over HTTP",
            "reason": "Traffic can be observed or modified when the app permits cleartext transport.",
            "examples": ["Intercept app HTTP traffic on an untrusted Wi-Fi network"],
            "taint_symbols": ["network"],
        }
    ]
    input_surface = {
        "channel": "network",
        "methods": ["HTTP"],
        "uris": ["http://<host>/<path>"],
        "params": ["request body", "headers", "responses"],
        "derived_params": [],
        "examples": ["Man-in-the-middle an HTTP request from the app"],
    }
    flows.append(
        _flow_template(
            file_path=rel_path,
            source_line=line,
            sink_line=line,
            source_code=source_code,
            sink_code=sink_code,
            sink_name=sink_name,
            description=description,
            explanation=explanation,
            function="application",
            input_surface=input_surface,
            attack_vectors=attack_vectors,
        )
    )
    return flows


def _parse_manifest(manifest_path: Path, source_root: Path) -> List[Dict]:
    try:
        raw = manifest_path.read_text(encoding="utf-8", errors="ignore")
        root = ET.fromstring(raw)
    except ET.ParseError:
        return []

    lines = raw.splitlines()
    manifest_package = _manifest_package(root)
    source_map = _source_index(source_root)
    source_cache = _source_cache(source_root)
    method_index = _method_index(source_cache)
    flows: List[Dict] = []
    flows.extend(_exported_component_flows(manifest_path, source_root, root, lines, source_map, manifest_package, method_index))
    flows.extend(_provider_flows(manifest_path, source_root, root, lines, source_map, manifest_package, method_index))
    flows.extend(_deep_link_flows(manifest_path, source_root, root, lines, source_map, manifest_package, method_index))
    flows.extend(_cleartext_flows(manifest_path, source_root, root, lines))
    return flows


def analyze_android_flows(source_root: Path, progress_callback=None):
    flows: List[Dict] = []
    flows.extend(annotate_flows(analyze_java_flows(source_root, progress_callback=progress_callback), platform="android", variant="java"))
    flows.extend(annotate_flows(analyze_kotlin_flows(source_root, progress_callback=progress_callback), platform="android", variant="kotlin"))

    for manifest_path in source_root.rglob("AndroidManifest.xml"):
        flows.extend(_parse_manifest(manifest_path, source_root))
    return flows


def run(source_root: Path, progress_callback=None):
    flows = analyze_android_flows(source_root, progress_callback=progress_callback)
    out_dir = output_dir(state.reports_dirpath, "android")
    return write_reports(flows, out_dir, title="Android Dataflow Analysis", platform="android")
