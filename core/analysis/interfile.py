# Standard libraries
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class FunctionDef:
    name: str
    file: Path
    line: int
    params: List[str]
    start: int
    end: int


@dataclass
class FunctionSummary:
    param_to_sink: Dict[int, List[Dict]] = field(default_factory=dict)
    param_to_return: Set[int] = field(default_factory=set)
    source_to_sink: List[Dict] = field(default_factory=list)
    source_to_return: bool = False


CALL_RE = re.compile(r"([A-Za-z_$][A-Za-z0-9_$]*(?:(?:->|::|\.)[A-Za-z_$][A-Za-z0-9_$]*)*)\s*\(")
RETURN_RE = re.compile(r"^\s*return\b")
JAVA_METHOD_SIG_RE = re.compile(
    r"^\s*(?:(?:public|private|protected|static|final|synchronized|native|abstract|strictfp)\s+)*"
    r"(?:<[^>]+>\s*)?"
    r"(?:[A-Za-z_][\w<>\[\]\.,\?]*\s+)"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*(?:throws[^{]+)?(?:\{|$)"
)
JAVA_CTOR_SIG_RE = re.compile(
    r"^\s*(?:(?:public|private|protected)\s+)+"
    r"(?:<[^>]+>\s*)?"
    r"([A-Z][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*(?:throws[^{]+)?(?:\{|$)"
)
JAVA_EXCLUDED_NAMES = {"if", "for", "while", "switch", "catch", "new"}


PLATFORM_SPECS = {
    "php": {
        "globs": ("*.php",),
        "function_def_re": re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)"),
        "mode": "brace",
    },
    "java": {
        "globs": ("*.java",),
        "function_def_re": re.compile(
            r"^\s*(?:(?:public|private|protected|static|final|synchronized|native|abstract|strictfp)\s+)+"
            r"(?:(?:[A-Za-z_][\w<>\[\], ?]*)\s+)?"
            r"(?!if\b|for\b|while\b|switch\b|catch\b|new\b)"
            r"([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*(?:throws[^{]+)?(?:\{|$)"
        ),
        "mode": "brace",
    },
    "dotnet": {
        "globs": ("*.cs",),
        "function_def_re": re.compile(
            r"\b(?:public|private|protected|internal|static|virtual|override|async|\s)+"
            r"[\w<>\[\], ?]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*\{"
        ),
        "mode": "brace",
    },
    "python": {
        "globs": ("*.py",),
        "function_def_re": re.compile(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*:"),
        "mode": "indent",
    },
    "javascript": {
        "globs": ("*.js", "*.jsx", "*.ts", "*.tsx"),
        "function_def_re": re.compile(r"(?:function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\))"),
        "mode": "brace",
    },
    "golang": {
        "globs": ("*.go",),
        "function_def_re": re.compile(
            r"^\s*func\s+(?:\([^)]*\)\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)"
        ),
        "mode": "brace",
    },
}


def _sanitize_param_name(raw: str) -> Optional[str]:
    token = raw.strip()
    if not token:
        return None
    token = token.split("=")[0].strip()
    token = token.split(":")[0].strip()
    token = token.split()[-1] if " " in token else token
    token = token.lstrip("$@*")
    token = token.replace("[]", "")
    return token or None


def _extract_go_params(raw_params: str) -> List[str]:
    params: List[str] = []
    for part in raw_params.split(","):
        token = part.strip()
        if not token:
            continue
        if " " in token:
            names = token.split(" ", 1)[0]
        else:
            names = token
        for n in names.split(","):
            cleaned = n.strip().lstrip("*")
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", cleaned):
                params.append(cleaned)
    return params


def _extract_params(raw_params: str) -> List[str]:
    params = []
    for part in raw_params.split(","):
        cleaned = _sanitize_param_name(part)
        if cleaned:
            params.append(cleaned)
    return params


def _find_python_block_end(lines: List[str], start_idx: int) -> int:
    start_indent = len(lines[start_idx]) - len(lines[start_idx].lstrip(" "))
    end = len(lines)
    for i in range(start_idx + 1, len(lines)):
        line = lines[i]
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= start_indent and not line.lstrip().startswith("#"):
            end = i
            break
    return end


def _find_brace_block_end(lines: List[str], start_idx: int) -> int:
    depth = 0
    started = False
    for i in range(start_idx, len(lines)):
        line = lines[i]
        opens = line.count("{")
        closes = line.count("}")
        if opens > 0:
            started = True
        depth += opens
        depth -= closes
        if started and depth <= 0:
            return i + 1
    return -1


def _parse_functions(file_path: Path, lines: List[str], platform: str) -> List[FunctionDef]:
    if platform == "java":
        return _parse_java_functions(file_path, lines)

    spec = PLATFORM_SPECS[platform]
    fn_re = spec["function_def_re"]
    mode = spec["mode"]
    functions: List[FunctionDef] = []

    for idx, line in enumerate(lines):
        match = fn_re.search(line)
        if not match:
            continue
        if platform == "javascript" and (match.group(1) is None or match.group(2) is None):
            continue
        name = match.group(1)
        if platform == "golang":
            params = _extract_go_params(match.group(2))
        else:
            params = _extract_params(match.group(2))
        if mode == "indent":
            end = _find_python_block_end(lines, idx)
        else:
            end = _find_brace_block_end(lines, idx)
            if end < 0:
                # Declaration without an implementation block (e.g., interface/abstract method).
                continue
        functions.append(
            FunctionDef(
                name=name,
                file=file_path,
                line=idx + 1,
                params=params,
                start=idx,
                end=end,
            )
        )
    return functions


def _parse_java_functions(file_path: Path, lines: List[str]) -> List[FunctionDef]:
    functions: List[FunctionDef] = []
    max_sig_lines = 12

    for idx in range(len(lines)):
        raw = lines[idx].strip()
        if not raw or raw.startswith("@"):
            continue
        low = raw.lower()
        if low.startswith(("if ", "for ", "while ", "switch ", "catch ", "return ", "throw ", "new ")):
            continue
        if "(" not in raw:
            continue
        if raw.endswith(";"):
            continue
        if "=" in raw and raw.index("=") < raw.index("("):
            continue

        sig_parts = [raw]
        end_idx = idx
        while ")" not in " ".join(sig_parts) and end_idx + 1 < len(lines) and (end_idx - idx) < max_sig_lines:
            end_idx += 1
            sig_parts.append(lines[end_idx].strip())

        signature = " ".join(sig_parts)
        m = JAVA_METHOD_SIG_RE.search(signature) or JAVA_CTOR_SIG_RE.search(signature)
        if not m:
            continue
        name = m.group(1)
        if name in JAVA_EXCLUDED_NAMES:
            continue
        params = _extract_params(m.group(2))
        end = _find_brace_block_end(lines, idx)
        if end < 0:
            continue
        functions.append(
            FunctionDef(
                name=name,
                file=file_path,
                line=idx + 1,
                params=params,
                start=idx,
                end=end,
            )
        )
    return functions


def _extract_calls(line: str) -> List[Tuple[str, List[str], str]]:
    calls = []
    for match in CALL_RE.finditer(line):
        raw_name = match.group(1)
        name = re.split(r"(?:->|::|\.)", raw_name)[-1].lstrip("$")
        if name in {"if", "for", "while", "switch", "catch", "return", "new", "def", "class"}:
            continue

        open_idx = line.find("(", match.start())
        if open_idx < 0:
            continue
        idx = open_idx + 1
        depth = 1
        arg_start = idx
        args_raw = []
        while idx < len(line):
            ch = line[idx]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    args_raw.append(line[arg_start:idx])
                    break
            elif ch == "," and depth == 1:
                args_raw.append(line[arg_start:idx])
                arg_start = idx + 1
            idx += 1

        args = [a.strip() for a in args_raw if a.strip()]
        calls.append((name, args, raw_name))
    return calls


def _is_function_definition_line(line: str, platform: str) -> bool:
    fn_re = PLATFORM_SPECS[platform]["function_def_re"]
    return fn_re.search(line) is not None


def _extract_assignment(line: str, platform: str) -> Optional[Tuple[str, str]]:
    stripped = line.strip().rstrip(";")
    if not stripped or stripped.startswith("#") or stripped.startswith("//"):
        return None

    if platform == "python":
        m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)", stripped)
    elif platform == "php":
        m = re.match(r"\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)", stripped)
    elif platform == "javascript":
        m = re.match(r"(?:const|let|var)?\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(.+)", stripped)
    elif platform == "golang":
        m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?::=|=)\s*(.+)", stripped)
    elif platform == "java":
        m = re.match(
            r"(?:(?:final|volatile|transient|var)\s+)*"
            r"(?:[A-Za-z_][\w<>\[\]\.,\?]*\s+)?"
            r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)",
            stripped,
        )
    elif platform == "dotnet":
        m = re.match(
            r"(?:(?:public|private|protected|internal|static|readonly|const|var|async)\s+)*"
            r"(?:[A-Za-z_][\w<>\[\]\.,\?]*\s+)?"
            r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)",
            stripped,
        )
    else:
        m = re.match(r"(?:[\w<>\[\]\.,\?]+\s+)?([A-Za-z_@][A-Za-z0-9_@]*)\s*=\s*(.+)", stripped)

    if not m:
        return None
    lhs = m.group(1).lstrip("$@")
    rhs = m.group(2).strip()
    return lhs, rhs


def _line_has_var(line: str, var: str, platform: str) -> bool:
    if platform == "php":
        return re.search(rf"\${re.escape(var)}\b", line) is not None
    return re.search(rf"\b{re.escape(var)}\b", line) is not None


def _line_source(lines: List[str], idx: int) -> str:
    if 0 <= idx < len(lines):
        return lines[idx].strip()
    return ""


def _scan_scope_for_summary(
    fn: FunctionDef,
    lines: List[str],
    cfg: Dict,
    platform: str,
    summary_by_name: Dict[str, FunctionSummary],
) -> FunctionSummary:
    summary = FunctionSummary()
    tainted: Dict[str, Set[int]] = {p: {i} for i, p in enumerate(fn.params)}
    source_tainted: Set[str] = set()

    for idx in range(fn.start, min(fn.end, len(lines))):
        line = lines[idx]
        stripped = line.strip()
        if not stripped:
            continue
        if _is_function_definition_line(stripped, platform):
            continue

        assign = _extract_assignment(stripped, platform)
        if assign:
            lhs, rhs = assign
            if any(r.search(rhs) for r in cfg.get("sources", [])):
                source_tainted.add(lhs)
            else:
                inherited: Set[int] = set()
                inherited_source = False
                for var, origins in tainted.items():
                    if _line_has_var(rhs, var, platform):
                        inherited.update(origins)
                for svar in source_tainted:
                    if _line_has_var(rhs, svar, platform):
                        inherited_source = True
                        break

                for call_name, call_args, _ in _extract_calls(rhs):
                    callee = summary_by_name.get(call_name)
                    if not callee:
                        continue
                    for arg_idx, arg_expr in enumerate(call_args):
                        for var, origins in tainted.items():
                            if _line_has_var(arg_expr, var, platform):
                                if arg_idx in callee.param_to_return:
                                    inherited.update(origins)
                                if callee.param_to_sink.get(arg_idx):
                                    for sink_item in callee.param_to_sink[arg_idx]:
                                        for origin_idx in origins:
                                            summary.param_to_sink.setdefault(origin_idx, []).append(sink_item)
                        for svar in source_tainted:
                            if _line_has_var(arg_expr, svar, platform):
                                if callee.source_to_return:
                                    inherited_source = True
                                if arg_idx in callee.param_to_return:
                                    inherited_source = True
                                if callee.source_to_sink:
                                    for sink_item in callee.source_to_sink:
                                        summary.source_to_sink.append(sink_item)
                                if callee.param_to_sink.get(arg_idx):
                                    for sink_item in callee.param_to_sink[arg_idx]:
                                        summary.source_to_sink.append(sink_item)

                if inherited:
                    tainted[lhs] = inherited
                if inherited_source:
                    source_tainted.add(lhs)

        for san_re in cfg.get("sanitizers", []):
            if san_re.search(stripped):
                for var in list(tainted.keys()):
                    if _line_has_var(stripped, var, platform):
                        tainted.pop(var, None)
                for var in list(source_tainted):
                    if _line_has_var(stripped, var, platform):
                        source_tainted.discard(var)

        for sink_name, (sink_re, sink_desc) in cfg.get("sinks", {}).items():
            if not sink_re.search(stripped):
                continue
            sink_obj = {
                "sink": sink_name,
                "description": sink_desc,
                "file": str(fn.file),
                "line": idx + 1,
                "code": _line_source(lines, idx),
                "function": fn.name,
            }
            for var, origins in tainted.items():
                if _line_has_var(stripped, var, platform):
                    for origin_idx in origins:
                        summary.param_to_sink.setdefault(origin_idx, []).append(sink_obj)
            for var in source_tainted:
                if _line_has_var(stripped, var, platform):
                    summary.source_to_sink.append(sink_obj)

        if RETURN_RE.search(stripped):
            for var, origins in tainted.items():
                if _line_has_var(stripped, var, platform):
                    summary.param_to_return.update(origins)
            for var in source_tainted:
                if _line_has_var(stripped, var, platform):
                    summary.source_to_return = True

    return summary


def _summaries_equal(a: FunctionSummary, b: FunctionSummary) -> bool:
    return (
        set(a.param_to_return) == set(b.param_to_return)
        and a.source_to_return == b.source_to_return
        and _canon_sink_map(a.param_to_sink) == _canon_sink_map(b.param_to_sink)
        and _canon_sinks(a.source_to_sink) == _canon_sinks(b.source_to_sink)
    )


def _canon_sinks(items: List[Dict]) -> Set[Tuple]:
    out = set()
    for item in items:
        out.add((item.get("sink"), item.get("description"), item.get("file"), item.get("line"), item.get("function")))
    return out


def _canon_sink_map(items: Dict[int, List[Dict]]) -> Dict[int, Set[Tuple]]:
    return {idx: _canon_sinks(sinks) for idx, sinks in items.items()}


def _build_xref(path_steps: List[Dict], call_index: Dict[str, List[Dict]], def_index: Dict[str, List[FunctionDef]]) -> List[Dict]:
    xrefs: List[Dict] = []
    seen = set()
    max_xref_entries = 120
    for step in path_steps:
        code = step.get("code", "")
        for call_name, _, full_symbol in _extract_calls(code):
            for defn in def_index.get(call_name, []):
                key = ("def", call_name, str(defn.file), defn.line)
                if key in seen:
                    continue
                seen.add(key)
                xrefs.append(
                    {
                        "type": "definition",
                        "symbol": full_symbol,
                        "resolved_name": call_name,
                        "file": str(defn.file),
                        "line": defn.line,
                        "context": f"Definition of {call_name}",
                    }
                )
                if len(xrefs) >= max_xref_entries:
                    return xrefs
            for caller in call_index.get(call_name, []):
                key = ("call", call_name, caller["file"], caller["line"], caller.get("symbol", call_name))
                if key in seen:
                    continue
                seen.add(key)
                xrefs.append(
                    {
                        "type": "callsite",
                        "symbol": caller.get("symbol", call_name),
                        "resolved_name": call_name,
                        "file": caller["file"],
                        "line": caller["line"],
                        "context": "Related callsite",
                    }
                )
                if len(xrefs) >= max_xref_entries:
                    return xrefs
    return xrefs


def analyze_multifile_flows(source_root: Path, cfg: Dict, platform: str) -> List[Dict]:
    spec = PLATFORM_SPECS[platform]
    globs = spec["globs"]

    files: List[Path] = []
    for pat in globs:
        files.extend(source_root.rglob(pat))

    file_lines: Dict[Path, List[str]] = {}
    functions: List[FunctionDef] = []
    def_index: Dict[str, List[FunctionDef]] = {}
    call_index: Dict[str, List[Dict]] = {}

    for file_path in files:
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        file_lines[file_path] = lines

        fns = _parse_functions(file_path, lines, platform)
        if not fns:
            # Fallback scope to avoid fully blank analysis when parser misses function forms.
            fns = [
                FunctionDef(
                    name="__file_scope__",
                    file=file_path,
                    line=1,
                    params=[],
                    start=0,
                    end=len(lines),
                )
            ]
        functions.extend(fns)
        for fn in fns:
            def_index.setdefault(fn.name, []).append(fn)

        for line_no, line in enumerate(lines, start=1):
            if _is_function_definition_line(line.strip(), platform):
                continue
            for call_name, _, full_symbol in _extract_calls(line):
                call_index.setdefault(call_name, []).append(
                    {"file": str(file_path), "line": line_no, "code": line.strip(), "symbol": full_symbol}
                )

    summary_by_name: Dict[str, FunctionSummary] = {}
    for fn in functions:
        summary_by_name.setdefault(fn.name, FunctionSummary())

    for _ in range(5):
        changed = False
        local_summaries: Dict[Tuple[str, str, int], FunctionSummary] = {}
        for fn in functions:
            lines = file_lines.get(fn.file, [])
            local_summaries[(str(fn.file), fn.name, fn.line)] = _scan_scope_for_summary(
                fn, lines, cfg, platform, summary_by_name
            )

        merged: Dict[str, FunctionSummary] = {}
        for fn in functions:
            key = (str(fn.file), fn.name, fn.line)
            cur = local_summaries[key]
            agg = merged.setdefault(fn.name, FunctionSummary())
            agg.param_to_return.update(cur.param_to_return)
            agg.source_to_return = agg.source_to_return or cur.source_to_return
            for idx, sinks in cur.param_to_sink.items():
                agg.param_to_sink.setdefault(idx, []).extend(sinks)
            agg.source_to_sink.extend(cur.source_to_sink)

        for name, new_summary in merged.items():
            old = summary_by_name.get(name, FunctionSummary())
            if not _summaries_equal(old, new_summary):
                summary_by_name[name] = new_summary
                changed = True
        if not changed:
            break

    flows: List[Dict] = []

    for fn in functions:
        lines = file_lines.get(fn.file, [])
        tainted_paths: Dict[str, List[Dict]] = {p: [{"file": str(fn.file), "line": fn.line, "role": "param", "code": p}] for p in fn.params}
        source_tainted_paths: Dict[str, List[Dict]] = {}

        for idx in range(fn.start, min(fn.end, len(lines))):
            line = lines[idx]
            stripped = line.strip()
            if not stripped:
                continue
            if _is_function_definition_line(stripped, platform):
                continue

            assign = _extract_assignment(stripped, platform)
            assign_lhs = assign[0] if assign else None
            assign_rhs = assign[1] if assign else stripped

            if assign:
                lhs, rhs = assign
                if any(r.search(rhs) for r in cfg.get("sources", [])):
                    source_tainted_paths[lhs] = [{"file": str(fn.file), "line": idx + 1, "role": "source", "code": stripped}]
                else:
                    for var, path_steps in tainted_paths.items():
                        if _line_has_var(rhs, var, platform):
                            tainted_paths[lhs] = path_steps + [{"file": str(fn.file), "line": idx + 1, "role": "assign", "code": stripped}]
                            break
                    for var, path_steps in source_tainted_paths.items():
                        if _line_has_var(rhs, var, platform):
                            source_tainted_paths[lhs] = path_steps + [{"file": str(fn.file), "line": idx + 1, "role": "assign", "code": stripped}]
                            break

            for san_re in cfg.get("sanitizers", []):
                if san_re.search(stripped):
                    for var in list(tainted_paths.keys()):
                        if _line_has_var(stripped, var, platform):
                            tainted_paths.pop(var, None)
                    for var in list(source_tainted_paths.keys()):
                        if _line_has_var(stripped, var, platform):
                            source_tainted_paths.pop(var, None)

            calls = _extract_calls(assign_rhs)
            for call_name, call_args, _ in calls:
                callee = summary_by_name.get(call_name)
                if not callee:
                    continue
                for arg_idx, arg_expr in enumerate(call_args):
                    arg_is_source = any(r.search(arg_expr) for r in cfg.get("sources", []))
                    source_arg_step = {"file": str(fn.file), "line": idx + 1, "role": "source", "code": stripped}
                    for var, steps in tainted_paths.items():
                        if not _line_has_var(arg_expr, var, platform):
                            continue
                        call_step = {"file": str(fn.file), "line": idx + 1, "role": "call", "code": stripped}
                        if arg_idx in callee.param_to_return and assign_lhs:
                            tainted_paths[assign_lhs] = steps + [call_step]
                        for sink_item in callee.param_to_sink.get(arg_idx, []):
                            path_steps = steps + [call_step, {
                                "file": sink_item.get("file"),
                                "line": sink_item.get("line"),
                                "role": "sink",
                                "code": sink_item.get("code", ""),
                            }]
                            xref = _build_xref(path_steps, call_index, def_index)
                            flows.append(
                                {
                                    "file": str(fn.file),
                                    "function": fn.name,
                                    "line": idx + 1,
                                    "sink": sink_item.get("sink", call_name),
                                    "description": (
                                        f"Tainted parameter `{var}` flows through `{call_name}` "
                                        f"into sink `{sink_item.get('sink', call_name)}`."
                                    ),
                                    "explanation": (
                                        "The value originates from user-controllable data and is propagated "
                                        "across function boundaries until it reaches a sensitive sink."
                                    ),
                                    "path": path_steps,
                                    "xref": xref,
                                }
                            )
                    for var, steps in source_tainted_paths.items():
                        if not _line_has_var(arg_expr, var, platform):
                            continue
                        call_step = {"file": str(fn.file), "line": idx + 1, "role": "call", "code": stripped}
                        if callee.source_to_return and assign_lhs:
                            source_tainted_paths[assign_lhs] = steps + [call_step]
                        if arg_idx in callee.param_to_return and assign_lhs:
                            source_tainted_paths[assign_lhs] = steps + [call_step]
                        for sink_item in callee.param_to_sink.get(arg_idx, []):
                            path_steps = steps + [call_step, {
                                "file": sink_item.get("file"),
                                "line": sink_item.get("line"),
                                "role": "sink",
                                "code": sink_item.get("code", ""),
                            }]
                            xref = _build_xref(path_steps, call_index, def_index)
                            flows.append(
                                {
                                    "file": str(fn.file),
                                    "function": fn.name,
                                    "line": idx + 1,
                                    "sink": sink_item.get("sink", call_name),
                                    "description": (
                                        f"Source-tainted argument `{var}` flows through `{call_name}` "
                                        f"into sink `{sink_item.get('sink', call_name)}`."
                                    ),
                                    "explanation": (
                                        "The value comes from a source in the caller and then crosses into "
                                        "another function/file where it reaches a sink."
                                    ),
                                    "path": path_steps,
                                    "xref": xref,
                                }
                            )
                        for sink_item in callee.source_to_sink:
                            path_steps = steps + [call_step, {
                                "file": sink_item.get("file"),
                                "line": sink_item.get("line"),
                                "role": "sink",
                                "code": sink_item.get("code", ""),
                            }]
                            xref = _build_xref(path_steps, call_index, def_index)
                            flows.append(
                                {
                                    "file": str(fn.file),
                                    "function": fn.name,
                                    "line": idx + 1,
                                    "sink": sink_item.get("sink", call_name),
                                    "description": (
                                        f"Tainted source data flows through `{call_name}` "
                                        f"into sink `{sink_item.get('sink', call_name)}`."
                                    ),
                                    "explanation": (
                                        "The source is not effectively neutralized before entering a sink "
                                        "in another function/file."
                                    ),
                                    "path": path_steps,
                                    "xref": xref,
                                }
                            )
                    if arg_is_source:
                        call_step = {"file": str(fn.file), "line": idx + 1, "role": "call", "code": stripped}
                        if callee.source_to_return and assign_lhs:
                            source_tainted_paths[assign_lhs] = [source_arg_step, call_step]
                        for sink_item in callee.source_to_sink:
                            path_steps = [source_arg_step, call_step, {
                                "file": sink_item.get("file"),
                                "line": sink_item.get("line"),
                                "role": "sink",
                                "code": sink_item.get("code", ""),
                            }]
                            xref = _build_xref(path_steps, call_index, def_index)
                            flows.append(
                                {
                                    "file": str(fn.file),
                                    "function": fn.name,
                                    "line": idx + 1,
                                    "sink": sink_item.get("sink", call_name),
                                    "description": (
                                        f"Direct source expression in argument flows through `{call_name}` "
                                        f"into sink `{sink_item.get('sink', call_name)}`."
                                    ),
                                    "explanation": (
                                        "Source data is passed directly as a call argument and reaches a sink "
                                        "across function boundaries."
                                    ),
                                    "path": path_steps,
                                    "xref": xref,
                                }
                            )

            for sink_name, (sink_re, sink_desc) in cfg.get("sinks", {}).items():
                if not sink_re.search(stripped):
                    continue
                line_has_source = any(r.search(stripped) for r in cfg.get("sources", []))
                for var, path_steps in tainted_paths.items():
                    if _line_has_var(stripped, var, platform):
                        full_path = path_steps + [{"file": str(fn.file), "line": idx + 1, "role": "sink", "code": stripped}]
                        xref = _build_xref(full_path, call_index, def_index)
                        flows.append(
                            {
                                "file": str(fn.file),
                                "function": fn.name,
                                "line": idx + 1,
                                "sink": sink_name,
                                "description": f"Tainted data reaches sink `{sink_name}`: {sink_desc}",
                                "explanation": "A tainted variable is used directly in a sensitive sink without sufficient sanitization.",
                                "path": full_path,
                                "xref": xref,
                            }
                        )
                for var, path_steps in source_tainted_paths.items():
                    if _line_has_var(stripped, var, platform):
                        full_path = path_steps + [{"file": str(fn.file), "line": idx + 1, "role": "sink", "code": stripped}]
                        xref = _build_xref(full_path, call_index, def_index)
                        flows.append(
                            {
                                "file": str(fn.file),
                                "function": fn.name,
                                "line": idx + 1,
                                "sink": sink_name,
                                "description": f"Source data reaches sink `{sink_name}`: {sink_desc}",
                                "explanation": "Data from a source is propagated into a sink path in this code scope.",
                                "path": full_path,
                                "xref": xref,
                            }
                        )
                if line_has_source:
                    full_path = [
                        {"file": str(fn.file), "line": idx + 1, "role": "source", "code": stripped},
                        {"file": str(fn.file), "line": idx + 1, "role": "sink", "code": stripped},
                    ]
                    xref = _build_xref(full_path, call_index, def_index)
                    flows.append(
                        {
                            "file": str(fn.file),
                            "function": fn.name,
                            "line": idx + 1,
                            "sink": sink_name,
                            "description": f"Source data is used directly in sink `{sink_name}`: {sink_desc}",
                            "explanation": "A source API appears in the same sink expression without an intermediate neutralization step.",
                            "path": full_path,
                            "xref": xref,
                        }
                    )

    return flows
