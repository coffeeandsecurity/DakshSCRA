from __future__ import annotations

# Standard libraries
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from core.analysis.common import load_analysis_config


@dataclass
class FunctionDef:
    name: str
    file: Path
    line: int
    params: List[str]
    start: int
    end: int
    signature: str = ""
    aliases: List[str] = field(default_factory=list)
    meta: Dict = field(default_factory=dict)


@dataclass
class FunctionSummary:
    param_to_sink: Dict[int, List[Dict]] = field(default_factory=dict)
    param_to_return: Set[int] = field(default_factory=set)
    source_to_sink: List[Dict] = field(default_factory=list)
    source_to_return: bool = False
    param_to_session: Dict[int, Set[str]] = field(default_factory=dict)
    source_to_session: Set[str] = field(default_factory=set)
    session_to_sink: Dict[str, List[Dict]] = field(default_factory=dict)
    session_to_return: Set[str] = field(default_factory=set)


CALL_RE = re.compile(r"([A-Za-z_$][A-Za-z0-9_$]*(?:(?:->|::|\.)[A-Za-z_$][A-Za-z0-9_$]*)*)\s*\(")
RETURN_RE = re.compile(r"^\s*return\b")
PYTHON_ASYNC_DEF_RE = re.compile(r"^\s*async\s+def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*:")
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
JS_ASSIGN_FUNCTION_RE = re.compile(
    r"^\s*(?:export\s+)?(?:const|let|var)?\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*function\b(?:\s+[A-Za-z_$][A-Za-z0-9_$]*)?\s*\(([^)]*)\)"
)
JS_ARROW_FUNCTION_RE = re.compile(
    r"^\s*(?:export\s+)?(?:const|let|var)?\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s*)?(?:\(([^)]*)\)|([A-Za-z_$][A-Za-z0-9_$]*))\s*=>"
)
JS_METHOD_SIG_RE = re.compile(
    r"^\s*(?:(?:async|static|get|set)\s+)*([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)\s*\{"
)
JS_OBJECT_FUNCTION_RE = re.compile(
    r"^\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*(?:async\s*)?function\b(?:\s+[A-Za-z_$][A-Za-z0-9_$]*)?\s*\(([^)]*)\)"
)
JS_OBJECT_ARROW_RE = re.compile(
    r"^\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*(?:async\s*)?(?:\(([^)]*)\)|([A-Za-z_$][A-Za-z0-9_$]*))\s*=>"
)
JS_OBJECT_METHOD_RE = re.compile(
    r"^\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\(([^)]*)\)\s*\{"
)
JS_EXCLUDED_METHODS = {"if", "for", "while", "switch", "catch", "constructor"}
JS_ROUTE_CALL_RE = re.compile(r"\.(get|post|put|patch|delete|use|all)\s*\(")
JS_INLINE_ARROW_CB_RE = re.compile(r"(?:async\s*)?\(([^)]*)\)\s*=>|(?:async\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=>")
JS_INLINE_FUNCTION_CB_RE = re.compile(r"function\s*(?:[A-Za-z_$][A-Za-z0-9_$]*)?\s*\(([^)]*)\)")
JAVA_SPRING_PARAM_ANN_RE = re.compile(r"@(RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|ModelAttribute)\b", re.IGNORECASE)
DOTNET_BINDING_ATTR_RE = re.compile(r"\[(FromBody|FromQuery|FromRoute|FromHeader|FromForm)\b[^\]]*\]", re.IGNORECASE)
NEST_BINDING_DECORATOR_RE = re.compile(r"@(Body|Param|Query|Headers|Req|Request|Session|Cookies)\b", re.IGNORECASE)
PHP_REQUEST_PARAM_HINT_RE = re.compile(r"\b(Request|ServerRequestInterface|FormRequest)\s+\$([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE)
PHP_SUPERGLOBAL_KEY_RE = re.compile(r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV)\s*\[\s*['\"]([^'\"]+)['\"]\s*\]", re.IGNORECASE)
PHP_DYNAMIC_SUPERGLOBAL_KEY_RE = re.compile(r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV)\s*\[\s*\$([A-Za-z_][A-Za-z0-9_]*)\s*\]", re.IGNORECASE)
PHP_INPUT_CALL_RE = re.compile(r"\$this\s*->\s*input\s*->\s*(get|post|cookie|get_post|post_get)\s*\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
PHP_REQUEST_CALL_RE = re.compile(r"(?:request\s*\(\s*\)|Request)\s*(?:::\s*|->\s*)(input|get|post|query|cookie|header|route)\s*\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
PHP_REQUEST_OBJECT_CALL_RE = re.compile(r"\$request\s*->\s*(get|query|request|cookies|headers|server|files)\s*(?:->\s*get\s*\(\s*['\"]([^'\"]+)['\"]|\[\s*['\"]([^'\"]+)['\"]\s*\])", re.IGNORECASE)
PHP_FOREACH_SUPERGLOBAL_RE = re.compile(r"foreach\s*\(\s*\$_(POST|GET|REQUEST|COOKIE|FILES|SESSION)\s*(?:\[\s*['\"]([^'\"]+)['\"]\s*\])?\s+as\s+\$([A-Za-z_][A-Za-z0-9_]*)(?:\s*=>\s*\$([A-Za-z_][A-Za-z0-9_]*))?\s*\)", re.IGNORECASE)
PHP_SESSION_WRITE_RE = re.compile(r"\$_SESSION\s*\[\s*['\"]([^'\"]+)['\"]\s*\](?:\s*\[\s*(\$?[A-Za-z_][A-Za-z0-9_]*|['\"][^'\"]+['\"])\s*\])?\s*=\s*(.+)", re.IGNORECASE)
PHP_SESSION_READ_RE = re.compile(r"\$_SESSION\s*\[\s*['\"]([^'\"]+)['\"]\s*\]", re.IGNORECASE)
PHP_FORM_OPEN_RE = re.compile(r"<form\b([^>]*)>", re.IGNORECASE)
PHP_FORM_CLOSE_RE = re.compile(r"</form>", re.IGNORECASE)
PHP_FORM_ATTR_RE = re.compile(r"\b(action|method|enctype)\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
PHP_FORM_FIELD_RE = re.compile(r"<(input|textarea|select)\b([^>]*)>", re.IGNORECASE)
PHP_FIELD_NAME_RE = re.compile(r"\bname\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
PHP_FIELD_TYPE_RE = re.compile(r"\btype\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
JAVA_HTTP_REQUEST_HINT_RE = re.compile(r"\b(HttpServletRequest|ServletRequest)\s+([A-Za-z_][A-Za-z0-9_]*)")
DOTNET_HTTP_REQUEST_HINT_RE = re.compile(r"\bHttpRequest\s+([A-Za-z_][A-Za-z0-9_]*)")
GENERIC_CLASS_RE = re.compile(r"\bclass\s+([A-Z][A-Za-z0-9_]*)\b")
JAVA_INTERFACE_RE = re.compile(r"\binterface\s+([A-Z][A-Za-z0-9_]*)\b")
JS_OBJECT_START_RE = re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*\{\s*$")
JS_EXPORT_OBJ_RE = re.compile(r"^\s*export\s+default\s+\{\s*$")
SERVICE_NAME_SUFFIX_RE = re.compile(r"(service|repository|repo|controller|handler|manager|provider)$", re.IGNORECASE)
BUILTIN_SINK_CALLS = {
    "move_uploaded_file": "File upload move operation",
}


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


def _pascal_case(value: str) -> str:
    parts = re.split(r"[_\-\s]+", str(value or ""))
    compact = "".join(part[:1].upper() + part[1:] for part in parts if part)
    return compact or str(value or "")


def _framework_owner_aliases(owner: str) -> List[str]:
    token = str(owner or "").strip().lstrip("$")
    if not token:
        return []
    raw_parts = [part for part in re.split(r"(?:->|::|\.)", token) if part]
    if not raw_parts:
        return []
    owner_leaf = raw_parts[-1]
    aliases: List[str] = []
    for candidate in (owner_leaf, owner_leaf.lstrip("_")):
        if not candidate:
            continue
        aliases.append(candidate)
        if SERVICE_NAME_SUFFIX_RE.search(candidate):
            aliases.append(_pascal_case(candidate))
        trimmed = SERVICE_NAME_SUFFIX_RE.sub("", candidate)
        if trimmed and trimmed != candidate:
            aliases.append(_pascal_case(trimmed))
            aliases.append(_pascal_case(trimmed) + "Service")
            aliases.append(_pascal_case(trimmed) + "Repository")
    seen: Set[str] = set()
    ordered: List[str] = []
    for alias in aliases:
        if alias and alias not in seen:
            seen.add(alias)
            ordered.append(alias)
    return ordered


def _infer_enclosing_container(lines: List[str], start_idx: int, platform: str) -> List[str]:
    containers: List[str] = []
    for idx in range(start_idx, max(-1, start_idx - 32), -1):
        line = lines[idx].strip()
        if not line:
            continue
        class_match = GENERIC_CLASS_RE.search(line) or JAVA_INTERFACE_RE.search(line)
        if class_match:
            containers.append(class_match.group(1))
            break
        if platform == "javascript":
            obj_match = JS_OBJECT_START_RE.search(line)
            if obj_match:
                containers.append(obj_match.group(1))
                break
            if JS_EXPORT_OBJ_RE.search(line):
                containers.append("defaultExport")
                break
    return containers


def _function_aliases(name: str, file_path: Path, lines: List[str], start_idx: int, platform: str) -> List[str]:
    aliases: List[str] = []
    seen: Set[str] = set()

    def add(value: str) -> None:
        token = str(value or "").strip().lstrip("$")
        if token and token not in seen:
            seen.add(token)
            aliases.append(token)

    add(name)
    add(file_path.stem)
    for container in _infer_enclosing_container(lines, start_idx, platform):
        add(f"{container}.{name}")
        add(f"{container}::{name}")
        for owner_alias in _framework_owner_aliases(container):
            add(f"{owner_alias}.{name}")
    if platform == "javascript":
        add(f"exports.{name}")
        add(f"module.exports.{name}")
    return aliases


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


def _find_end_keyword_block_end(lines: List[str], start_idx: int) -> int:
    """Find the end of a Ruby-style `def...end` block by counting nested def/do/begin/end."""
    depth = 0
    _OPEN_RE = re.compile(r"^\s*(?:def|do|begin|class|module|if|unless|while|until|for|case)\b")
    _CLOSE_RE = re.compile(r"^\s*end\b")
    for i in range(start_idx, len(lines)):
        s = lines[i].strip()
        if _OPEN_RE.match(s):
            depth += 1
        if _CLOSE_RE.match(s) and i > start_idx:
            depth -= 1
            if depth <= 0:
                return i + 1
    return len(lines)


def _get_platform_spec(platform: str, cfg: Dict) -> Dict:
    """Return the platform spec dict, merging PLATFORM_SPECS (hard-coded) with
    config.yaml ``analyzer`` blocks for dynamically defined platforms."""
    if platform in PLATFORM_SPECS:
        return PLATFORM_SPECS[platform]
    analyzer_block = cfg.get("_analyzer_block", {})
    if not analyzer_block:
        raise KeyError(f"Unknown platform '{platform}' and no analyzer block found in config.")
    raw_globs = analyzer_block.get("globs", [])
    globs = tuple(raw_globs) if isinstance(raw_globs, list) else (raw_globs,)
    mode = analyzer_block.get("mode", "brace")
    fn_re_pat = analyzer_block.get("function_def_re", "")
    try:
        fn_re = re.compile(fn_re_pat, re.MULTILINE) if fn_re_pat else re.compile(r"(?!)")
    except re.error:
        fn_re = re.compile(r"(?!)")
    return {
        "globs": globs,
        "function_def_re": fn_re,
        "mode": mode,
    }


def _source_in_sink_args(line: str, sink_name: str, source_patterns: List) -> bool:
    """Return True only if a source pattern matches *inside the argument list* of sink_name on this line.

    This prevents the common FP where source and sink regexes both happen to
    match different parts of the same line with no actual data connection.
    """
    # Find the argument span of the sink call.
    call_pat = re.compile(re.escape(sink_name) + r"\s*\(", re.IGNORECASE)
    m = call_pat.search(line)
    if not m:
        # Sink may appear as attribute access or other form; fall back to full-line check
        # but only accept if source regex is a sub-match within any parenthesised group.
        paren_match = re.search(r"\(([^)]*)\)", line)
        arg_text = paren_match.group(1) if paren_match else ""
        if not arg_text:
            return False
    else:
        paren_start = m.end() - 1  # index of '('
        depth = 0
        end_idx = len(line)
        for i in range(paren_start, len(line)):
            if line[i] == "(":
                depth += 1
            elif line[i] == ")":
                depth -= 1
                if depth == 0:
                    end_idx = i
                    break
        arg_text = line[paren_start + 1:end_idx]
    for src_re in source_patterns:
        if src_re.search(arg_text):
            return True
    return False


def _is_safe_callee(call_name: str, raw_symbol: Optional[str], safe_set: Set[str]) -> bool:
    """Return True if the call resolves to a known-safe (non-propagating) function."""
    if not safe_set:
        return False
    candidates = {call_name}
    if raw_symbol:
        candidates.add(raw_symbol)
        # Also check the method portion of an owner.method call
        parts = re.split(r"(?:->|::|\.)", raw_symbol)
        candidates.add(parts[-1])
    return bool(candidates & safe_set)


def _compute_confidence(fn: "FunctionDef", path_steps: List[Dict], is_cross_file: bool) -> str:
    """Compute a confidence label for a taint flow.

    Returns one of: "high", "medium", "low".
    """
    if fn.meta.get("is_file_scope_fallback"):
        return "low"
    n_steps = len(path_steps)
    has_assign = any(s.get("type") == "assign" for s in path_steps)
    if is_cross_file and n_steps >= 3 and has_assign:
        return "high"
    if is_cross_file and n_steps >= 2:
        return "medium"
    if not is_cross_file and n_steps >= 2 and has_assign:
        return "medium"
    return "low"


def _parse_functions(platform: str, cfg: Dict, file_path: Path, lines: List[str]) -> List[FunctionDef]:
    """Dispatch to the right parser for the given platform, supporting
    both hard-coded specs and config-driven platforms."""
    return _parse_functions_internal(file_path, lines, platform, cfg)


def _parse_functions_internal(file_path: Path, lines: List[str], platform: str, cfg: Dict = None) -> List[FunctionDef]:
    if platform == "javascript":
        return _parse_javascript_functions(file_path, lines)
    if platform == "java":
        return _parse_java_functions(file_path, lines)
    if platform == "python":
        return _parse_python_functions(file_path, lines)

    spec = _get_platform_spec(platform, cfg or {})
    fn_re = spec["function_def_re"]
    mode = spec["mode"]
    functions: List[FunctionDef] = []

    for idx, line in enumerate(lines):
        match = fn_re.search(line)
        if not match:
            continue
        try:
            name = match.group(1)
        except IndexError:
            continue
        if not name:
            continue
        try:
            raw_params = match.group(2) or ""
        except IndexError:
            raw_params = ""
        if platform == "golang":
            params = _extract_go_params(raw_params)
        else:
            params = _extract_params(raw_params)
        if mode == "indent":
            end = _find_python_block_end(lines, idx)
        elif mode == "end_keyword":
            end = _find_end_keyword_block_end(lines, idx)
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
                signature=line.strip(),
                aliases=_function_aliases(name, file_path, lines, idx, platform),
            )
        )
    return functions


def _parse_python_functions(file_path: Path, lines: List[str]) -> List[FunctionDef]:
    functions: List[FunctionDef] = []
    fn_re = PLATFORM_SPECS["python"]["function_def_re"]

    for idx, line in enumerate(lines):
        match = fn_re.search(line) or PYTHON_ASYNC_DEF_RE.search(line)
        if not match:
            continue
        name = match.group(1)
        params = _extract_params(match.group(2))
        end = _find_python_block_end(lines, idx)
        functions.append(
            FunctionDef(
                name=name,
                file=file_path,
                line=idx + 1,
                params=params,
                start=idx,
                end=end,
                signature=line.strip(),
                aliases=_function_aliases(name, file_path, lines, idx, "python"),
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
                signature=signature,
                aliases=_function_aliases(name, file_path, lines, idx, "java"),
            )
        )
    return functions


def _parse_javascript_functions(file_path: Path, lines: List[str]) -> List[FunctionDef]:
    functions: List[FunctionDef] = []
    seen: Set[Tuple[str, int]] = set()

    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        match = PLATFORM_SPECS["javascript"]["function_def_re"].search(line)
        params: List[str] = []
        name = None
        if match and match.group(1) and match.group(2) is not None:
            name = match.group(1)
            params = _extract_params(match.group(2))
        else:
            assign_match = JS_ASSIGN_FUNCTION_RE.search(line)
            if assign_match:
                name = assign_match.group(1)
                params = _extract_params(assign_match.group(2))
            else:
                arrow_match = JS_ARROW_FUNCTION_RE.search(line)
                if arrow_match:
                    name = arrow_match.group(1)
                    raw_params = arrow_match.group(2) if arrow_match.group(2) is not None else arrow_match.group(3) or ""
                    params = _extract_params(raw_params)
                else:
                    method_match = JS_METHOD_SIG_RE.search(line)
                    if method_match:
                        candidate = method_match.group(1)
                        if candidate not in JS_EXCLUDED_METHODS:
                            name = candidate
                            params = _extract_params(method_match.group(2))
                    else:
                        object_fn_match = JS_OBJECT_FUNCTION_RE.search(line)
                        if object_fn_match:
                            name = object_fn_match.group(1)
                            params = _extract_params(object_fn_match.group(2))
                        else:
                            object_arrow_match = JS_OBJECT_ARROW_RE.search(line)
                            if object_arrow_match:
                                name = object_arrow_match.group(1)
                                raw_params = object_arrow_match.group(2) if object_arrow_match.group(2) is not None else object_arrow_match.group(3) or ""
                                params = _extract_params(raw_params)
                            else:
                                object_method_match = JS_OBJECT_METHOD_RE.search(line)
                                if object_method_match:
                                    candidate = object_method_match.group(1)
                                    if candidate not in JS_EXCLUDED_METHODS:
                                        name = candidate
                                        params = _extract_params(object_method_match.group(2))

        if not name:
            if JS_ROUTE_CALL_RE.search(line):
                inline_match = JS_INLINE_FUNCTION_CB_RE.search(line) or JS_INLINE_ARROW_CB_RE.search(line)
                if inline_match:
                    route_kind_match = JS_ROUTE_CALL_RE.search(line)
                    route_kind = route_kind_match.group(1).lower() if route_kind_match else "route"
                    raw_params = inline_match.group(1) or inline_match.group(2) or ""
                    params = _extract_params(raw_params)
                    name = f"route_{route_kind}_{idx + 1}"

        if not name or (name, idx) in seen:
            continue

        end = _find_brace_block_end(lines, idx)
        if end < 0:
            continue
        seen.add((name, idx))
        functions.append(
            FunctionDef(
                name=name,
                file=file_path,
                line=idx + 1,
                params=params,
                start=idx,
                end=end,
                signature=line.strip(),
                aliases=_function_aliases(name, file_path, lines, idx, "javascript"),
            )
        )
    return functions


def _extract_calls(line: str) -> List[Tuple[str, List[str], str]]:
    calls = []
    scrubbed = []
    in_quote = ""
    escaped = False
    for ch in str(line or ""):
        if in_quote:
            if escaped:
                escaped = False
                scrubbed.append(" ")
                continue
            if ch == "\\":
                escaped = True
                scrubbed.append(" ")
                continue
            if ch == in_quote:
                in_quote = ""
            scrubbed.append(" ")
            continue
        if ch in {"'", '"'}:
            in_quote = ch
            scrubbed.append(" ")
            continue
        scrubbed.append(ch)
    scrubbed_line = "".join(scrubbed)

    for match in CALL_RE.finditer(scrubbed_line):
        raw_name = match.group(1)
        name = re.split(r"(?:->|::|\.)", raw_name)[-1].lstrip("$")
        if name in {"if", "for", "while", "switch", "catch", "return", "new", "def", "class"}:
            continue

        open_idx = scrubbed_line.find("(", match.start())
        if open_idx < 0:
            continue
        idx = open_idx + 1
        depth = 1
        arg_start = idx
        args_raw = []
        while idx < len(scrubbed_line):
            ch = scrubbed_line[idx]
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
    if platform == "javascript":
        return (
            PLATFORM_SPECS[platform]["function_def_re"].search(line) is not None
            or JS_ASSIGN_FUNCTION_RE.search(line) is not None
            or JS_ARROW_FUNCTION_RE.search(line) is not None
            or JS_METHOD_SIG_RE.search(line) is not None
            or JS_OBJECT_FUNCTION_RE.search(line) is not None
            or JS_OBJECT_ARROW_RE.search(line) is not None
            or JS_OBJECT_METHOD_RE.search(line) is not None
        )
    if platform == "python":
        return PLATFORM_SPECS[platform]["function_def_re"].search(line) is not None or PYTHON_ASYNC_DEF_RE.search(line) is not None
    if platform in PLATFORM_SPECS:
        fn_re = PLATFORM_SPECS[platform]["function_def_re"]
    else:
        cfg = load_analysis_config() or {}
        plat_cfg = cfg.get(str(platform).lower(), {}) if isinstance(cfg, dict) else {}
        analyzer_block = plat_cfg.get("analyzer", {}) if isinstance(plat_cfg, dict) else {}
        fn_re_pat = str(analyzer_block.get("function_def_re", "")).strip()
        try:
            fn_re = re.compile(fn_re_pat, re.MULTILINE) if fn_re_pat else re.compile(r"(?!)")
        except re.error:
            fn_re = re.compile(r"(?!)")
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


def _resolve_php_form_target(current_file: Path, action: str) -> str:
    action_text = str(action or "").strip()
    if not action_text:
        return current_file.name
    if re.match(r"^[a-z]+://", action_text, re.IGNORECASE):
        return action_text
    path_part = action_text.split("?", 1)[0].split("#", 1)[0].strip()
    if not path_part:
        return current_file.name
    return str((current_file.parent / path_part).resolve())


def _extract_php_form_declarations(file_path: Path, lines: List[str]) -> List[Dict]:
    declarations: List[Dict] = []
    active: Optional[Dict] = None

    for idx, raw_line in enumerate(lines, start=1):
        line = str(raw_line or "")
        open_match = PHP_FORM_OPEN_RE.search(line)
        if open_match:
            attrs = {key.lower(): value.strip() for key, value in PHP_FORM_ATTR_RE.findall(open_match.group(1) or "")}
            action = attrs.get("action", "").strip() or file_path.name
            active = {
                "decl_file": str(file_path),
                "decl_line": idx,
                "action": action,
                "resolved_target": _resolve_php_form_target(file_path, action),
                "method": attrs.get("method", "get").strip().upper() or "GET",
                "enctype": attrs.get("enctype", "").strip(),
                "fields": [],
            }

        if active:
            for field_match in PHP_FORM_FIELD_RE.finditer(line):
                tag = (field_match.group(1) or "").lower()
                attrs = field_match.group(2) or ""
                name_match = PHP_FIELD_NAME_RE.search(attrs)
                if not name_match:
                    continue
                field_type_match = PHP_FIELD_TYPE_RE.search(attrs)
                field_type = (field_type_match.group(1).strip().lower() if field_type_match else "")
                if tag == "textarea":
                    field_type = field_type or "textarea"
                elif tag == "select":
                    field_type = field_type or "select"
                elif not field_type:
                    field_type = "text"
                active["fields"].append({"name": name_match.group(1).strip(), "type": field_type, "line": idx})

        if active and PHP_FORM_CLOSE_RE.search(line):
            if active["fields"]:
                declarations.append(active)
            active = None

    if active and active["fields"]:
        declarations.append(active)
    return declarations


def _find_php_form_field_declaration(
    current_file: Path,
    scope: str,
    field_name: str,
    form_declarations_by_target: Dict[str, List[Dict]],
) -> Optional[Dict]:
    target_keys = {str(current_file), current_file.name}
    try:
        target_keys.add(str(current_file.resolve()))
    except OSError:
        pass

    for target_key in target_keys:
        for declaration in form_declarations_by_target.get(target_key, []):
            method = str(declaration.get("method", "")).upper()
            enctype = str(declaration.get("enctype", "")).lower()
            scope_name = str(scope or "").upper()
            if scope_name == "POST" and method != "POST":
                continue
            if scope_name == "GET" and method != "GET":
                continue
            if scope_name == "FILES" and "multipart/form-data" not in enctype:
                continue
            for field in declaration.get("fields", []):
                if str(field.get("name", "")).strip() == str(field_name or "").strip():
                    return {
                        "decl_file": declaration.get("decl_file", ""),
                        "decl_line": field.get("line") or declaration.get("decl_line", ""),
                        "action": declaration.get("action", ""),
                        "method": method,
                        "field_type": field.get("type", ""),
                    }
    return None


def _describe_source_expression(
    rhs: str,
    lhs: str,
    platform: str,
    *,
    current_file: Optional[Path] = None,
    form_declarations_by_target: Optional[Dict[str, List[Dict]]] = None,
) -> Tuple[str, str, List[str]]:
    expr = str(rhs or "").strip()
    target = str(lhs or "").strip().lstrip("$@")
    default_code = expr
    default_symbol = target or "source"
    default_vars = [value for value in [target] if value]

    if platform == "php":
        m = PHP_SUPERGLOBAL_KEY_RE.search(expr)
        if m:
            scope = m.group(1).upper()
            key = m.group(2)
            code = f"[source] PHP {scope} parameter `{key}` is assigned to `${target or key}`."
            if current_file and form_declarations_by_target:
                form_decl = _find_php_form_field_declaration(current_file, scope, key, form_declarations_by_target)
                if form_decl:
                    code += (
                        f" Declared by form field `{key}` in `{Path(str(form_decl['decl_file'])).name}:{form_decl['decl_line']}` "
                        f"and submitted via {form_decl['method']} to `{form_decl['action']}`."
                    )
            symbol = key or default_symbol
            vars_out = [value for value in [key, target] if value]
            return code, symbol, vars_out

        m = PHP_DYNAMIC_SUPERGLOBAL_KEY_RE.search(expr)
        if m:
            scope = m.group(1).upper()
            key_var = m.group(2)
            code = f"[source] PHP {scope} parameter selected by `${key_var}` is assigned to `${target or key_var}`."
            symbol = key_var or default_symbol
            vars_out = [value for value in [key_var, target] if value]
            return code, symbol, vars_out

        m = PHP_INPUT_CALL_RE.search(expr)
        if m:
            method = m.group(1).lower()
            key = m.group(2)
            code = f"[source] Request {method.upper()} input `{key}` is assigned to `${target or key}`."
            if current_file and form_declarations_by_target:
                form_decl = _find_php_form_field_declaration(current_file, method, key, form_declarations_by_target)
                if form_decl:
                    code += (
                        f" Declared by form field `{key}` in `{Path(str(form_decl['decl_file'])).name}:{form_decl['decl_line']}` "
                        f"and submitted via {form_decl['method']} to `{form_decl['action']}`."
                    )
            symbol = key or default_symbol
            vars_out = [value for value in [key, target] if value]
            return code, symbol, vars_out

        m = PHP_REQUEST_CALL_RE.search(expr)
        if m:
            method = m.group(1).lower()
            key = m.group(2)
            code = f"[source] Request {method.upper()} value `{key}` is assigned to `${target or key}`."
            if current_file and form_declarations_by_target:
                mapped_scope = "POST" if method in {"post", "input"} else "GET" if method in {"get", "query"} else method
                form_decl = _find_php_form_field_declaration(current_file, mapped_scope, key, form_declarations_by_target)
                if form_decl:
                    code += (
                        f" Declared by form field `{key}` in `{Path(str(form_decl['decl_file'])).name}:{form_decl['decl_line']}` "
                        f"and submitted via {form_decl['method']} to `{form_decl['action']}`."
                    )
            symbol = key or default_symbol
            vars_out = [value for value in [key, target] if value]
            return code, symbol, vars_out

        m = PHP_REQUEST_OBJECT_CALL_RE.search(expr)
        if m:
            method = m.group(1).lower()
            key = m.group(2) or m.group(3) or ""
            code = f"[source] Request {method.upper()} value `{key or target or 'input'}` is assigned to `${target or key or 'input'}`."
            if key and current_file and form_declarations_by_target:
                mapped_scope = "POST" if method in {"request", "files"} else "GET" if method in {"get", "query"} else method
                form_decl = _find_php_form_field_declaration(current_file, mapped_scope, key, form_declarations_by_target)
                if form_decl:
                    code += (
                        f" Declared by form field `{key}` in `{Path(str(form_decl['decl_file'])).name}:{form_decl['decl_line']}` "
                        f"and submitted via {form_decl['method']} to `{form_decl['action']}`."
                    )
            symbol = key or default_symbol
            vars_out = [value for value in [key, target] if value]
            return code, symbol, vars_out

    return default_code, default_symbol, default_vars


def _extract_php_foreach_source(line: str) -> Optional[Dict]:
    match = PHP_FOREACH_SUPERGLOBAL_RE.search(str(line or ""))
    if not match:
        return None
    return {
        "scope": match.group(1).upper(),
        "bucket": match.group(2) or "",
        "key_var": match.group(3) or "",
        "value_var": match.group(4) or "",
    }


def _extract_php_session_write(line: str) -> Optional[Dict]:
    match = PHP_SESSION_WRITE_RE.search(str(line or ""))
    if not match:
        return None
    return {
        "bucket": match.group(1) or "",
        "index": match.group(2) or "",
        "rhs": (match.group(3) or "").strip(),
    }


def _extract_php_session_reads(text: str) -> List[str]:
    seen: Set[str] = set()
    buckets: List[str] = []
    for match in PHP_SESSION_READ_RE.finditer(str(text or "")):
        bucket = str(match.group(1) or "").strip()
        if bucket and bucket not in seen:
            seen.add(bucket)
            buckets.append(bucket)
    return buckets


def _make_path_step(
    file_path: Path | str,
    line: int | str,
    role: str,
    code: str,
    *,
    symbol: str = "",
    source_symbol: str = "",
    target_symbol: str = "",
    variables: Optional[List[str]] = None,
) -> Dict:
    seen: Set[str] = set()
    normalized_vars: List[str] = []
    for item in variables or []:
        token = str(item or "").strip().lstrip("$@")
        if token and token not in seen:
            seen.add(token)
            normalized_vars.append(token)
    return {
        "file": str(file_path),
        "line": line,
        "role": role,
        "code": code,
        "symbol": symbol,
        "source_symbol": source_symbol,
        "target_symbol": target_symbol,
        "variables": normalized_vars,
    }


def _make_termination_node(
    file_path: Path | str,
    line: int | str,
    reason: str,
    code: str,
    *,
    symbol: str = "",
    source_symbol: str = "",
    target_symbol: str = "",
    variables: Optional[List[str]] = None,
) -> Dict:
    node = _make_path_step(
        file_path,
        line,
        "termination",
        code,
        symbol=symbol,
        source_symbol=source_symbol,
        target_symbol=target_symbol,
        variables=variables,
    )
    node["reason"] = str(reason or "").strip() or "unresolved"
    return node


def _append_partial_flow(
    flows: List[Dict],
    *,
    fn: FunctionDef,
    line_no: int,
    call_name: str,
    raw_symbol: str,
    description: str,
    explanation: str,
    path_steps: List[Dict],
    call_index: Dict[str, List[Dict]],
    def_index: Dict[str, List[FunctionDef]],
    termination_reason: str,
    termination_node: Dict,
) -> None:
    xref = _build_xref(path_steps, call_index, def_index)
    flows.append(
        {
            "file": str(fn.file),
            "function": fn.name,
            "line": line_no,
            "sink": raw_symbol or call_name or "trace termination",
            "description": description,
            "explanation": explanation,
            "path": path_steps,
            "xref": xref,
            "flow_kind": "partial",
            "trace_status": "partial",
            "termination_reason": termination_reason,
            "termination_nodes": [termination_node],
            "confidence": "low",
            "cross_file": False,
        }
    )


def _make_interfile_handoff_step(
    caller_fn: FunctionDef,
    sink_item: Dict,
    *,
    call_name: str,
    raw_symbol: str,
    source_symbol: str,
) -> Optional[Dict]:
    sink_file = str(sink_item.get("file", "") or "")
    if not sink_file or sink_file == str(caller_fn.file):
        return None
    sink_line = sink_item.get("line", "")
    sink_fn = str(sink_item.get("function", "") or call_name or raw_symbol or "callee").strip()
    handoff_code = (
        f"[inter-file] Tainted value crosses from `{caller_fn.name}` into `{sink_fn}` and remains "
        "tainted in the callee scope before reaching the sink."
    )
    return _make_path_step(
        sink_file,
        sink_line,
        "handoff",
        handoff_code,
        symbol=raw_symbol or call_name,
        source_symbol=source_symbol,
        target_symbol=sink_fn,
        variables=[value for value in [source_symbol, sink_fn] if value],
    )


def _call_aliases(raw_symbol: str, resolved_name: str) -> List[str]:
    aliases: List[str] = []
    candidates = [resolved_name or "", raw_symbol or ""]
    seen: Set[str] = set()

    for candidate in candidates:
        token = str(candidate).strip().lstrip("$")
        if not token:
            continue
        parts = [part.lstrip("$") for part in re.split(r"(?:->|::|\.)", token) if part]
        if token not in seen:
            seen.add(token)
            aliases.append(token)
        for index in range(len(parts)):
            suffix = ".".join(parts[index:])
            if suffix and suffix not in seen:
                seen.add(suffix)
                aliases.append(suffix)
            scope_suffix = "::".join(parts[index:])
            if scope_suffix and scope_suffix not in seen:
                seen.add(scope_suffix)
                aliases.append(scope_suffix)
        if parts:
            leaf = parts[-1]
            if leaf not in seen:
                seen.add(leaf)
                aliases.append(leaf)
            if len(parts) >= 2:
                owner = parts[-2]
                qualified = f"{owner}.{leaf}"
                if qualified not in seen:
                    seen.add(qualified)
                    aliases.append(qualified)
                for owner_alias in _framework_owner_aliases(owner):
                    expanded = f"{owner_alias}.{leaf}"
                    if expanded not in seen:
                        seen.add(expanded)
                        aliases.append(expanded)
    return aliases


def _lookup_summary(summary_by_name: Dict[str, FunctionSummary], call_name: str, raw_symbol: str) -> Optional[FunctionSummary]:
    for alias in _call_aliases(raw_symbol, call_name):
        summary = summary_by_name.get(alias)
        if summary:
            return summary
    return None


def _signature_window(lines: List[str], fn: FunctionDef, lookback: int = 3) -> str:
    start = max(0, fn.start - lookback)
    end = min(len(lines), fn.start + 1)
    return "\n".join(line.strip() for line in lines[start:end] if line.strip())


def _infer_initial_source_params(fn: FunctionDef, lines: List[str], platform: str) -> Set[str]:
    params = {str(param).strip(): str(param).strip().lower() for param in fn.params if str(param).strip()}
    if not params:
        return set()

    signature = fn.signature or ""
    signature_window = _signature_window(lines, fn).lower()
    file_lower = str(fn.file).lower()
    inferred: Set[str] = set()

    def add_by_names(*names: str) -> None:
        lower_names = {name.lower() for name in names}
        for original, lowered in params.items():
            if lowered in lower_names:
                inferred.add(original)

    if platform == "javascript":
        if any(marker in file_lower for marker in ("/routes/", "/route/", "/controllers/", "/controller/", "/api/", "/middleware/", "/handlers/")):
            add_by_names("req", "request", "ctx", "context", "event", "params", "searchparams", "query", "body")
        if any(marker in file_lower for marker in ("/app/api/", "/pages/api/", "/src/app/api/", "/server/actions/", "/actions/")):
            add_by_names("request", "req", "context", "ctx", "params", "searchparams")
        if any(token in signature_window for token in ("nextrequest", "nextapirequest", "nextapirequest", "routehandlercontext")):
            add_by_names("request", "req", "context", "ctx", "params")
        if any(token in signature_window for token in ("usesearchparams", "useparams", "userouter", "router.query", "@injectable", "@controller", "@resolver")):
            add_by_names("params", "searchparams", "query", "body", "input")
        if "router." in signature_window or "app." in signature_window or "fastify." in signature_window or any(token in signature_window for token in ("@get", "@post", "@put", "@patch", "@delete")):
            add_by_names("req", "request", "ctx", "context", "reply", "res", "response")
        if NEST_BINDING_DECORATOR_RE.search(signature):
            inferred.update(params.keys())

    elif platform == "php":
        if any(marker in file_lower for marker in ("/controller/", "/controllers/", "/middleware/", "/routes/")):
            add_by_names("request", "req", "input")
        if any(marker in file_lower for marker in ("/app/http/controllers/", "/app/controllers/", "/src/controller/", "/src/controllers/", "/modules/", "/application/controllers/")):
            add_by_names("request", "req", "input", "query", "params")
        if any(token in signature_window for token in ("illuminate\\http\\request", "serverrequestinterface", "symfony\\component\\httpfoundation\\request", "codeigniter\\http\\incomingrequest")):
            add_by_names("request", "req")
        for match in PHP_REQUEST_PARAM_HINT_RE.finditer(signature):
            inferred.add(match.group(2))

    elif platform == "java":
        if "@restcontroller" in signature_window or "@controller" in signature_window:
            for original, lowered in params.items():
                if lowered in {"request", "req", "body", "query", "params", "path"}:
                    inferred.add(original)
        if any(token in signature_window for token in ("@getmapping", "@postmapping", "@putmapping", "@patchmapping", "@deletemapping", "@requestmapping")):
            inferred.update(params.keys())
        if any(token in signature_window for token in ("@service", "@repository", "@component", "@autowired", "@bean")):
            add_by_names("request", "req", "body", "query", "params", "dto", "command")
        if JAVA_SPRING_PARAM_ANN_RE.search(signature):
            inferred.update(params.keys())
        for match in JAVA_HTTP_REQUEST_HINT_RE.finditer(signature):
            inferred.add(match.group(2))

    elif platform == "dotnet":
        if any(marker in file_lower for marker in ("/controllers/", "\\controllers\\")) or "controllerbase" in signature_window or "controller" in signature_window:
            for original, lowered in params.items():
                if lowered in {"request", "req", "model", "dto", "id", "input", "query"}:
                    inferred.add(original)
        if any(token in signature_window for token in ("[httpget", "[httppost", "[httpput", "[httppatch", "[httpdelete", "[route", "mapget(", "mappost(", "mapput(", "mappatch(", "mapdelete(")):
            inferred.update(params.keys())
        if any(token in signature_window for token in ("[apicontroller", "iservicecollection", "builder.services", "addscoped(", "addtransient(", "addsingleton(")):
            add_by_names("request", "req", "model", "dto", "command", "query", "input")
        if DOTNET_BINDING_ATTR_RE.search(signature):
            inferred.update(params.keys())
        for match in DOTNET_HTTP_REQUEST_HINT_RE.finditer(signature):
            inferred.add(match.group(1))

    return {name for name in inferred if name in params}


def _scan_scope_for_summary(
    fn: FunctionDef,
    lines: List[str],
    cfg: Dict,
    platform: str,
    summary_by_name: Dict[str, FunctionSummary],
) -> FunctionSummary:
    summary = FunctionSummary()
    tainted: Dict[str, Set[int]] = {p: {i} for i, p in enumerate(fn.params)}
    source_tainted: Set[str] = set(_infer_initial_source_params(fn, lines, platform))
    session_tainted: Dict[str, Set[int]] = {}
    session_source_tainted: Set[str] = set()
    session_var_buckets: Dict[str, Set[str]] = {}

    for idx in range(fn.start, min(fn.end, len(lines))):
        line = lines[idx]
        stripped = line.strip()
        if not stripped:
            continue
        if _is_function_definition_line(stripped, platform):
            continue

        if platform == "php":
            foreach_source = _extract_php_foreach_source(stripped)
            if foreach_source and foreach_source["scope"] == "SESSION":
                bucket = foreach_source["bucket"]
                key_var = foreach_source["key_var"]
                value_var = foreach_source["value_var"]
                if bucket in session_tainted:
                    if key_var:
                        tainted[key_var] = set(session_tainted[bucket])
                    if value_var:
                        tainted[value_var] = set(session_tainted[bucket])
                if bucket in session_source_tainted:
                    if key_var:
                        source_tainted.add(key_var)
                    if value_var:
                        source_tainted.add(value_var)
                for derived_var in [key_var, value_var]:
                    if derived_var:
                        session_var_buckets.setdefault(derived_var, set()).add(bucket)

        assign = _extract_assignment(stripped, platform)
        if assign:
            lhs, rhs = assign
            if platform == "php":
                read_buckets = _extract_php_session_reads(rhs)
                inherited_session: Set[int] = set()
                inherited_session_source = False
                for bucket in read_buckets:
                    inherited_session.update(session_tainted.get(bucket, set()))
                    if bucket in session_source_tainted:
                        inherited_session_source = True
                if inherited_session:
                    tainted[lhs] = inherited_session
                if inherited_session_source:
                    source_tainted.add(lhs)
                for bucket in read_buckets:
                    session_var_buckets.setdefault(lhs, set()).add(bucket)
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
                inherited_session_buckets: Set[str] = set()
                if platform == "php":
                    for var, buckets in session_var_buckets.items():
                        if _line_has_var(rhs, var, platform):
                            inherited_session_buckets.update(buckets)

                for call_name, call_args, raw_symbol in _extract_calls(rhs):
                    callee = _lookup_summary(summary_by_name, call_name, raw_symbol)
                    if not callee:
                        builtin_desc = BUILTIN_SINK_CALLS.get(str(call_name or "").strip().lower())
                        if builtin_desc:
                            sink_obj = {
                                "sink": call_name,
                                "description": builtin_desc,
                                "file": str(fn.file),
                                "line": idx + 1,
                                "code": _line_source(lines, idx),
                                "function": fn.name,
                            }
                            for arg_idx, arg_expr in enumerate(call_args):
                                for var, origins in tainted.items():
                                    if _line_has_var(arg_expr, var, platform):
                                        for origin_idx in origins:
                                            summary.param_to_sink.setdefault(origin_idx, []).append(sink_obj)
                                for var in source_tainted:
                                    if _line_has_var(arg_expr, var, platform):
                                        summary.source_to_sink.append(sink_obj)
                        continue
                    for bucket in callee.session_to_return:
                        if bucket in session_tainted:
                            inherited.update(session_tainted[bucket])
                        if bucket in session_source_tainted:
                            inherited_source = True
                    for arg_idx, arg_expr in enumerate(call_args):
                        for var, origins in tainted.items():
                            if _line_has_var(arg_expr, var, platform):
                                if arg_idx in callee.param_to_return:
                                    inherited.update(origins)
                                for bucket in callee.param_to_session.get(arg_idx, set()):
                                    session_tainted.setdefault(bucket, set()).update(origins)
                                if callee.param_to_sink.get(arg_idx):
                                    for sink_item in callee.param_to_sink[arg_idx]:
                                        for origin_idx in origins:
                                            summary.param_to_sink.setdefault(origin_idx, []).append(sink_item)
                                if platform == "php" and callee.session_to_sink:
                                    for bucket in session_var_buckets.get(var, set()):
                                        if bucket in callee.session_to_return:
                                            inherited_session_buckets.add(bucket)
                        for svar in source_tainted:
                            if _line_has_var(arg_expr, svar, platform):
                                if callee.source_to_return:
                                    inherited_source = True
                                if arg_idx in callee.param_to_return:
                                    inherited_source = True
                                if callee.param_to_session.get(arg_idx):
                                    summary.source_to_session.update(callee.param_to_session[arg_idx])
                                    session_source_tainted.update(callee.param_to_session[arg_idx])
                                if callee.source_to_sink:
                                    for sink_item in callee.source_to_sink:
                                        summary.source_to_sink.append(sink_item)
                                if callee.param_to_sink.get(arg_idx):
                                    for sink_item in callee.param_to_sink[arg_idx]:
                                        summary.source_to_sink.append(sink_item)
                    for bucket, sink_items in callee.session_to_sink.items():
                        if bucket in session_tainted:
                            for origin_idx in session_tainted[bucket]:
                                summary.param_to_sink.setdefault(origin_idx, []).extend(sink_items)
                        if bucket in session_source_tainted:
                            summary.source_to_sink.extend(sink_items)
                    if callee.source_to_session:
                        summary.source_to_session.update(callee.source_to_session)
                        session_source_tainted.update(callee.source_to_session)
                    if platform == "php" and callee.session_to_return:
                        inherited_session_buckets.update(callee.session_to_return)

                if inherited:
                    tainted[lhs] = inherited
                if inherited_source:
                    source_tainted.add(lhs)
                if platform == "php" and inherited_session_buckets:
                    session_var_buckets.setdefault(lhs, set()).update(inherited_session_buckets)

        for call_name, call_args, raw_symbol in _extract_calls(stripped):
            callee = _lookup_summary(summary_by_name, call_name, raw_symbol)
            if callee:
                continue
            builtin_desc = BUILTIN_SINK_CALLS.get(str(call_name or "").strip().lower())
            if not builtin_desc:
                continue
            sink_obj = {
                "sink": call_name,
                "description": builtin_desc,
                "file": str(fn.file),
                "line": idx + 1,
                "code": _line_source(lines, idx),
                "function": fn.name,
            }
            for arg_idx, arg_expr in enumerate(call_args):
                for var, origins in tainted.items():
                    if _line_has_var(arg_expr, var, platform):
                        for origin_idx in origins:
                            summary.param_to_sink.setdefault(origin_idx, []).append(sink_obj)
                for var in source_tainted:
                    if _line_has_var(arg_expr, var, platform):
                        summary.source_to_sink.append(sink_obj)

        if platform == "php":
            session_write = _extract_php_session_write(stripped)
            if session_write:
                bucket = session_write["bucket"]
                rhs = session_write["rhs"]
                if any(r.search(rhs) for r in cfg.get("sources", [])):
                    summary.source_to_session.add(bucket)
                    session_source_tainted.add(bucket)
                else:
                    for var, origins in tainted.items():
                        if _line_has_var(rhs, var, platform):
                            for origin_idx in origins:
                                summary.param_to_session.setdefault(origin_idx, set()).add(bucket)
                            session_tainted.setdefault(bucket, set()).update(origins)
                    for var in source_tainted:
                        if _line_has_var(rhs, var, platform):
                            summary.source_to_session.add(bucket)
                            session_source_tainted.add(bucket)

        for san_re in cfg.get("sanitizers", []):
            if san_re.search(stripped):
                for var in list(tainted.keys()):
                    if _line_has_var(stripped, var, platform):
                        tainted.pop(var, None)
                for var in list(source_tainted):
                    if _line_has_var(stripped, var, platform):
                        source_tainted.discard(var)
                if platform == "php":
                    for var in list(session_var_buckets.keys()):
                        if _line_has_var(stripped, var, platform):
                            session_var_buckets.pop(var, None)

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
            if platform == "php":
                for var, buckets in session_var_buckets.items():
                    if _line_has_var(stripped, var, platform):
                        for bucket in buckets:
                            summary.session_to_sink.setdefault(bucket, []).append(sink_obj)
                for bucket in _extract_php_session_reads(stripped):
                    summary.session_to_sink.setdefault(bucket, []).append(sink_obj)
                    for origin_idx in session_tainted.get(bucket, set()):
                        summary.param_to_sink.setdefault(origin_idx, []).append(sink_obj)
                    if bucket in session_source_tainted:
                        summary.source_to_sink.append(sink_obj)

        if RETURN_RE.search(stripped):
            for var, origins in tainted.items():
                if _line_has_var(stripped, var, platform):
                    summary.param_to_return.update(origins)
            for var in source_tainted:
                if _line_has_var(stripped, var, platform):
                    summary.source_to_return = True
            if platform == "php":
                for var, buckets in session_var_buckets.items():
                    if _line_has_var(stripped, var, platform):
                        summary.session_to_return.update(buckets)
                for bucket in _extract_php_session_reads(stripped):
                    summary.session_to_return.add(bucket)

    return summary


def _summaries_equal(a: FunctionSummary, b: FunctionSummary) -> bool:
    return (
        set(a.param_to_return) == set(b.param_to_return)
        and a.source_to_return == b.source_to_return
        and _canon_sink_map(a.param_to_sink) == _canon_sink_map(b.param_to_sink)
        and _canon_sinks(a.source_to_sink) == _canon_sinks(b.source_to_sink)
        and _canon_bucket_map(a.param_to_session) == _canon_bucket_map(b.param_to_session)
        and set(a.source_to_session) == set(b.source_to_session)
        and _canon_session_sink_map(a.session_to_sink) == _canon_session_sink_map(b.session_to_sink)
        and set(a.session_to_return) == set(b.session_to_return)
    )


def _canon_sinks(items: List[Dict]) -> Set[Tuple]:
    out = set()
    for item in items:
        out.add((item.get("sink"), item.get("description"), item.get("file"), item.get("line"), item.get("function")))
    return out


def _canon_sink_map(items: Dict[int, List[Dict]]) -> Dict[int, Set[Tuple]]:
    return {idx: _canon_sinks(sinks) for idx, sinks in items.items()}


def _canon_bucket_map(items: Dict[int, Set[str]]) -> Dict[int, Set[str]]:
    return {idx: set(values) for idx, values in items.items()}


def _canon_session_sink_map(items: Dict[str, List[Dict]]) -> Dict[str, Set[Tuple]]:
    return {bucket: _canon_sinks(sinks) for bucket, sinks in items.items()}


def _build_xref(path_steps: List[Dict], call_index: Dict[str, List[Dict]], def_index: Dict[str, List[FunctionDef]]) -> List[Dict]:
    xrefs: List[Dict] = []
    seen = set()
    max_xref_entries = 40
    for step in path_steps:
        code = step.get("code", "")
        for call_name, _, full_symbol in _extract_calls(code):
            aliases = _call_aliases(full_symbol, call_name)
            def_alias = next((alias for alias in aliases if def_index.get(alias)), "")
            call_alias = next((alias for alias in aliases if call_index.get(alias)), "")

            if def_alias:
                for defn in def_index.get(def_alias, [])[:2]:
                    key = ("def", def_alias, str(defn.file), defn.line)
                    if key in seen:
                        continue
                    seen.add(key)
                    xrefs.append(
                        {
                            "type": "definition",
                            "symbol": full_symbol,
                            "resolved_name": def_alias,
                            "file": str(defn.file),
                            "line": defn.line,
                            "context": f"Definition of {def_alias}",
                        }
                    )
                    if len(xrefs) >= max_xref_entries:
                        return xrefs

            if call_alias:
                related = 0
                for caller in call_index.get(call_alias, []):
                    if str(caller.get("file", "")) == str(step.get("file", "")) and int(caller.get("line", 0) or 0) == int(step.get("line", 0) or 0):
                        continue
                    key = ("call", call_alias, caller["file"], caller["line"], caller.get("symbol", call_alias))
                    if key in seen:
                        continue
                    seen.add(key)
                    xrefs.append(
                        {
                            "type": "callsite",
                            "symbol": caller.get("symbol", call_alias),
                            "resolved_name": call_alias,
                            "file": caller["file"],
                            "line": caller["line"],
                            "context": "Related callsite",
                        }
                    )
                    related += 1
                    if len(xrefs) >= max_xref_entries or related >= 4:
                        break
                if len(xrefs) >= max_xref_entries:
                    return xrefs
    return xrefs


def _load_analyzer_limits():
    """Read max_files / max_functions from tool.yaml, with safe fallback."""
    try:
        import utils.config_utils as _cu
        acfg = _cu.get_analysis_config()
        return acfg.get("max_files_per_platform", 300), acfg.get("max_functions_per_platform", 1500)
    except Exception:
        return 300, 1500


def analyze_multifile_flows(
    source_root: Path,
    cfg: Dict,
    platform: str,
    max_files: Optional[int] = None,
    max_functions: Optional[int] = None,
) -> List[Dict]:
    if max_files is None or max_functions is None:
        _mf, _mfn = _load_analyzer_limits()
        if max_files is None:
            max_files = _mf
        if max_functions is None:
            max_functions = _mfn

    spec = _get_platform_spec(platform, cfg)
    globs = spec["globs"]

    files: List[Path] = []
    for pat in globs:
        files.extend(source_root.rglob(pat))

    if len(files) > max_files:
        print(
            f"     [!] Analyzer limit: {len(files)} {platform} files found; "
            f"capping at {max_files}. Use --no-analysis to skip or raise "
            f"max_files_per_platform in config/tool.yaml for full coverage."
        )
        files = sorted(files)[:max_files]

    total_files = len(files)
    print(f"     [-] Analyzer Files       : {total_files} {platform} file(s) queued for parsing", flush=True)

    file_lines: Dict[Path, List[str]] = {}
    functions: List[FunctionDef] = []
    def_index: Dict[str, List[FunctionDef]] = {}
    call_index: Dict[str, List[Dict]] = {}
    form_declarations_by_target: Dict[str, List[Dict]] = {}

    _PARSE_REPORT_EVERY = max(1, total_files // 10)
    for _fi, file_path in enumerate(files, start=1):
        if _fi == 1 or _fi % _PARSE_REPORT_EVERY == 0 or _fi == total_files:
            end = "\n" if _fi == total_files else "\r"
            print(f"     [-] Parsing              : {_fi}/{total_files} files", end=end, flush=True)
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        file_lines[file_path] = lines
        if platform == "php":
            for declaration in _extract_php_form_declarations(file_path, lines):
                for target_key in {
                    declaration.get("resolved_target", ""),
                    Path(str(declaration.get("resolved_target", "") or "")).name if declaration.get("resolved_target") else "",
                }:
                    if target_key:
                        form_declarations_by_target.setdefault(target_key, []).append(declaration)

        fns = _parse_functions(platform, cfg, file_path, lines)
        if not fns:
            # Fallback scope: entire file treated as one scope. Marked so confidence scoring
            # can downgrade flows found in this scope.
            fallback_fn = FunctionDef(
                name="__file_scope__",
                file=file_path,
                line=1,
                params=[],
                start=0,
                end=len(lines),
                aliases=["__file_scope__", file_path.stem],
            )
            fallback_fn.meta["is_file_scope_fallback"] = True
            fns = [fallback_fn]
        functions.extend(fns)
        for fn in fns:
            for alias in fn.aliases or _call_aliases(fn.name, fn.name):
                def_index.setdefault(alias, []).append(fn)

        for line_no, line in enumerate(lines, start=1):
            if _is_function_definition_line(line.strip(), platform):
                continue
            for call_name, _, full_symbol in _extract_calls(line):
                call_obj = {"file": str(file_path), "line": line_no, "code": line.strip(), "symbol": full_symbol}
                for alias in _call_aliases(full_symbol, call_name):
                    call_index.setdefault(alias, []).append(call_obj)

    if len(functions) > max_functions:
        print(
            f"     [!] Analyzer limit: {len(functions)} {platform} functions parsed; "
            f"capping at {max_functions}. Raise max_functions_per_platform in "
            f"config/tool.yaml for full coverage."
        )
        functions = functions[:max_functions]
        def_index = {}
        for fn in functions:
            for alias in fn.aliases or _call_aliases(fn.name, fn.name):
                def_index.setdefault(alias, []).append(fn)

    max_taint_passes = int(cfg.get("max_taint_passes", 7))
    print(f"     [-] Functions parsed     : {len(functions)}", flush=True)
    print(f"     [-] Propagating taint    : running up to {max_taint_passes} passes over {len(functions)} function(s)", flush=True)

    summary_by_name: Dict[str, FunctionSummary] = {}
    for fn in functions:
        for alias in fn.aliases or [fn.name]:
            summary_by_name.setdefault(alias, FunctionSummary())

    for _pass in range(max_taint_passes):
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
            for alias in fn.aliases or [fn.name]:
                agg = merged.setdefault(alias, FunctionSummary())
                agg.param_to_return.update(cur.param_to_return)
                agg.source_to_return = agg.source_to_return or cur.source_to_return
                for idx, buckets in cur.param_to_session.items():
                    agg.param_to_session.setdefault(idx, set()).update(buckets)
                agg.source_to_session.update(cur.source_to_session)
                for idx, sinks in cur.param_to_sink.items():
                    agg.param_to_sink.setdefault(idx, []).extend(sinks)
                agg.source_to_sink.extend(cur.source_to_sink)
                for bucket, sinks in cur.session_to_sink.items():
                    agg.session_to_sink.setdefault(bucket, []).extend(sinks)
                agg.session_to_return.update(cur.session_to_return)

        for name, new_summary in merged.items():
            old = summary_by_name.get(name, FunctionSummary())
            if not _summaries_equal(old, new_summary):
                summary_by_name[name] = new_summary
                changed = True
        print(f"     [-] Taint pass {_pass + 1}/{max_taint_passes}        : {'converged (done early)' if not changed else 'changes found, continuing'}", flush=True)
        if not changed:
            break

    print(f"     [-] Flow tracing         : tracing paths across {len(functions)} function(s)", flush=True)
    flows: List[Dict] = []

    for fn in functions:
        lines = file_lines.get(fn.file, [])
        session_tainted_paths: Dict[str, List[Dict]] = {}
        tainted_paths: Dict[str, List[Dict]] = {
            p: [_make_path_step(fn.file, fn.line, "param", p, symbol=p, source_symbol=p, variables=[p])]
            for p in fn.params
        }
        source_tainted_paths: Dict[str, List[Dict]] = {
            param: [_make_path_step(
                fn.file,
                fn.line,
                "source",
                f"[framework] Request-bound parameter `{param}`",
                symbol=param,
                source_symbol=param,
                variables=[param],
            )]
            for param in _infer_initial_source_params(fn, lines, platform)
        }

        for idx in range(fn.start, min(fn.end, len(lines))):
            line = lines[idx]
            stripped = line.strip()
            if not stripped:
                continue
            if _is_function_definition_line(stripped, platform):
                continue

            if platform == "php":
                foreach_source = _extract_php_foreach_source(stripped)
                if foreach_source:
                    scope = foreach_source["scope"]
                    bucket = foreach_source["bucket"]
                    key_var = foreach_source["key_var"]
                    value_var = foreach_source["value_var"]
                    if scope == "SESSION" and bucket and bucket in session_tainted_paths:
                        base_path = session_tainted_paths[bucket]
                        if key_var:
                            tainted_paths[key_var] = base_path + [_make_path_step(
                                fn.file,
                                idx + 1,
                                "assign",
                                f"[session] Tainted session bucket `{bucket}` key is assigned to `${key_var}` via foreach.",
                                symbol=key_var,
                                source_symbol=bucket,
                                target_symbol=key_var,
                                variables=[bucket, key_var],
                            )]
                        if value_var:
                            tainted_paths[value_var] = base_path + [_make_path_step(
                                fn.file,
                                idx + 1,
                                "assign",
                                f"[session] Tainted session bucket `{bucket}` value is assigned to `${value_var}` via foreach.",
                                symbol=value_var,
                                source_symbol=bucket,
                                target_symbol=value_var,
                                variables=[bucket, value_var],
                            )]
                    elif scope in {"POST", "GET", "REQUEST", "COOKIE", "FILES"}:
                        if key_var:
                            source_tainted_paths[key_var] = [
                                _make_path_step(
                                    fn.file,
                                    idx + 1,
                                    "source",
                                    f"[source] PHP {scope} parameter name is assigned to `${key_var}` via foreach.",
                                    symbol=key_var,
                                    source_symbol=key_var,
                                    target_symbol=key_var,
                                    variables=[key_var],
                                )
                            ]
                        if value_var:
                            source_tainted_paths[value_var] = [
                                _make_path_step(
                                    fn.file,
                                    idx + 1,
                                    "source",
                                    f"[source] PHP {scope} parameter value is assigned to `${value_var}` via foreach.",
                                    symbol=value_var,
                                    source_symbol=value_var,
                                    target_symbol=value_var,
                                    variables=[value_var],
                                )
                            ]

            assign = _extract_assignment(stripped, platform)
            assign_lhs = assign[0] if assign else None
            assign_rhs = assign[1] if assign else stripped

            if assign:
                lhs, rhs = assign
                if any(r.search(rhs) for r in cfg.get("sources", [])):
                    source_code, source_symbol, source_vars = _describe_source_expression(
                        rhs,
                        lhs,
                        platform,
                        current_file=fn.file,
                        form_declarations_by_target=form_declarations_by_target,
                    )
                    source_step = _make_path_step(
                        fn.file,
                        idx + 1,
                        "source",
                        source_code,
                        symbol=source_symbol or lhs,
                        source_symbol=source_symbol or lhs,
                        target_symbol=lhs,
                        variables=source_vars or [lhs],
                    )
                    assign_step = _make_path_step(
                        fn.file,
                        idx + 1,
                        "assign",
                        stripped,
                        symbol=lhs,
                        source_symbol=source_symbol or lhs,
                        target_symbol=lhs,
                        variables=(source_vars or []) + ([lhs] if lhs else []),
                    )
                    source_tainted_paths[lhs] = [source_step, assign_step]
                else:
                    for var, path_steps in tainted_paths.items():
                        if _line_has_var(rhs, var, platform):
                            tainted_paths[lhs] = path_steps + [_make_path_step(
                                fn.file,
                                idx + 1,
                                "assign",
                                stripped,
                                symbol=lhs,
                                source_symbol=var,
                                target_symbol=lhs,
                                variables=[var, lhs],
                            )]
                            break
                    for var, path_steps in source_tainted_paths.items():
                        if _line_has_var(rhs, var, platform):
                            source_tainted_paths[lhs] = path_steps + [_make_path_step(
                                fn.file,
                                idx + 1,
                                "assign",
                                stripped,
                                symbol=lhs,
                                source_symbol=var,
                                target_symbol=lhs,
                                variables=[var, lhs],
                            )]
                            break

            if platform == "php":
                session_write = _extract_php_session_write(stripped)
                if session_write:
                    bucket = session_write["bucket"]
                    rhs = session_write["rhs"]
                    if any(r.search(rhs) for r in cfg.get("sources", [])):
                        source_code, source_symbol, source_vars = _describe_source_expression(
                            rhs,
                            bucket,
                            platform,
                            current_file=fn.file,
                            form_declarations_by_target=form_declarations_by_target,
                        )
                        session_tainted_paths[bucket] = [
                            _make_path_step(
                                fn.file,
                                idx + 1,
                                "source",
                                source_code,
                                symbol=source_symbol or bucket,
                                source_symbol=source_symbol or bucket,
                                target_symbol=bucket,
                                variables=source_vars or [bucket],
                            ),
                            _make_path_step(
                                fn.file,
                                idx + 1,
                                "assign",
                                f"[session] Source-tainted value is stored in session bucket `{bucket}`.",
                                symbol=bucket,
                                source_symbol=source_symbol or bucket,
                                target_symbol=bucket,
                                variables=[value for value in [source_symbol, bucket] if value],
                            ),
                        ]
                    else:
                        for var, path_steps in {**tainted_paths, **source_tainted_paths}.items():
                            if _line_has_var(rhs, var, platform):
                                session_tainted_paths[bucket] = path_steps + [_make_path_step(
                                    fn.file,
                                    idx + 1,
                                    "assign",
                                    f"[session] Tainted value `{var}` is stored in session bucket `{bucket}`.",
                                    symbol=bucket,
                                    source_symbol=var,
                                    target_symbol=bucket,
                                    variables=[var, bucket],
                                )]
                                break

            for san_re in cfg.get("sanitizers", []):
                if san_re.search(stripped):
                    for var in list(tainted_paths.keys()):
                        if _line_has_var(stripped, var, platform):
                            tainted_paths.pop(var, None)
                    for var in list(source_tainted_paths.keys()):
                        if _line_has_var(stripped, var, platform):
                            source_tainted_paths.pop(var, None)

            safe_callees = cfg.get("safe_callees", set())
            calls = _extract_calls(assign_rhs)
            for call_name, call_args, raw_symbol in calls:
                callee = _lookup_summary(summary_by_name, call_name, raw_symbol)
                if not callee:
                    # Skip known-safe callees (logging, type casts, framework response helpers)
                    # to avoid generating noisy partial flows that are never true sinks.
                    if _is_safe_callee(call_name, raw_symbol, safe_callees):
                        continue
                    for arg_expr in call_args:
                        for var, steps in tainted_paths.items():
                            if not _line_has_var(arg_expr, var, platform):
                                continue
                            call_step = _make_path_step(
                                fn.file,
                                idx + 1,
                                "call",
                                stripped,
                                symbol=raw_symbol or call_name,
                                source_symbol=var,
                                target_symbol=call_name,
                                variables=[var, call_name],
                            )
                            termination_node = _make_termination_node(
                                fn.file,
                                idx + 1,
                                "unresolved_callee",
                                stripped,
                                symbol=raw_symbol or call_name,
                                source_symbol=var,
                                target_symbol=call_name,
                                variables=[var, call_name],
                            )
                            _append_partial_flow(
                                flows,
                                fn=fn,
                                line_no=idx + 1,
                                call_name=call_name,
                                raw_symbol=raw_symbol,
                                description=(
                                    f"Tainted value `{var}` reaches call `{call_name}`, but the analyzer cannot trace "
                                    "the callee body from this codebase."
                                ),
                                explanation=(
                                    "This is a trace termination point. The value is still tainted at the call boundary, "
                                    "but source-to-sink tracking becomes incomplete because the callee could not be resolved."
                                ),
                                path_steps=steps + [call_step],
                                call_index=call_index,
                                def_index=def_index,
                                termination_reason="unresolved_callee",
                                termination_node=termination_node,
                            )
                        for var, steps in source_tainted_paths.items():
                            if not _line_has_var(arg_expr, var, platform):
                                continue
                            call_step = _make_path_step(
                                fn.file,
                                idx + 1,
                                "call",
                                stripped,
                                symbol=raw_symbol or call_name,
                                source_symbol=var,
                                target_symbol=call_name,
                                variables=[var, call_name],
                            )
                            termination_node = _make_termination_node(
                                fn.file,
                                idx + 1,
                                "unresolved_callee",
                                stripped,
                                symbol=raw_symbol or call_name,
                                source_symbol=var,
                                target_symbol=call_name,
                                variables=[var, call_name],
                            )
                            _append_partial_flow(
                                flows,
                                fn=fn,
                                line_no=idx + 1,
                                call_name=call_name,
                                raw_symbol=raw_symbol,
                                description=(
                                    f"Source-tainted value `{var}` reaches call `{call_name}`, but the analyzer cannot "
                                    "trace the callee body from this codebase."
                                ),
                                explanation=(
                                    "This is a trace termination point. The value remains source-tainted at the call boundary, "
                                    "but downstream propagation could not be resolved statically."
                                ),
                                path_steps=steps + [call_step],
                                call_index=call_index,
                                def_index=def_index,
                                termination_reason="unresolved_callee",
                                termination_node=termination_node,
                            )
                        if any(r.search(arg_expr) for r in cfg.get("sources", [])):
                            source_code, source_symbol, source_vars = _describe_source_expression(
                                arg_expr,
                                arg_expr,
                                platform,
                                current_file=fn.file,
                                form_declarations_by_target=form_declarations_by_target,
                            )
                            source_arg_step = _make_path_step(
                                fn.file,
                                idx + 1,
                                "source",
                                source_code,
                                symbol=raw_symbol or call_name,
                                source_symbol=source_symbol or arg_expr,
                                target_symbol=call_name,
                                variables=source_vars or [arg_expr],
                            )
                            call_step = _make_path_step(
                                fn.file,
                                idx + 1,
                                "call",
                                stripped,
                                symbol=raw_symbol or call_name,
                                source_symbol=arg_expr,
                                target_symbol=call_name,
                                variables=[arg_expr, call_name],
                            )
                            termination_node = _make_termination_node(
                                fn.file,
                                idx + 1,
                                "unresolved_callee",
                                stripped,
                                symbol=raw_symbol or call_name,
                                source_symbol=arg_expr,
                                target_symbol=call_name,
                                variables=[arg_expr, call_name],
                            )
                            _append_partial_flow(
                                flows,
                                fn=fn,
                                line_no=idx + 1,
                                call_name=call_name,
                                raw_symbol=raw_symbol,
                                description=(
                                    f"Direct source expression reaches call `{call_name}`, but the analyzer cannot trace "
                                    "the callee body from this codebase."
                                ),
                                explanation=(
                                    "This is a trace termination point. The source reaches an unresolved call boundary, "
                                    "so a downstream sink may still exist outside the currently resolved graph."
                                ),
                                path_steps=[source_arg_step, call_step],
                                call_index=call_index,
                                def_index=def_index,
                                termination_reason="unresolved_callee",
                                termination_node=termination_node,
                            )
                    continue
                session_call_step = _make_path_step(
                    fn.file,
                    idx + 1,
                    "call",
                    stripped,
                    symbol=raw_symbol or call_name,
                    source_symbol="session",
                    target_symbol=call_name,
                    variables=[call_name],
                )
                if assign_lhs:
                    for bucket in callee.session_to_return:
                        if bucket in session_tainted_paths:
                            tainted_paths[assign_lhs] = session_tainted_paths[bucket] + [session_call_step]
                if not assign_lhs and callee.session_to_return:
                    for bucket in callee.session_to_return:
                        if bucket not in session_tainted_paths:
                            continue
                        for sink_name, (sink_re, sink_desc) in cfg.get("sinks", {}).items():
                            if not sink_re.search(stripped):
                                continue
                            path_steps = session_tainted_paths[bucket] + [session_call_step] + [_make_path_step(
                                fn.file,
                                idx + 1,
                                "sink",
                                stripped,
                                symbol=sink_name,
                                source_symbol=bucket,
                                target_symbol=sink_name,
                                variables=[bucket, sink_name],
                            )]
                            xref = _build_xref(path_steps, call_index, def_index)
                            flows.append(
                                {
                                    "file": str(fn.file),
                                    "function": fn.name,
                                    "line": idx + 1,
                                    "sink": sink_name,
                                    "description": (
                                        f"Session bucket `{bucket}` remains tainted after `{call_name}` returns "
                                        f"and reaches sink `{sink_name}`."
                                    ),
                                    "explanation": (
                                        "A tainted value was previously stored in session state, returned by the callee, "
                                        "and then used immediately in a sensitive sink."
                                    ),
                                    "path": path_steps,
                                    "xref": xref,
                                    "confidence": _compute_confidence(fn, path_steps, False),
                                    "cross_file": False,
                                }
                            )
                for arg_idx, arg_expr in enumerate(call_args):
                    arg_is_source = any(r.search(arg_expr) for r in cfg.get("sources", []))
                    source_code, source_symbol, source_vars = _describe_source_expression(
                        arg_expr,
                        arg_expr,
                        platform,
                        current_file=fn.file,
                        form_declarations_by_target=form_declarations_by_target,
                    ) if arg_is_source else ("", "", [])
                    source_arg_step = _make_path_step(
                        fn.file,
                        idx + 1,
                        "source",
                        source_code if arg_is_source else stripped,
                        symbol=raw_symbol or call_name,
                        source_symbol=source_symbol or arg_expr,
                        target_symbol=call_name,
                        variables=source_vars or [arg_expr],
                    )
                    for var, steps in tainted_paths.items():
                        if not _line_has_var(arg_expr, var, platform):
                            continue
                        call_step = _make_path_step(
                            fn.file,
                            idx + 1,
                            "call",
                            stripped,
                            symbol=raw_symbol or call_name,
                            source_symbol=var,
                            target_symbol=call_name,
                            variables=[var, call_name],
                        )
                        if arg_idx in callee.param_to_return and assign_lhs:
                            tainted_paths[assign_lhs] = steps + [call_step]
                        for bucket in callee.param_to_session.get(arg_idx, set()):
                            session_tainted_paths[bucket] = steps + [call_step] + [_make_path_step(
                                fn.file,
                                idx + 1,
                                "assign",
                                f"[session] Tainted value `{var}` is stored via `{call_name}` into session bucket `{bucket}`.",
                                symbol=bucket,
                                source_symbol=var,
                                target_symbol=bucket,
                                variables=[var, bucket],
                            )]
                        for sink_item in callee.param_to_sink.get(arg_idx, []):
                            handoff_step = _make_interfile_handoff_step(
                                fn,
                                sink_item,
                                call_name=call_name,
                                raw_symbol=raw_symbol,
                                source_symbol=var,
                            )
                            path_steps = steps + [call_step] + ([handoff_step] if handoff_step else []) + [_make_path_step(
                                sink_item.get("file", fn.file),
                                sink_item.get("line", idx + 1),
                                "sink",
                                sink_item.get("code", ""),
                                symbol=sink_item.get("sink", call_name),
                                source_symbol=var,
                                target_symbol=sink_item.get("sink", call_name),
                                variables=[var, sink_item.get("sink", call_name)],
                            )]
                            xref = _build_xref(path_steps, call_index, def_index)
                            _is_cross = str(sink_item.get("file", fn.file)) != str(fn.file)
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
                                    "confidence": _compute_confidence(fn, path_steps, _is_cross),
                                    "cross_file": _is_cross,
                                }
                            )
                    for var, steps in source_tainted_paths.items():
                        if not _line_has_var(arg_expr, var, platform):
                            continue
                        call_step = _make_path_step(
                            fn.file,
                            idx + 1,
                            "call",
                            stripped,
                            symbol=raw_symbol or call_name,
                            source_symbol=var,
                            target_symbol=call_name,
                            variables=[var, call_name],
                        )
                        if callee.source_to_return and assign_lhs:
                            source_tainted_paths[assign_lhs] = steps + [call_step]
                        if arg_idx in callee.param_to_return and assign_lhs:
                            source_tainted_paths[assign_lhs] = steps + [call_step]
                        for bucket in callee.param_to_session.get(arg_idx, set()):
                            session_tainted_paths[bucket] = steps + [call_step] + [_make_path_step(
                                fn.file,
                                idx + 1,
                                "assign",
                                f"[session] Source-tainted value `{var}` is stored via `{call_name}` into session bucket `{bucket}`.",
                                symbol=bucket,
                                source_symbol=var,
                                target_symbol=bucket,
                                variables=[var, bucket],
                            )]
                        for sink_item in callee.param_to_sink.get(arg_idx, []):
                            handoff_step = _make_interfile_handoff_step(
                                fn,
                                sink_item,
                                call_name=call_name,
                                raw_symbol=raw_symbol,
                                source_symbol=var,
                            )
                            path_steps = steps + [call_step] + ([handoff_step] if handoff_step else []) + [_make_path_step(
                                sink_item.get("file", fn.file),
                                sink_item.get("line", idx + 1),
                                "sink",
                                sink_item.get("code", ""),
                                symbol=sink_item.get("sink", call_name),
                                source_symbol=var,
                                target_symbol=sink_item.get("sink", call_name),
                                variables=[var, sink_item.get("sink", call_name)],
                            )]
                            xref = _build_xref(path_steps, call_index, def_index)
                            _is_cross = str(sink_item.get("file", fn.file)) != str(fn.file)
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
                                    "confidence": _compute_confidence(fn, path_steps, _is_cross),
                                    "cross_file": _is_cross,
                                }
                            )
                        for sink_item in callee.source_to_sink:
                            handoff_step = _make_interfile_handoff_step(
                                fn,
                                sink_item,
                                call_name=call_name,
                                raw_symbol=raw_symbol,
                                source_symbol=var,
                            )
                            path_steps = steps + [call_step] + ([handoff_step] if handoff_step else []) + [_make_path_step(
                                sink_item.get("file", fn.file),
                                sink_item.get("line", idx + 1),
                                "sink",
                                sink_item.get("code", ""),
                                symbol=sink_item.get("sink", call_name),
                                source_symbol=var,
                                target_symbol=sink_item.get("sink", call_name),
                                variables=[var, sink_item.get("sink", call_name)],
                            )]
                            xref = _build_xref(path_steps, call_index, def_index)
                            _is_cross = str(sink_item.get("file", fn.file)) != str(fn.file)
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
                                    "confidence": _compute_confidence(fn, path_steps, _is_cross),
                                    "cross_file": _is_cross,
                                }
                            )
                    if arg_is_source:
                        call_step = _make_path_step(
                            fn.file,
                            idx + 1,
                            "call",
                            stripped,
                            symbol=raw_symbol or call_name,
                            source_symbol=arg_expr,
                            target_symbol=call_name,
                            variables=[arg_expr, call_name],
                        )
                        if callee.source_to_return and assign_lhs:
                            source_tainted_paths[assign_lhs] = [source_arg_step, call_step]
                        for bucket in callee.source_to_session:
                            session_tainted_paths[bucket] = [source_arg_step, call_step] + [_make_path_step(
                                fn.file,
                                idx + 1,
                                "assign",
                                f"[session] Source expression is stored via `{call_name}` into session bucket `{bucket}`.",
                                symbol=bucket,
                                source_symbol=source_symbol or arg_expr,
                                target_symbol=bucket,
                                variables=[source_symbol or arg_expr, bucket],
                            )]
                        for sink_item in callee.source_to_sink:
                            handoff_step = _make_interfile_handoff_step(
                                fn,
                                sink_item,
                                call_name=call_name,
                                raw_symbol=raw_symbol,
                                source_symbol=arg_expr,
                            )
                            path_steps = [source_arg_step, call_step] + ([handoff_step] if handoff_step else []) + [_make_path_step(
                                sink_item.get("file", fn.file),
                                sink_item.get("line", idx + 1),
                                "sink",
                                sink_item.get("code", ""),
                                symbol=sink_item.get("sink", call_name),
                                source_symbol=arg_expr,
                                target_symbol=sink_item.get("sink", call_name),
                                variables=[arg_expr, sink_item.get("sink", call_name)],
                            )]
                            xref = _build_xref(path_steps, call_index, def_index)
                            _is_cross = str(sink_item.get("file", fn.file)) != str(fn.file)
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
                                    "confidence": _compute_confidence(fn, path_steps, _is_cross),
                                    "cross_file": _is_cross,
                                }
                            )
                for bucket, sink_items in callee.session_to_sink.items():
                    if bucket not in session_tainted_paths:
                        continue
                    for sink_item in sink_items:
                        handoff_step = _make_interfile_handoff_step(
                            fn,
                            sink_item,
                            call_name=call_name,
                            raw_symbol=raw_symbol,
                            source_symbol=bucket,
                        )
                        path_steps = session_tainted_paths[bucket] + [session_call_step] + ([handoff_step] if handoff_step else []) + [_make_path_step(
                            sink_item.get("file", fn.file),
                            sink_item.get("line", idx + 1),
                            "sink",
                            sink_item.get("code", ""),
                            symbol=sink_item.get("sink", call_name),
                            source_symbol=bucket,
                            target_symbol=sink_item.get("sink", call_name),
                            variables=[bucket, sink_item.get("sink", call_name)],
                        )]
                        xref = _build_xref(path_steps, call_index, def_index)
                        _is_cross = str(sink_item.get("file", fn.file)) != str(fn.file)
                        flows.append(
                            {
                                "file": str(fn.file),
                                "function": fn.name,
                                "line": idx + 1,
                                "sink": sink_item.get("sink", call_name),
                                "description": (
                                    f"Session bucket `{bucket}` remains tainted and flows through `{call_name}` "
                                    f"into sink `{sink_item.get('sink', call_name)}`."
                                ),
                                "explanation": (
                                    "A tainted value was previously stored in session state and later consumed "
                                    "by another function where it reaches a sensitive sink."
                                ),
                                "path": path_steps,
                                "xref": xref,
                                "confidence": _compute_confidence(fn, path_steps, _is_cross),
                                "cross_file": _is_cross,
                            }
                        )

            for sink_name, (sink_re, sink_desc) in cfg.get("sinks", {}).items():
                if not sink_re.search(stripped):
                    continue
                line_has_source = any(r.search(stripped) for r in cfg.get("sources", []))
                for var, path_steps in tainted_paths.items():
                    if _line_has_var(stripped, var, platform):
                        full_path = path_steps + [_make_path_step(
                            fn.file,
                            idx + 1,
                            "sink",
                            stripped,
                            symbol=sink_name,
                            source_symbol=var,
                            target_symbol=sink_name,
                            variables=[var, sink_name],
                        )]
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
                                "confidence": _compute_confidence(fn, full_path, False),
                                "cross_file": False,
                            }
                        )
                for var, path_steps in source_tainted_paths.items():
                    if _line_has_var(stripped, var, platform):
                        full_path = path_steps + [_make_path_step(
                            fn.file,
                            idx + 1,
                            "sink",
                            stripped,
                            symbol=sink_name,
                            source_symbol=var,
                            target_symbol=sink_name,
                            variables=[var, sink_name],
                        )]
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
                                "confidence": _compute_confidence(fn, full_path, False),
                                "cross_file": False,
                            }
                        )
                # Only emit a direct source→sink flow when the source pattern
                # actually appears *inside the argument list* of the sink call,
                # not just anywhere on the same line (avoids FPs from co-occurring
                # source/sink keywords that have no data connection).
                if line_has_source and _source_in_sink_args(stripped, sink_name, cfg.get("sources", [])):
                    source_code, source_symbol, source_vars = _describe_source_expression(
                        stripped,
                        "source",
                        platform,
                        current_file=fn.file,
                        form_declarations_by_target=form_declarations_by_target,
                    )
                    full_path = [
                        _make_path_step(
                            fn.file,
                            idx + 1,
                            "source",
                            source_code,
                            symbol="source",
                            source_symbol=source_symbol or "source",
                            variables=source_vars or ["source"],
                        ),
                        _make_path_step(fn.file, idx + 1, "sink", stripped, symbol=sink_name, target_symbol=sink_name, variables=[sink_name]),
                    ]
                    xref = _build_xref(full_path, call_index, def_index)
                    is_cross = str(fn.file) != str(fn.file)  # same-file direct flow
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
                            "confidence": _compute_confidence(fn, full_path, is_cross),
                            "cross_file": is_cross,
                        }
                    )

    print(f"     [-] Flows identified     : {len(flows)} cross-file flow(s) found", flush=True)
    return flows
