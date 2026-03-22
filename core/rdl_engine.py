import fnmatch
import re
from pathlib import Path


def _strip_comment(line):
    text = (line or "").strip()
    if not text or text.startswith("#"):
        return ""
    return text


def _parse_regex_token(token):
    raw = (token or "").strip()
    if not raw:
        return None, 0
    if len(raw) >= 2 and raw[0] == "/" and raw.count("/") >= 2:
        end = raw.rfind("/")
        pattern = raw[1:end]
        flags_text = raw[end + 1:].strip().lower()
        flags = 0
        if "i" in flags_text:
            flags |= re.IGNORECASE
        if "m" in flags_text:
            flags |= re.MULTILINE
        if "s" in flags_text:
            flags |= re.DOTALL
        return pattern, flags
    return raw, re.IGNORECASE | re.MULTILINE


def _split_top_level(expr, operator):
    parts = []
    start = 0
    depth = 0
    i = 0
    op_len = len(operator)

    while i < len(expr):
        char = expr[i]
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)

        if depth == 0 and expr[i:i + op_len] == operator:
            parts.append(expr[start:i].strip())
            i += op_len
            start = i
            continue
        i += 1

    tail = expr[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _strip_wrapping_parentheses(expr):
    text = (expr or "").strip()
    if not text:
        return text

    while text.startswith("(") and text.endswith(")"):
        depth = 0
        balanced = True
        for idx, char in enumerate(text):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0 and idx != len(text) - 1:
                    balanced = False
                    break
        if balanced and depth == 0:
            text = text[1:-1].strip()
        else:
            break
    return text


def _evaluate_predicate(predicate, text):
    token = _strip_wrapping_parentheses(predicate)
    match = re.match(r"^(MISSING|PRESENT|EXISTS)\s*:(.+)$", token, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return False

    mode = match.group(1).upper()
    pattern = match.group(2).strip()
    if not pattern:
        return False

    try:
        found = bool(re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE))
    except re.error:
        return False

    if mode == "MISSING":
        return not found
    return found


def _evaluate_expression(expr, text):
    expression = _strip_wrapping_parentheses(expr)
    if not expression:
        return True

    or_parts = _split_top_level(expression, "||")
    if len(or_parts) > 1:
        return any(_evaluate_expression(part, text) for part in or_parts)

    and_parts = _split_top_level(expression, "&&")
    if len(and_parts) > 1:
        return all(_evaluate_expression(part, text) for part in and_parts)

    if expression.startswith("!"):
        return not _evaluate_expression(expression[1:].strip(), text)

    return _evaluate_predicate(expression, text)


def load_rdl(path):
    rdl_path = Path(path)
    return rdl_path.read_text(encoding="utf-8")


def _project_glob(project_root, pattern):
    root = Path(project_root or ".").resolve()
    matches = []
    try:
        for item in root.rglob("*"):
            try:
                rel = item.relative_to(root).as_posix()
            except ValueError:
                rel = item.as_posix()
            if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(item.name, pattern):
                matches.append(item)
    except OSError:
        return []
    return matches


def evaluate_rdl_with_reason(rdl_script, *, file_text="", file_path="", project_root=""):
    commands = []
    for raw_line in (rdl_script or "").splitlines():
        line = _strip_comment(raw_line)
        if line:
            commands.append(line)

    result = {
        "passes": True,
        "outcome": "area_of_interest",
        "reason": "",
        "fail_reason": "",
        "trace": [],
        "consulted_files": [],
    }
    current_path = Path(file_path or "")
    current_name = current_path.name
    normalized_path = current_path.as_posix()

    for line in commands:
        upper = line.upper()
        if upper.startswith("REPORT AS "):
            result["outcome"] = line[len("REPORT AS "):].strip().lower()
            continue
        if upper.startswith("REASON "):
            result["reason"] = line[len("REASON "):].strip()
            continue
        if upper.startswith("FAIL_REASON "):
            result["fail_reason"] = line[len("FAIL_REASON "):].strip()
            continue
        if upper.startswith("TRACE "):
            result["trace"].append(line[len("TRACE "):].strip())
            continue

    for line in commands:
        upper = line.upper()
        if upper.startswith("VERSION "):
            continue
        if upper.startswith("REPORT AS ") or upper.startswith("REASON ") or upper.startswith("FAIL_REASON ") or upper.startswith("TRACE "):
            continue

        if upper.startswith("WHEN FILE_NAME_IS "):
            expected = line[len("WHEN FILE_NAME_IS "):].strip()
            matched = current_name == expected
            result["trace"].append(f"file_name_is {expected}: {'matched' if matched else 'missed'}")
            if not matched:
                result["passes"] = False
                if not result["fail_reason"]:
                    result["fail_reason"] = f"Expected file name {expected}"
                return result
            continue

        if upper.startswith("WHEN FILE_PATH_MATCHES "):
            pattern = line[len("WHEN FILE_PATH_MATCHES "):].strip()
            matched = fnmatch.fnmatch(normalized_path, pattern) or fnmatch.fnmatch(current_name, pattern)
            result["trace"].append(f"file_path_matches {pattern}: {'matched' if matched else 'missed'}")
            if not matched:
                result["passes"] = False
                if not result["fail_reason"]:
                    result["fail_reason"] = f"Expected file path match {pattern}"
                return result
            continue

        if upper.startswith("WHEN CURRENT_FILE_MATCHES "):
            token = line[len("WHEN CURRENT_FILE_MATCHES "):].strip()
            pattern, flags = _parse_regex_token(token)
            matched = bool(pattern and re.search(pattern, file_text or "", flags=flags))
            result["trace"].append(f"current_file_matches {token}: {'matched' if matched else 'missed'}")
            if not matched:
                result["passes"] = False
                if not result["fail_reason"]:
                    result["fail_reason"] = f"Current file did not satisfy {token}"
                return result
            continue

        if upper.startswith("WHEN PRESENT "):
            token = line[len("WHEN PRESENT "):].strip()
            pattern, flags = _parse_regex_token(token)
            matched = bool(pattern and re.search(pattern, file_text or "", flags=flags))
            result["trace"].append(f"present {token}: {'matched' if matched else 'missed'}")
            if not matched:
                result["passes"] = False
                if not result["fail_reason"]:
                    result["fail_reason"] = f"Required pattern was not found: {token}"
                return result
            continue

        if upper.startswith("WHEN MISSING "):
            token = line[len("WHEN MISSING "):].strip()
            pattern, flags = _parse_regex_token(token)
            matched = bool(pattern and re.search(pattern, file_text or "", flags=flags))
            result["trace"].append(f"missing {token}: {'violated' if matched else 'satisfied'}")
            if matched:
                result["passes"] = False
                if not result["fail_reason"]:
                    result["fail_reason"] = f"Excluded by present safe pattern: {token}"
                return result
            continue

        if upper.startswith("WHEN EXPR "):
            expr = line[len("WHEN EXPR "):].strip()
            matched = bool(expr and _evaluate_expression(expr, file_text or ""))
            result["trace"].append(f"expr {expr}: {'matched' if matched else 'missed'}")
            if not matched:
                result["passes"] = False
                if not result["fail_reason"]:
                    result["fail_reason"] = f"Expression did not pass: {expr}"
                return result
            continue

        if upper.startswith("UNLESS CURRENT_FILE_MATCHES "):
            token = line[len("UNLESS CURRENT_FILE_MATCHES "):].strip()
            pattern, flags = _parse_regex_token(token)
            matched = bool(pattern and re.search(pattern, file_text or "", flags=flags))
            result["trace"].append(f"unless current_file_matches {token}: {'triggered' if matched else 'not_triggered'}")
            if matched:
                result["passes"] = False
                if not result["fail_reason"]:
                    result["fail_reason"] = f"Excluded by current file pattern {token}"
                return result
            continue

        if upper.startswith("OBSERVE PROJECT_HAS_GLOB "):
            remainder = line[len("OBSERVE PROJECT_HAS_GLOB "):].strip()
            label = ""
            if " AS " in remainder:
                pattern, label = remainder.rsplit(" AS ", 1)
                pattern = pattern.strip()
                label = label.strip()
            else:
                pattern = remainder
            matches = _project_glob(project_root, pattern)
            for item in matches[:8]:
                try:
                    rel = item.resolve().relative_to(Path(project_root).resolve()).as_posix()
                except Exception:
                    rel = item.as_posix()
                result["consulted_files"].append(rel)
            observation = f"project_has_glob {pattern}: {len(matches)} match(es)"
            if label:
                observation = f"{label}: {observation}"
            result["trace"].append(observation)
            continue

    # Keep consulted files unique and stable.
    seen = set()
    deduped = []
    for item in result["consulted_files"]:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    result["consulted_files"] = deduped
    return result
