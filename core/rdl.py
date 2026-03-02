# Standard libraries
import re


def extract_flag_pattern(rdl_text):
    """
    Extract FLAG regex from RDL expression.
    Expected style: [FLAG:<regex>][IF(...)]
    """
    if not rdl_text:
        return None
    match = re.search(r"\[\s*FLAG\s*:", rdl_text, flags=re.IGNORECASE)
    if not match:
        return None

    idx = match.end()
    buf = []
    escaped = False
    in_char_class = False

    while idx < len(rdl_text):
        ch = rdl_text[idx]

        if escaped:
            buf.append(ch)
            escaped = False
            idx += 1
            continue

        if ch == "\\":
            buf.append(ch)
            escaped = True
            idx += 1
            continue

        if ch == "[" and not in_char_class:
            in_char_class = True
            buf.append(ch)
            idx += 1
            continue

        if ch == "]":
            if in_char_class:
                in_char_class = False
                buf.append(ch)
                idx += 1
                continue
            break

        buf.append(ch)
        idx += 1

    pattern = "".join(buf).strip()
    return pattern or None


def _extract_if_expression(rdl_text):
    if not rdl_text:
        return ""

    match = re.search(r"\[\s*IF\s*\((.*)\)\s*\]\s*$", rdl_text, flags=re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).strip()

    match = re.search(r"IF\s*\((.*)\)\s*$", rdl_text, flags=re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).strip()

    return ""


def _split_top_level(expr, operator):
    parts = []
    start = 0
    depth = 0
    i = 0
    op_len = len(operator)

    while i < len(expr):
        char = expr[i]
        if char == '(':
            depth += 1
        elif char == ')':
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
    text = expr.strip()
    if not text:
        return text

    while text.startswith('(') and text.endswith(')'):
        depth = 0
        balanced = True
        for idx, char in enumerate(text):
            if char == '(':
                depth += 1
            elif char == ')':
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

    if expression.startswith('!'):
        return not _evaluate_expression(expression[1:].strip(), text)

    return _evaluate_predicate(expression, text)


def evaluate_rdl(rdl_text, file_text):
    """
    Evaluate RDL rule against complete file content.

    Supported operators:
      - FLAG:<regex>
      - IF(<predicate && predicate || predicate>)
      - Predicates: MISSING:<regex>, PRESENT:<regex>, EXISTS:<regex>
    """
    if not rdl_text:
        return False

    text = file_text or ""
    flag_pattern = extract_flag_pattern(rdl_text)

    if flag_pattern:
        try:
            if not re.search(flag_pattern, text, flags=re.IGNORECASE | re.MULTILINE):
                return False
        except re.error:
            return False

    if_expr = _extract_if_expression(rdl_text)
    if not if_expr:
        return bool(flag_pattern)

    return _evaluate_expression(if_expr, text)
