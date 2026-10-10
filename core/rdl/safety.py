"""Static safety checks for regular expressions accepted by RDL v2."""

import sre_parse
import re
from functools import lru_cache


MAX_REGEX_CHARACTERS = 4096


def regex_safety_error(pattern):
    if len(pattern) > MAX_REGEX_CHARACTERS:
        return "regex exceeds {0} characters".format(MAX_REGEX_CHARACTERS)
    try:
        parsed = sre_parse.parse(pattern)
    except Exception:
        return "regex could not be parsed"
    if _contains_unsafe_repeat(parsed, False):
        return "regex contains nested repetition with potentially unbounded work"
    return ""


def _contains_unsafe_repeat(sequence, inside_repeat):
    repeat_ops = {sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT}
    for operation, argument in sequence:
        if operation in repeat_ops:
            minimum, maximum, child = argument
            potentially_unbounded = maximum == sre_parse.MAXREPEAT or maximum > 1000
            if inside_repeat and potentially_unbounded:
                return True
            if _contains_unsafe_repeat(child, inside_repeat or potentially_unbounded):
                return True
        elif operation == sre_parse.SUBPATTERN:
            if _contains_unsafe_repeat(argument[-1], inside_repeat):
                return True
        elif operation == sre_parse.BRANCH:
            if any(_contains_unsafe_repeat(branch, inside_repeat) for branch in argument[1]):
                return True
        elif operation in {sre_parse.ASSERT, sre_parse.ASSERT_NOT}:
            # Lookarounds do not backtrack after success; still check their own nested repetitions.
            if _contains_unsafe_repeat(argument[1], False):
                return True
    return False


@lru_cache(maxsize=4096)
def required_literal_clauses(pattern, flags=0):
    """Necessary literal conditions only; the regex remains the decision maker."""
    parsed = sre_parse.parse(pattern, flags)
    def clauses(sequence, active_flags):
        found, run = [], []
        def flush():
            literal = ''.join(run)
            run.clear()
            if len(literal) >= 3 and literal.isascii():
                found.append(((literal[:512], bool(active_flags & re.IGNORECASE)),))
        for operation, argument in sequence:
            if operation == sre_parse.LITERAL:
                run.append(chr(argument))
                continue
            flush()
            if operation == sre_parse.SUBPATTERN:
                _, add, remove, child = argument
                found.extend(clauses(child, (active_flags | add) & ~remove))
            elif operation in {sre_parse.MAX_REPEAT, sre_parse.MIN_REPEAT}:
                minimum, _, child = argument
                if minimum:
                    found.extend(clauses(child, active_flags))
            elif operation == sre_parse.BRANCH:
                alternatives = [clauses(branch, active_flags) for branch in argument[1]]
                if alternatives and all(alternatives):
                    # At least one branch is taken. Unioning all branch literals
                    # is a deliberately weaker necessary condition.
                    found.append(tuple(set(token for branch in alternatives for group in branch for token in group)))
            if len(found) > 64:
                found = found[:64]
        flush()
        return tuple(found[:64])
    return clauses(parsed, parsed.state.flags)


@lru_cache(maxsize=2)
def regex_casefold(text):
    # Python IGNORECASE additionally equates dotted/dotless i with ASCII i.
    return text.translate({0x130: 'i', 0x131: 'i'}).casefold()


def literals_possible(pattern, flags, text):
    for group in required_literal_clauses(pattern, flags):
        if not any(literal.casefold() in regex_casefold(text) if insensitive else literal in text
                   for literal, insensitive in group):
            return False
    return True
