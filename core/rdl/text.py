"""Adapter-independent execution of native v2 file and path predicates."""
import fnmatch
import json
import re
import time
from functools import lru_cache
from pathlib import Path
from utils.scan_scope import glob_source
from utils.source_cache import read_source_text, source_stat

from .ast import BinaryExpression, UnaryExpression, Predicate
from .cache import AnalysisBudgetExceeded
from .ir import SourceLocation
from .plan import Capability


@lru_cache(maxsize=4096)
def compiled_pattern(pattern, flags):
    return re.compile(pattern, flags)


def match_location(path, text, start, end):
    last = max(start, end - 1)
    return SourceLocation(str(path), text.count('\n', 0, start) + 1,
                          start - text.rfind('\n', 0, start),
                          text.count('\n', 0, last) + 1,
                          last - text.rfind('\n', 0, last) + 1)


def execute_text(document, source, project_root=None, file_text=None, max_elapsed_ms=10000, max_evidence=1000, collect_matches=False):
    from .executor import Evidence, ExecutionResult, ExecutionOutcome
    plan = document.execution_plan
    source = Path(source)
    deadline = time.perf_counter() + max_elapsed_ms / 1000
    evidence = []
    primary = []
    is_path = any(scope.value == 'PATH' for scope in plan.scopes)
    try:
        if file_text is None:
            if is_path:
                file_text = source.as_posix()
            else:
                if source_stat(source).st_size > 4 * 1024 * 1024:
                    raise AnalysisBudgetExceeded('text input exceeds 4 MiB budget')
                # Match the scanner's encoding detection rather than silently losing characters.
                from utils.file_utils import detect_encoding_type
                file_text = read_source_text(source, encoding=detect_encoding_type(source))
        if len(file_text) > 4 * 1024 * 1024:
            raise AnalysisBudgetExceeded('text input exceeds 4 MiB budget')

        def check_budget():
            if time.perf_counter() > deadline:
                raise AnalysisBudgetExceeded('text execution time budget exceeded')
            if len(evidence) >= max_evidence:
                raise AnalysisBudgetExceeded('text evidence budget exceeded')

        def evaluate(node):
            check_budget()
            if isinstance(node, BinaryExpression):
                if node.operator == 'AND':
                    return evaluate(node.left) and evaluate(node.right)
                return evaluate(node.left) or evaluate(node.right)
            if isinstance(node, UnaryExpression):
                return not evaluate(node.operand)
            if not isinstance(node, Predicate):
                raise ValueError('unsupported text expression')
            name = node.name.upper()
            operand = node.arguments[0] if node.arguments else ''
            location = None
            if name in {'TEXT_MATCHES', 'TEXT_MISSING', 'PRESENT', 'MISSING', 'MATCHES', 'CONTAINS'}:
                if name.startswith('TEXT_'):
                    pattern, flag_text = [json.loads(value) for value in node.arguments]
                else:
                    literal = re.fullmatch(r'/(.*)/([imsIMS]*)', operand, re.S)
                    pattern, flag_text = literal.groups() if literal else (operand.strip('"'), '')
                flags = sum(flag for letter, flag in [('i', re.I), ('m', re.M), ('s', re.S)] if letter in flag_text.lower())
                from .safety import literals_possible
                match = compiled_pattern(pattern, flags).search(file_text) if literals_possible(pattern, flags, file_text) else None
                matched = not bool(match) if name in {'TEXT_MISSING', 'MISSING'} else bool(match)
                if match and not is_path:
                    location = match_location(source, file_text, match.start(), match.end())
                explanation = '{} /{}/{} in the inspected {}.'.format(
                    'Required pattern' if name not in {'TEXT_MISSING', 'MISSING'} else 'Absence check for pattern',
                    pattern, flag_text, 'path' if is_path else 'file')
                if collect_matches and match and not is_path and name in {'TEXT_MATCHES', 'PRESENT', 'MATCHES', 'CONTAINS'} and not evidence:
                    for occurrence in compiled_pattern(pattern, flags).finditer(file_text):
                        check_budget()
                        primary.append(Evidence(name, True, location=match_location(source, file_text, occurrence.start(), occurrence.end()), explanation=explanation))
            elif name in {'FILE_NAME_IS', 'FILE_PATH_GLOB'}:
                value = json.loads(operand)
                matched = source.name == value if name == 'FILE_NAME_IS' else (fnmatch.fnmatch(source.as_posix(), value) or fnmatch.fnmatch(source.name, value))
                explanation = value
            elif name == 'PROJECT_OBSERVATION':
                value = json.loads(operand)
                matches = []
                for index, path in enumerate(glob_source(Path(project_root or source.parent), '*')):
                    check_budget()
                    if index >= 100000:
                        raise AnalysisBudgetExceeded('project observation file budget exceeded')
                    relative = path.relative_to(Path(project_root or source.parent)).as_posix()
                    if fnmatch.fnmatch(relative, value) or fnmatch.fnmatch(path.name, value):
                        matches.append(relative)
                    if len(matches) >= 8:
                        break
                # Observations provide context; they are deliberately not requirements.
                evidence.append(Evidence(name, bool(matches), explanation=value + ': ' + ', '.join(matches)))
                return True
            else:
                raise ValueError('unsupported text predicate: ' + name)
            evidence.append(Evidence(name, matched, location=location, explanation=explanation))
            check_budget()
            return matched

        matched = all(evaluate(expression) for expression in document.rule.conditions + document.rule.requirements)
        if matched and not evidence:
            raise ValueError('text rule has no evidence predicate')
        witnesses = tuple((anchor,) + tuple(evidence[1:]) for anchor in primary) if matched and primary else ()
        errors = ()
        return ExecutionResult(ExecutionOutcome.MATCH if matched else ExecutionOutcome.NO_MATCH, plan.rule_id, tuple(evidence), errors=errors, witnesses=witnesses)
    except AnalysisBudgetExceeded as exc:
        return ExecutionResult(ExecutionOutcome.INDETERMINATE, plan.rule_id, tuple(primary) + tuple(evidence), errors=(str(exc),))
    except (OSError, UnicodeError, ValueError, re.error) as exc:
        return ExecutionResult(ExecutionOutcome.RULE_ERROR, plan.rule_id, tuple(evidence), errors=(str(exc),))
