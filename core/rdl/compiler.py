"""Compatibility compiler and linter for RDL v1.

This module intentionally does not execute rules.  It turns the implicit
line-oriented v1 syntax into a typed document, reports rule errors separately
from no-match outcomes, and establishes the front-end boundary used by RDL v2.
"""

import re
from typing import List, Optional, Tuple

from .model import (
    Diagnostic,
    DiagnosticSeverity,
    RdlDocument,
    RdlInstruction,
    SourceSpan,
)


_COMMANDS: Tuple[Tuple[str, str], ...] = (
    ("UNLESS CURRENT_FILE_MATCHES ", "unless_current_file_matches"),
    ("OBSERVE PROJECT_HAS_GLOB ", "observe_project_has_glob"),
    ("WHEN CURRENT_FILE_MATCHES ", "when_current_file_matches"),
    ("WHEN FILE_PATH_MATCHES ", "when_file_path_matches"),
    ("WHEN FILE_NAME_IS ", "when_file_name_is"),
    ("WHEN PRESENT ", "when_present"),
    ("WHEN MISSING ", "when_missing"),
    ("WHEN EXPR ", "when_expr"),
    ("REPORT AS ", "report_as"),
    ("FAIL_REASON ", "fail_reason"),
    ("REASON ", "reason"),
    ("TRACE ", "trace"),
)

_REGEX_KINDS = {
    "unless_current_file_matches",
    "when_current_file_matches",
    "when_present",
    "when_missing",
}
_EXPR_PREDICATE_RE = re.compile(r"(?:^|&&|\|\|)\s*!?\s*(PRESENT|MISSING|EXISTS)\s*:(.*?)(?=(?:&&|\|\|)|$)", re.IGNORECASE)
_DELIMITED_REGEX_RE = re.compile(r"^/(.*)/([a-zA-Z]*)$", re.DOTALL)


def _diagnostic(code: str, message: str, severity: DiagnosticSeverity, line: int, hint: str = "") -> Diagnostic:
    return Diagnostic(code, message, severity, SourceSpan(line), hint)


def _regex_parts(operand: str) -> Tuple[str, int, Optional[str]]:
    match = _DELIMITED_REGEX_RE.match(operand.strip())
    if not match:
        return operand.strip(), re.IGNORECASE | re.MULTILINE, None
    pattern, flags_text = match.groups()
    invalid = set(flags_text.lower()) - set("ims")
    if invalid:
        # Match the v1 evaluator: a slash-prefixed bare expression such as
        # /NXCOMPAT|/GS is not a delimited literal when the suffix is not made
        # exclusively of supported flag letters.
        return operand.strip(), re.IGNORECASE | re.MULTILINE, None
    flags = 0
    if "i" in flags_text.lower():
        flags |= re.IGNORECASE
    if "m" in flags_text.lower():
        flags |= re.MULTILINE
    if "s" in flags_text.lower():
        flags |= re.DOTALL
    return pattern, flags, None


def _validate_regex(operand: str, line: int, diagnostics: List[Diagnostic]) -> None:
    pattern, flags, flag_error = _regex_parts(operand)
    if flag_error:
        diagnostics.append(_diagnostic("RDL104", flag_error, DiagnosticSeverity.ERROR, line))
        return
    if not pattern:
        diagnostics.append(_diagnostic("RDL102", "regex operand is empty", DiagnosticSeverity.ERROR, line))
        return
    try:
        re.compile(pattern, flags)
    except re.error as exc:
        diagnostics.append(_diagnostic("RDL103", "invalid regex: {0}".format(exc), DiagnosticSeverity.ERROR, line))


def _validate_expression(operand: str, line: int, diagnostics: List[Diagnostic]) -> None:
    if not operand.strip():
        diagnostics.append(_diagnostic("RDL105", "boolean expression is empty", DiagnosticSeverity.ERROR, line))
        return
    matches = list(_EXPR_PREDICATE_RE.finditer(operand))
    if not matches:
        diagnostics.append(_diagnostic("RDL106", "expression has no recognized predicate", DiagnosticSeverity.ERROR, line))
        return
    for match in matches:
        _validate_regex(match.group(2).strip(), line, diagnostics)


def compile_rdl(source: str, source_name: str = "<memory>"):
    """Compile an RDL v1 or v2 document without executing it."""

    first_command = next(
        (line.strip() for line in (source or "").splitlines() if line.strip() and not line.lstrip().startswith("#")),
        "",
    )
    if first_command.upper() == "VERSION 2":
        from .parser_v2 import parse_v2
        from .semantics import validate_and_lower

        document = parse_v2(source, source_name)
        plan, diagnostics = validate_and_lower(document)
        document.diagnostics = diagnostics
        document.execution_plan = plan
        return document

    return _compile_v1(source, source_name)


def _compile_v1(source: str, source_name: str = "<memory>") -> RdlDocument:
    """Parse and validate an RDL v1 document without executing it."""

    diagnostics: List[Diagnostic] = []
    instructions: List[RdlInstruction] = []
    version: Optional[int] = None

    for line_number, raw_line in enumerate((source or "").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        upper = line.upper()
        if upper.startswith("VERSION "):
            value = line[len("VERSION "):].strip()
            if version is not None:
                diagnostics.append(_diagnostic("RDL002", "VERSION may only be declared once", DiagnosticSeverity.ERROR, line_number))
                continue
            try:
                version = int(value)
            except ValueError:
                diagnostics.append(_diagnostic("RDL003", "VERSION must be an integer", DiagnosticSeverity.ERROR, line_number))
                continue
            instructions.append(RdlInstruction("version", value, SourceSpan(line_number)))
            continue

        command = next(((prefix, kind) for prefix, kind in _COMMANDS if upper.startswith(prefix)), None)
        if command is None:
            diagnostics.append(_diagnostic(
                "RDL101",
                "unknown instruction: {0}".format(line.split(None, 1)[0]),
                DiagnosticSeverity.ERROR,
                line_number,
                "Unknown instructions are ignored by the v1 runtime and can create silent false negatives.",
            ))
            continue
        prefix, kind = command
        operand = line[len(prefix):].strip()
        if not operand:
            diagnostics.append(_diagnostic("RDL102", "{0} requires an operand".format(prefix.strip()), DiagnosticSeverity.ERROR, line_number))
        elif kind in _REGEX_KINDS:
            _validate_regex(operand, line_number, diagnostics)
        elif kind == "when_expr":
            _validate_expression(operand, line_number, diagnostics)
        instructions.append(RdlInstruction(kind, operand, SourceSpan(line_number)))

    if version is None:
        diagnostics.append(_diagnostic("RDL001", "missing VERSION declaration", DiagnosticSeverity.ERROR, 1, "Declare VERSION 1 for existing rules."))
        version = 1
    elif version != 1:
        diagnostics.append(_diagnostic("RDL004", "unsupported RDL version: {0}".format(version), DiagnosticSeverity.ERROR, 1))

    kinds = [instruction.kind for instruction in instructions]
    if not any(kind.startswith("when_") for kind in kinds):
        diagnostics.append(_diagnostic("RDL201", "rule has no gating predicate and will always pass", DiagnosticSeverity.WARNING, 1))
    if "report_as" not in kinds:
        diagnostics.append(_diagnostic("RDL202", "REPORT AS is omitted; runtime default is area_of_interest", DiagnosticSeverity.WARNING, 1))
    if kinds.count("report_as") > 1:
        diagnostics.append(_diagnostic("RDL203", "multiple REPORT AS declarations use last-write-wins behavior", DiagnosticSeverity.WARNING, 1))
    if any(kind in {"when_present", "when_missing", "when_expr"} for kind in kinds):
        diagnostics.append(_diagnostic(
            "RDL301",
            "text predicates use whole-file scope in RDL v1",
            DiagnosticSeverity.INFO,
            1,
            "Use explicit FILE/FUNCTION/entity scope when migrating this rule to RDL v2.",
        ))

    return RdlDocument(version, instructions, diagnostics, source_name)


def lint_rdl(source: str, source_name: str = "<memory>") -> List[Diagnostic]:
    return compile_rdl(source, source_name).diagnostics
