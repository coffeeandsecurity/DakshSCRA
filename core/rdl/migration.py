"""Conservative migration helpers for unambiguous RDL v1 rules."""

from typing import List, Tuple

from .compiler import _compile_v1
from .model import Diagnostic, DiagnosticSeverity, SourceSpan


def migrate_v1_to_v2(source: str, rule_id: str, rule_version: int = 1) -> Tuple[str, List[Diagnostic]]:
    """Convert simple v1 gates and annotate constructs requiring manual review."""

    document = _compile_v1(source)
    diagnostics = [item for item in document.diagnostics if item.severity == DiagnosticSeverity.ERROR]
    lines = ["VERSION 2", "RULE {0} VERSION {1}".format(rule_id, rule_version), "IN FILE"]
    report_title = rule_id.replace("-", " ").replace(".", " ")
    trace = False
    for instruction in document.instructions:
        kind = instruction.kind
        operand = instruction.operand
        if kind == "when_present":
            lines.append("WHEN PRESENT {0}".format(operand))
        elif kind == "when_missing":
            lines.append("WHEN MISSING {0}".format(operand))
        elif kind == "when_current_file_matches":
            lines.append("WHEN MATCHES {0}".format(operand))
        elif kind == "when_file_path_matches":
            lines[2] = "IN PATH"
            lines.append("WHEN PATH_MATCHES \"{0}\"".format(operand.replace('"', '\\"')))
        elif kind == "when_file_name_is":
            lines.append("WHEN FILE_HAS \"name:{0}\"".format(operand.replace('"', '\\"')))
        elif kind == "when_expr":
            diagnostics.append(Diagnostic(
                "RDLM2001",
                "WHEN EXPR requires manual migration because v1 regex alternation and boolean operators are ambiguous",
                DiagnosticSeverity.WARNING,
                instruction.span,
                "Rewrite the expression with v2 predicates and explicit grouping.",
            ))
            lines.append("# REVIEW v1 expression: {0}".format(operand))
        elif kind == "unless_current_file_matches":
            lines.append("WHEN NOT MATCHES {0}".format(operand))
        elif kind == "observe_project_has_glob":
            diagnostics.append(Diagnostic("RDLM2002", "project observation requires manual migration", DiagnosticSeverity.WARNING, instruction.span))
            lines.append("# REVIEW project observation: {0}".format(operand))
        elif kind == "reason" and operand:
            report_title = operand
        elif kind == "trace":
            trace = True
    lines.append('REPORT "{0}"'.format(report_title.replace('"', '\\"')))
    lines.append("SEVERITY MEDIUM")
    lines.append("CONFIDENCE FROM EVIDENCE")
    if trace:
        lines.append("WITH TRACE")
    return "\n".join(lines) + "\n", diagnostics
