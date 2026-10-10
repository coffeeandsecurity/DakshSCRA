"""Formal line grammar and expression parser for RDL v2."""

import re
import shlex
from typing import List, Optional, Sequence, Tuple

from .ast import (
    BinaryExpression, BindingDeclaration, Confidence, EntityType, Predicate,
    ReportDeclaration, Rule, Scope, ScopeDeclaration, Severity,
    StateDeclaration, TransitionDeclaration, UnaryExpression, V2Document,
    ViolationDeclaration,
)
from .model import Diagnostic, DiagnosticSeverity, SourceSpan


_TOKEN_RE = re.compile(
    r'\s*(?:(?P<regex>/(?:\\.|[^/])*/[imsIMS]*)|(?P<string>"(?:\\.|[^"\\])*")|(?P<lparen>\()|(?P<rparen>\))|(?P<comma>,)|(?P<word>[^\s(),]+))'
)
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")
_TEXT_PREDICATES = {"PRESENT", "MISSING", "MATCHES", "CONTAINS", "PATH_MATCHES"}


def _diag(code, message, line, severity=DiagnosticSeverity.ERROR, hint=""):
    return Diagnostic(code, message, severity, SourceSpan(line), hint)


def _tokens(text: str, line: int, diagnostics: List[Diagnostic]) -> List[str]:
    result = []
    position = 0
    while position < len(text):
        match = _TOKEN_RE.match(text, position)
        if not match:
            diagnostics.append(_diag("RDLV2001", "invalid token", line))
            break
        token = next(value for value in match.groupdict().values() if value is not None)
        result.append(token)
        position = match.end()
    return result


class _ExpressionParser:
    def __init__(self, tokens: Sequence[str], line: int, diagnostics: List[Diagnostic]):
        self.tokens = list(tokens)
        self.line = line
        self.diagnostics = diagnostics
        self.index = 0

    def parse(self):
        expression = self._or()
        if self.index != len(self.tokens):
            self.diagnostics.append(_diag("RDLV2002", "unexpected token: {0}".format(self.tokens[self.index]), self.line))
        return expression

    def _peek(self, value=None):
        if self.index >= len(self.tokens):
            return False if value is not None else None
        token = self.tokens[self.index]
        return token.upper() == value if value is not None else token

    def _take(self):
        token = self._peek()
        if token is not None:
            self.index += 1
        return token

    def _or(self):
        left = self._and()
        while self._peek("OR"):
            self._take()
            right = self._and()
            left = BinaryExpression(SourceSpan(self.line), "OR", left, right)
        return left

    def _and(self):
        left = self._unary()
        while self._peek("AND"):
            self._take()
            right = self._unary()
            left = BinaryExpression(SourceSpan(self.line), "AND", left, right)
        return left

    def _unary(self):
        if self._peek("NOT"):
            self._take()
            return UnaryExpression(SourceSpan(self.line), "NOT", self._unary())
        if self._peek("("):
            self._take()
            expression = self._or()
            if not self._peek(")"):
                self.diagnostics.append(_diag("RDLV2003", "missing closing parenthesis", self.line))
            else:
                self._take()
            return expression
        return self._predicate()

    def _predicate(self):
        first = self._take()
        if first is None:
            self.diagnostics.append(_diag("RDLV2004", "expected predicate", self.line))
            return Predicate(SourceSpan(self.line), "INVALID")
        upper = first.upper()
        if upper in {"TEXT_MATCHES", "TEXT_MISSING"}:
            operands = (self._take(), self._take())
            if any(value is None for value in operands):
                self.diagnostics.append(_diag("RDLV2005", "text regex requires quoted pattern and flags", self.line))
            return Predicate(SourceSpan(self.line), upper, tuple(value or '""' for value in operands))
        if upper in {"FILE_NAME_IS", "FILE_PATH_GLOB", "PROJECT_OBSERVATION"}:
            operand = self._take()
            if operand is None:
                self.diagnostics.append(_diag("RDLV2005", "predicate requires quoted operand", self.line))
            return Predicate(SourceSpan(self.line), upper, (operand or '""',))
        if upper in _TEXT_PREDICATES:
            operand = self._take()
            if operand is None:
                self.diagnostics.append(_diag("RDLV2005", "{0} requires an operand".format(upper), self.line))
                operand = ""
            return Predicate(SourceSpan(self.line), upper, (operand,))
        if upper in {"PROJECT_HAS", "FILE_HAS"}:
            operand = self._take()
            if operand is None:
                self.diagnostics.append(_diag("RDLV2005", "{0} requires an operand".format(upper), self.line))
                operand = ""
            return Predicate(SourceSpan(self.line), upper, (operand,))
        if upper == "EXISTS":
            entity_token = self._take() or ""
            try:
                entity_type = EntityType(entity_token.upper())
            except ValueError:
                self.diagnostics.append(_diag("RDLV2101", "unknown entity type: {0}".format(entity_token), self.line))
                entity_type = None
            concept = ""
            binding = ""
            if self._peek("MATCHES"):
                self._take()
                concept = self._take() or ""
            if self._peek("AS"):
                self._take()
                binding = self._take() or ""
            return Predicate(SourceSpan(self.line), "EXISTS", (concept,), entity_type, binding)
        arguments = []
        while self.index < len(self.tokens) and not self._peek("AND") and not self._peek("OR") and not self._peek(")"):
            arguments.append(self._take())
        return Predicate(SourceSpan(self.line), upper, tuple(arguments))


def _parse_expression(text, line, diagnostics):
    return _ExpressionParser(_tokens(text, line, diagnostics), line, diagnostics).parse()


def parse_v2(source: str, source_name: str = "<memory>") -> V2Document:
    diagnostics: List[Diagnostic] = []
    lines = [(number, raw.strip()) for number, raw in enumerate((source or "").splitlines(), 1) if raw.strip() and not raw.lstrip().startswith("#")]
    if not lines:
        return V2Document(2, None, [_diag("RDLV1000", "empty RDL document", 1)], source_name)

    language_version = 0
    rule: Optional[Rule] = None
    pending_severity = Severity.MEDIUM
    pending_confidence = Confidence.FROM_EVIDENCE
    pending_trace = False
    report_line = 1

    for line_number, line in lines:
        upper = line.upper()
        if upper.startswith("VERSION ") and rule is None:
            try:
                language_version = int(line.split(None, 1)[1])
            except ValueError:
                diagnostics.append(_diag("RDLV1001", "language VERSION must be an integer", line_number))
            continue
        if upper.startswith("RULE "):
            if rule is not None:
                diagnostics.append(_diag("RDLV1013", "document may contain exactly one RULE declaration", line_number))
                continue
            parts = shlex.split(line)
            if len(parts) not in {2, 4} or (len(parts) == 4 and parts[2].upper() != "VERSION"):
                diagnostics.append(_diag("RDLV1002", "expected RULE <id> [VERSION <integer>]", line_number))
                continue
            rule_version = 1
            if len(parts) == 4:
                try:
                    rule_version = int(parts[3])
                except ValueError:
                    diagnostics.append(_diag("RDLV1003", "rule version must be an integer", line_number))
            rule = Rule(parts[1], rule_version, SourceSpan(line_number))
            continue
        if rule is None:
            diagnostics.append(_diag("RDLV1004", "declaration appears before RULE", line_number))
            continue
        if upper.startswith("IN "):
            parts = line.split(None, 2)
            try:
                scope = Scope(parts[1].upper())
            except ValueError:
                diagnostics.append(_diag("RDLV2102", "unknown scope: {0}".format(parts[1]), line_number))
                continue
            rule.scopes.append(ScopeDeclaration(scope, parts[2] if len(parts) > 2 else "", SourceSpan(line_number)))
        elif upper.startswith("LET "):
            match = re.match(r"^LET\s+([A-Za-z_][\w.-]*)\s+BE\s+([A-Za-z_]+)(?:\s+MATCHES\s+(.+))?$", line, re.IGNORECASE)
            if not match:
                diagnostics.append(_diag("RDLV1005", "expected LET <name> BE <entity> [MATCHES <concept>]", line_number))
                continue
            try:
                entity_type = EntityType(match.group(2).upper())
            except ValueError:
                diagnostics.append(_diag("RDLV2101", "unknown entity type: {0}".format(match.group(2)), line_number))
                continue
            rule.bindings.append(BindingDeclaration(match.group(1), entity_type, (match.group(3) or "").strip(), SourceSpan(line_number)))
        elif upper.startswith("WHEN "):
            rule.conditions.append(_parse_expression(line[5:].strip(), line_number, diagnostics))
        elif upper.startswith("REQUIRE "):
            rule.requirements.append(_parse_expression(line[8:].strip(), line_number, diagnostics))
        elif upper.startswith("STATE "):
            match = re.match(r"^STATE\s+(\S+)\s+STARTS\s+(\S+)$", line, re.IGNORECASE)
            if match:
                rule.states.append(StateDeclaration(match.group(1), match.group(2), SourceSpan(line_number)))
            else:
                diagnostics.append(_diag("RDLV1006", "expected STATE <binding> STARTS <state>", line_number))
        elif upper.startswith("TRANSITION "):
            match = re.match(r"^TRANSITION\s+(\S+)\((\S+)\)\s+FROM\s+(\S+)\s+TO\s+(\S+)$", line, re.IGNORECASE)
            if match:
                rule.transitions.append(TransitionDeclaration(match.group(1), match.group(2), match.group(3), match.group(4), SourceSpan(line_number)))
            else:
                diagnostics.append(_diag("RDLV1007", "expected TRANSITION event(binding) FROM state TO state", line_number))
        elif upper.startswith("VIOLATION "):
            match = re.match(r"^VIOLATION\s+(\S+)\((\S+)\)\s+WHILE\s+(\S+)$", line, re.IGNORECASE)
            if match:
                rule.violations.append(ViolationDeclaration(match.group(1), match.group(2), match.group(3), SourceSpan(line_number)))
            else:
                diagnostics.append(_diag("RDLV1008", "expected VIOLATION event(binding) WHILE state", line_number))
        elif upper.startswith("REPORT "):
            if rule.report is not None:
                diagnostics.append(_diag("RDLV1014", "rule may contain exactly one REPORT declaration", line_number))
                continue
            title = line[7:].strip().strip('"')
            report_line = line_number
            rule.report = ReportDeclaration(title, pending_severity, pending_confidence, pending_trace, SourceSpan(line_number))
        elif upper.startswith("SEVERITY "):
            try:
                pending_severity = Severity(line.split(None, 1)[1].upper())
                if rule.report:
                    rule.report = ReportDeclaration(rule.report.title, pending_severity, rule.report.confidence, rule.report.with_trace, rule.report.span)
            except ValueError:
                diagnostics.append(_diag("RDLV2103", "invalid severity", line_number))
        elif upper.startswith("CONFIDENCE "):
            value = line.split(None, 1)[1].upper()
            try:
                pending_confidence = Confidence(value)
                if rule.report:
                    rule.report = ReportDeclaration(rule.report.title, rule.report.severity, pending_confidence, rule.report.with_trace, rule.report.span)
            except ValueError:
                diagnostics.append(_diag("RDLV2104", "invalid confidence", line_number))
        elif upper == "WITH TRACE":
            pending_trace = True
            if rule.report:
                rule.report = ReportDeclaration(rule.report.title, rule.report.severity, rule.report.confidence, True, rule.report.span)
        else:
            diagnostics.append(_diag("RDLV1009", "unknown v2 declaration: {0}".format(line.split(None, 1)[0]), line_number))

    if language_version != 2:
        diagnostics.append(_diag("RDLV1010", "RDL v2 documents must declare VERSION 2", 1))
    if rule is None:
        diagnostics.append(_diag("RDLV1011", "missing RULE declaration", 1))
    elif rule.report is None:
        diagnostics.append(_diag("RDLV1012", "missing REPORT declaration", report_line))
    if rule and not _IDENTIFIER_RE.match(rule.rule_id):
        diagnostics.append(_diag("RDLV2105", "invalid rule identifier", rule.span.line))
    return V2Document(language_version or 2, rule, diagnostics, source_name)
