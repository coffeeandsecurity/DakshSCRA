"""Semantic validation and execution-plan lowering for RDL v2."""

from collections import defaultdict
import re
import json
from typing import Dict, Iterable, List, Set

from .ast import BinaryExpression, Predicate, UnaryExpression, V2Document
from .model import Diagnostic, DiagnosticSeverity
from .plan import Capability, ExecutionPlan, PlannedBinding, PlannedState
from .safety import regex_safety_error


_ENTITY_CAPABILITY = {
    "CALL": Capability.ENTITIES,
    "FUNCTION": Capability.ENTITIES,
    "METHOD": Capability.ENTITIES,
    "VARIABLE": Capability.ENTITIES,
    "PARAMETER": Capability.ENTITIES,
    "TYPE": Capability.TYPES,
    "CLASS": Capability.TYPES,
    "RESOURCE": Capability.STATE,
    "OBJECT": Capability.STATE,
    "ALLOCATION": Capability.STATE,
    "DEALLOCATION": Capability.STATE,
    "CONFIGURATION_ENTRY": Capability.CONFIGURATION,
    "FLOW": Capability.DATA_FLOW,
}


def _diag(code, message, span, severity=DiagnosticSeverity.ERROR, hint=""):
    return Diagnostic(code, message, severity, span, hint)


def _walk(expression):
    yield expression
    if isinstance(expression, UnaryExpression):
        yield from _walk(expression.operand)
    elif isinstance(expression, BinaryExpression):
        yield from _walk(expression.left)
        yield from _walk(expression.right)


def _predicate_capabilities(predicate: Predicate) -> Set[Capability]:
    name = predicate.name.upper()
    capabilities: Set[Capability] = set()
    if name in {"PRESENT", "MISSING", "MATCHES", "CONTAINS", "FILE_HAS"}:
        capabilities.add(Capability.TEXT)
    elif name == "PATH_MATCHES":
        capabilities.add(Capability.PATH)
    elif name == "PROJECT_HAS":
        capabilities.add(Capability.PROJECT)
    elif name == "EXISTS" and predicate.entity_type:
        capabilities.add(_ENTITY_CAPABILITY.get(predicate.entity_type.value, Capability.ENTITIES))
    if name in {"TEXT_MATCHES", "TEXT_MISSING"}:
        return {Capability.TEXT}
    if name in {"FILE_NAME_IS", "FILE_PATH_GLOB"}:
        return {Capability.PATH}
    if name == "PROJECT_OBSERVATION":
        return {Capability.PROJECT}
    if name in {"PRESENT", "MISSING", "MATCHES", "CONTAINS", "FILE_HAS", "PATH_MATCHES", "PROJECT_HAS"}:
        return capabilities
    text = " ".join((predicate.name,) + predicate.arguments).lower()
    if "flows" in text or "taint" in text or "sanitiz" in text:
        capabilities.add(Capability.DATA_FLOW)
    if any(word in text for word in ("reachable", "dominates", "post_dominates", "branch", "path_condition")):
        capabilities.add(Capability.CONTROL_FLOW)
    if any(word in text for word in ("called_by", "call_graph", "interprocedural")):
        capabilities.add(Capability.CALL_GRAPH)
    if any(word in text for word in ("memory.", "resource.", "state", "allocated", "freed", "locked", "unlocked")):
        capabilities.add(Capability.STATE)
    if any(word in text for word in ("race", "atomic", "synchron", "lock_order", "concurrency.")):
        capabilities.add(Capability.CONCURRENCY)
    if any(word in text for word in ("config.", "configuration", "terraform", "kubernetes")):
        capabilities.add(Capability.CONFIGURATION)
    return capabilities


def validate_and_lower(document: V2Document):
    diagnostics: List[Diagnostic] = list(document.diagnostics)
    rule = document.rule
    if rule is None:
        return None, diagnostics

    bindings: Dict[str, object] = {}
    for declaration in rule.bindings:
        if declaration.name in bindings:
            diagnostics.append(_diag("RDLV2201", "duplicate binding: {0}".format(declaration.name), declaration.span))
        else:
            bindings[declaration.name] = declaration
    bindings_lower = {name.lower(): value for name, value in bindings.items()}

    capabilities: Set[Capability] = set()
    condition_kinds = []
    positive_text = set()
    negative_text = set()
    for expression in rule.conditions + rule.requirements:
        for node in _walk(expression):
            if not isinstance(node, Predicate):
                continue
            condition_kinds.append(node.name.lower())
            capabilities.update(_predicate_capabilities(node))
            if node.name.upper() in {"TEXT_MATCHES", "TEXT_MISSING"}:
                try:
                    pattern, flag_text = (json.loads(value) for value in node.arguments)
                    if not isinstance(pattern, str) or not isinstance(flag_text, str) or set(flag_text) - set('ims'):
                        raise ValueError("invalid text regex or flags")
                    flags = sum(flag for letter, flag in [('i', re.I), ('m', re.M), ('s', re.S)] if letter in flag_text)
                    re.compile(pattern, flags)
                    problem = regex_safety_error(pattern)
                    if problem:
                        raise ValueError(problem)
                except (ValueError, TypeError, re.error) as exc:
                    diagnostics.append(_diag("RDLV2304", str(exc), node.span))
            if node.name.upper() in {"FILE_NAME_IS", "FILE_PATH_GLOB", "PROJECT_OBSERVATION"}:
                try:
                    if not isinstance(json.loads(node.arguments[0]), str):
                        raise ValueError('expected a quoted string')
                except (ValueError, TypeError) as exc:
                    diagnostics.append(_diag("RDLV2302", str(exc), node.span))
            if node.name.upper() in {"PRESENT", "MISSING", "MATCHES", "CONTAINS", "PATH_MATCHES"} and node.arguments:
                operand = node.arguments[0]
                if operand.startswith("/"):
                    match = re.match(r"^/(.*)/([imsIMS]*)$", operand, re.DOTALL)
                    if not match:
                        diagnostics.append(_diag("RDLV2301", "malformed delimited regex", node.span))
                    else:
                        flags = 0
                        if "i" in match.group(2).lower():
                            flags |= re.IGNORECASE
                        if "m" in match.group(2).lower():
                            flags |= re.MULTILINE
                        if "s" in match.group(2).lower():
                            flags |= re.DOTALL
                        try:
                            re.compile(match.group(1), flags)
                        except re.error as exc:
                            diagnostics.append(_diag("RDLV2302", "invalid regex: {0}".format(exc), node.span))
                        else:
                            safety_error = regex_safety_error(match.group(1))
                            if safety_error:
                                diagnostics.append(_diag("RDLV2304", safety_error, node.span))
                if node.name.upper() == "PRESENT":
                    positive_text.add(operand)
                elif node.name.upper() == "MISSING":
                    negative_text.add(operand)
            if node.binding:
                if node.binding in bindings:
                    diagnostics.append(_diag("RDLV2201", "duplicate binding: {0}".format(node.binding), node.span))
                elif node.entity_type:
                    bindings[node.binding] = PlannedBinding(node.binding, node.entity_type, node.arguments[0] if node.arguments else "")
                    bindings_lower[node.binding.lower()] = bindings[node.binding]
            source_binding = bindings_lower.get(node.name.lower())
            if source_binding and node.arguments:
                relation = node.arguments[0].upper()
                if relation in {"FLOWS", "TARGETS", "READS", "WRITES", "ALIASES"}:
                    target_name = node.arguments[-1].lower()
                    target_binding = bindings_lower.get(target_name)
                    if target_binding is None and "." not in target_name:
                        diagnostics.append(_diag("RDLV2208", "relation references undefined binding: {0}".format(node.arguments[-1]), node.span))
                    if relation == "TARGETS" and source_binding.entity_type.value != "CALL":
                        diagnostics.append(_diag("RDLV2209", "TARGETS source must be a CALL binding", node.span))
                    if relation in {"READS", "WRITES"} and source_binding.entity_type.value not in {"CALL", "STATEMENT", "EXPRESSION"}:
                        diagnostics.append(_diag("RDLV2210", "{0} source must be a CALL, STATEMENT, or EXPRESSION binding".format(relation), node.span))

    if not rule.scopes:
        diagnostics.append(_diag("RDLV2202", "v2 rules require an explicit IN scope", rule.span, hint="Use IN FILE for a text rule."))
    for scope in rule.scopes:
        if scope.scope.value == "PATH":
            capabilities.add(Capability.PATH)
        elif scope.scope.value in {"PROJECT", "DIRECTORY"}:
            capabilities.add(Capability.PROJECT)
        elif scope.scope.value == "DATA_FLOW":
            capabilities.update({Capability.ENTITIES, Capability.DATA_FLOW})
        elif scope.scope.value not in {"FILE"}:
            capabilities.add(Capability.ENTITIES)

    contradictions = positive_text & negative_text
    for operand in sorted(contradictions):
        diagnostics.append(_diag("RDLV2303", "contradictory PRESENT and MISSING predicates: {0}".format(operand), rule.span))

    state_transitions = defaultdict(list)
    state_violations = defaultdict(list)
    state_initial = {}
    for state in rule.states:
        if state.binding not in bindings:
            diagnostics.append(_diag("RDLV2203", "state references undefined binding: {0}".format(state.binding), state.span))
        if state.binding in state_initial:
            diagnostics.append(_diag("RDLV2204", "duplicate STATE declaration for: {0}".format(state.binding), state.span))
        state_initial[state.binding] = state.initial_state
        capabilities.add(Capability.STATE)
    for transition in rule.transitions:
        if transition.binding not in state_initial:
            diagnostics.append(_diag("RDLV2205", "transition has no STATE declaration: {0}".format(transition.binding), transition.span))
        state_transitions[transition.binding].append((transition.event, transition.from_state, transition.to_state))
        capabilities.add(Capability.STATE)
    for violation in rule.violations:
        if violation.binding not in state_initial:
            diagnostics.append(_diag("RDLV2206", "violation has no STATE declaration: {0}".format(violation.binding), violation.span))
        state_violations[violation.binding].append((violation.event, violation.state))
        capabilities.add(Capability.STATE)

    if not rule.conditions and not rule.violations:
        diagnostics.append(_diag("RDLV2207", "rule has neither WHEN conditions nor state violations", rule.span))
    if rule.states and not rule.violations:
        diagnostics.append(_diag("RDLV3201", "state machine defines no violation", rule.span, DiagnosticSeverity.WARNING))

    errors = any(item.severity == DiagnosticSeverity.ERROR for item in diagnostics)
    implemented = {Capability.TEXT, Capability.PATH, Capability.PROJECT}
    unavailable = sorted(item.value for item in capabilities - implemented)
    executable = not errors and not unavailable
    report = rule.report
    if report is None:
        return None, diagnostics

    planned_bindings = []
    for name, binding in bindings.items():
        if isinstance(binding, PlannedBinding):
            planned_bindings.append(binding)
        else:
            planned_bindings.append(PlannedBinding(name, binding.entity_type, binding.concept))
    states = tuple(
        PlannedState(name, initial, tuple(state_transitions[name]), tuple(state_violations[name]))
        for name, initial in sorted(state_initial.items())
    )
    plan = ExecutionPlan(
        rule.rule_id,
        rule.rule_version,
        document.language_version,
        tuple(item.scope for item in rule.scopes),
        tuple(planned_bindings),
        tuple(condition_kinds),
        states,
        frozenset(capabilities),
        report.title,
        report.severity,
        report.confidence,
        report.with_trace,
        executable,
        "requires unavailable Phase 3+ capabilities: {0}".format(", ".join(unavailable)) if unavailable else None,
    )
    return plan, diagnostics
