"""Typed syntax tree for RDL v2 source."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List, Optional, Tuple

from .model import SourceSpan


class Scope(str, Enum):
    PROJECT = "PROJECT"
    DIRECTORY = "DIRECTORY"
    FILE = "FILE"
    MODULE = "MODULE"
    CLASS = "CLASS"
    FUNCTION = "FUNCTION"
    BLOCK = "BLOCK"
    STATEMENT = "STATEMENT"
    EXPRESSION = "EXPRESSION"
    VARIABLE = "VARIABLE"
    CALL = "CALL"
    PATH = "PATH"
    DATA_FLOW = "DATA_FLOW"


class EntityType(str, Enum):
    PROGRAM = "PROGRAM"
    FILE = "FILE"
    MODULE = "MODULE"
    NAMESPACE = "NAMESPACE"
    TYPE = "TYPE"
    CLASS = "CLASS"
    FUNCTION = "FUNCTION"
    METHOD = "METHOD"
    PARAMETER = "PARAMETER"
    VARIABLE = "VARIABLE"
    EXPRESSION = "EXPRESSION"
    STATEMENT = "STATEMENT"
    CALL = "CALL"
    ASSIGNMENT = "ASSIGNMENT"
    RETURN = "RETURN"
    CONDITION = "CONDITION"
    BRANCH = "BRANCH"
    LOOP = "LOOP"
    ALLOCATION = "ALLOCATION"
    DEALLOCATION = "DEALLOCATION"
    OBJECT = "OBJECT"
    FIELD = "FIELD"
    LITERAL = "LITERAL"
    RESOURCE = "RESOURCE"
    CONFIGURATION_ENTRY = "CONFIGURATION_ENTRY"
    FLOW = "FLOW"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    FROM_EVIDENCE = "FROM EVIDENCE"


@dataclass(frozen=True)
class Expression:
    span: SourceSpan


@dataclass(frozen=True)
class Predicate(Expression):
    name: str
    arguments: Tuple[str, ...] = ()
    entity_type: Optional[EntityType] = None
    binding: str = ""


@dataclass(frozen=True)
class UnaryExpression(Expression):
    operator: str
    operand: Expression


@dataclass(frozen=True)
class BinaryExpression(Expression):
    operator: str
    left: Expression
    right: Expression


@dataclass(frozen=True)
class ScopeDeclaration:
    scope: Scope
    selector: str
    span: SourceSpan


@dataclass(frozen=True)
class BindingDeclaration:
    name: str
    entity_type: EntityType
    concept: str
    span: SourceSpan


@dataclass(frozen=True)
class StateDeclaration:
    binding: str
    initial_state: str
    span: SourceSpan


@dataclass(frozen=True)
class TransitionDeclaration:
    event: str
    binding: str
    from_state: str
    to_state: str
    span: SourceSpan


@dataclass(frozen=True)
class ViolationDeclaration:
    event: str
    binding: str
    state: str
    span: SourceSpan


@dataclass(frozen=True)
class ReportDeclaration:
    title: str
    severity: Severity
    confidence: Confidence
    with_trace: bool
    span: SourceSpan


@dataclass
class Rule:
    rule_id: str
    rule_version: int
    span: SourceSpan
    scopes: List[ScopeDeclaration] = field(default_factory=list)
    bindings: List[BindingDeclaration] = field(default_factory=list)
    conditions: List[Expression] = field(default_factory=list)
    requirements: List[Expression] = field(default_factory=list)
    states: List[StateDeclaration] = field(default_factory=list)
    transitions: List[TransitionDeclaration] = field(default_factory=list)
    violations: List[ViolationDeclaration] = field(default_factory=list)
    report: Optional[ReportDeclaration] = None


@dataclass
class V2Document:
    language_version: int
    rule: Optional[Rule]
    diagnostics: list
    source_name: str = "<memory>"
    execution_plan: Any = None

    @property
    def valid(self):
        from .model import DiagnosticSeverity
        return self.rule is not None and not any(item.severity == DiagnosticSeverity.ERROR for item in self.diagnostics)
