"""Typed, language-neutral front-end model for RDL source documents."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class DiagnosticSeverity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True)
class SourceSpan:
    line: int
    column: int = 1
    end_column: Optional[int] = None


@dataclass(frozen=True)
class Diagnostic:
    code: str
    message: str
    severity: DiagnosticSeverity
    span: SourceSpan
    hint: str = ""


@dataclass(frozen=True)
class RdlInstruction:
    """One normalized v1 instruction.

    ``kind`` is stable and machine-oriented; ``operand`` retains author text
    so compatibility execution does not silently alter regex semantics.
    """

    kind: str
    operand: str
    span: SourceSpan
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RdlDocument:
    version: int
    instructions: List[RdlInstruction]
    diagnostics: List[Diagnostic]
    source_name: str = "<memory>"

    @property
    def valid(self) -> bool:
        return not any(item.severity == DiagnosticSeverity.ERROR for item in self.diagnostics)

    def diagnostics_by_severity(self, severity: DiagnosticSeverity) -> List[Diagnostic]:
        return [item for item in self.diagnostics if item.severity == severity]
