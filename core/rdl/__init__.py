"""RDL compilation and validation foundations.

The production evaluator remains ``core.rdl_engine`` during the compatibility
phase.  This package provides a side-effect-free front end that can validate
legacy rules before execution and evolve independently toward RDL v2.
"""

from .compiler import compile_rdl, lint_rdl
from .model import Diagnostic, RdlDocument, RdlInstruction, SourceSpan
from .parser_v2 import parse_v2
from .semantics import validate_and_lower
from .migration import migrate_v1_to_v2
from .executor import ExecutionOutcome, SemanticExecutor
from .cfg import CFGEdge, CFGNode, ControlFlowGraph, ControlPath, PythonControlFlowProvider
from .state import StateEvent, StateMachineAnalyzer, StateStep, StateTrace
from .callgraph import CallGraph, CallGraphEdge, PythonCallGraphProvider, UnresolvedCall
from .cache import AnalysisBudgetExceeded, CacheStats, IncrementalIRCache
from .shadow import ShadowRunner

__all__ = [
    "Diagnostic",
    "RdlDocument",
    "RdlInstruction",
    "SourceSpan",
    "compile_rdl",
    "lint_rdl",
    "parse_v2",
    "validate_and_lower",
    "migrate_v1_to_v2",
    "ExecutionOutcome",
    "SemanticExecutor",
    "CFGEdge",
    "CFGNode",
    "ControlFlowGraph",
    "ControlPath",
    "PythonControlFlowProvider",
    "StateEvent",
    "StateMachineAnalyzer",
    "StateStep",
    "StateTrace",
    "CallGraph",
    "CallGraphEdge",
    "PythonCallGraphProvider",
    "UnresolvedCall",
    "AnalysisBudgetExceeded",
    "CacheStats",
    "IncrementalIRCache",
    "ShadowRunner",
]
