"""Immutable execution-plan model produced by RDL semantic analysis."""

from dataclasses import dataclass
from enum import Enum
from typing import FrozenSet, Optional, Tuple

from .ast import Confidence, EntityType, Scope, Severity


class Capability(str, Enum):
    TEXT = "text"
    PATH = "path"
    PROJECT = "project"
    ENTITIES = "entities"
    TYPES = "types"
    DATA_FLOW = "data_flow"
    CONTROL_FLOW = "control_flow"
    CALL_GRAPH = "call_graph"
    STATE = "state"
    CONCURRENCY = "concurrency"
    CONFIGURATION = "configuration"


@dataclass(frozen=True)
class PlannedBinding:
    name: str
    entity_type: EntityType
    concept: str


@dataclass(frozen=True)
class PlannedState:
    binding: str
    initial_state: str
    transitions: Tuple[Tuple[str, str, str], ...]
    violations: Tuple[Tuple[str, str], ...]


@dataclass(frozen=True)
class ExecutionPlan:
    rule_id: str
    rule_version: int
    language_version: int
    scopes: Tuple[Scope, ...]
    bindings: Tuple[PlannedBinding, ...]
    condition_kinds: Tuple[str, ...]
    states: Tuple[PlannedState, ...]
    capabilities: FrozenSet[Capability]
    report_title: str
    severity: Severity
    confidence: Confidence
    with_trace: bool
    executable: bool
    unavailable_reason: Optional[str] = None
