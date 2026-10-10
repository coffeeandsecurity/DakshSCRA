"""Language-neutral semantic intermediate representation for RDL."""

from dataclasses import dataclass, field
from functools import cached_property
from enum import Enum
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Tuple

from .ast import EntityType
from .plan import Capability


class EdgeKind(str, Enum):
    CONTAINS = "contains"
    DECLARES = "declares"
    READS = "reads"
    WRITES = "writes"
    CALLS = "calls"
    RETURNS = "returns"
    ASSIGNS = "assigns"
    ARGUMENT = "argument"
    RECEIVER = "receiver"
    IMPORTS = "imports"
    DERIVES_FROM = "derives_from"
    ALIASES = "aliases"


@dataclass(frozen=True)
class SourceLocation:
    path: str
    line: int
    column: int
    end_line: int
    end_column: int


@dataclass(frozen=True)
class SemanticEntity:
    entity_id: str
    kind: EntityType
    name: str
    qualified_name: str
    location: SourceLocation
    language: str
    native_kind: str
    type_name: str = ""
    concepts: FrozenSet[str] = frozenset()
    attributes: Tuple[Tuple[str, Any], ...] = ()

    def attribute(self, name: str, default=None):
        return dict(self.attributes).get(name, default)


@dataclass(frozen=True)
class SemanticEdge:
    source_id: str
    target_id: str
    kind: EdgeKind
    attributes: Tuple[Tuple[str, Any], ...] = ()


@dataclass(frozen=True)
class SemanticIR:
    language: str
    adapter_name: str
    adapter_version: str
    schema_version: int
    entities: Tuple[SemanticEntity, ...]
    edges: Tuple[SemanticEdge, ...]
    capabilities: FrozenSet[Capability]
    diagnostics: Tuple[str, ...] = ()

    @cached_property
    def concept_index(self):
        """Exact semantic candidates in original order; no lexical approximation."""
        index = {}
        for entity in self.entities:
            for concept in entity.concepts:
                index.setdefault(concept, []).append(entity)
        return {concept: tuple(entities) for concept, entities in index.items()}

    def entities_of_type(self, kind: EntityType) -> Tuple[SemanticEntity, ...]:
        return tuple(entity for entity in self.entities if entity.kind == kind)

    def entity(self, entity_id: str) -> Optional[SemanticEntity]:
        return next((entity for entity in self.entities if entity.entity_id == entity_id), None)


class IRBuilder:
    """Mutable construction helper; adapters return only immutable SemanticIR."""

    def __init__(self, language: str, adapter_name: str, adapter_version: str):
        self.language = language
        self.adapter_name = adapter_name
        self.adapter_version = adapter_version
        self.entities: List[SemanticEntity] = []
        self.edges: List[SemanticEdge] = []
        self.diagnostics: List[str] = []
        self._counter = 0

    def add_entity(self, kind, name, qualified_name, location, native_kind, type_name="", concepts=(), attributes=None):
        self._counter += 1
        entity_id = "{0}:{1}:{2}:{3}".format(self.language, location.path, location.line, self._counter)
        entity = SemanticEntity(
            entity_id, kind, name, qualified_name, location, self.language,
            native_kind, type_name, frozenset(concepts),
            tuple(sorted((attributes or {}).items())),
        )
        self.entities.append(entity)
        return entity

    def add_edge(self, source, target, kind, attributes=None):
        self.edges.append(SemanticEdge(source.entity_id, target.entity_id, kind, tuple(sorted((attributes or {}).items()))))

    def build(self, capabilities):
        return SemanticIR(
            self.language, self.adapter_name, self.adapter_version, 1,
            tuple(self.entities), tuple(self.edges), frozenset(capabilities),
            tuple(self.diagnostics),
        )
