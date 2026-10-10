"""Adapter SDK for mapping source languages into the semantic IR."""

from abc import ABC, abstractmethod
from pathlib import Path
from utils.scan_scope import glob_source, allows_file
from dataclasses import dataclass
from typing import FrozenSet, Iterable, Tuple

from ..catalog import SemanticCatalog
from ..ir import SemanticIR
from ..plan import Capability


@dataclass(frozen=True)
class AdapterDescriptor:
    language_id: str
    adapter_name: str
    adapter_version: str
    ir_schema_version: int
    extensions: Tuple[str, ...]
    capabilities: FrozenSet[Capability]


class LanguageAdapter(ABC):
    language_id = ""
    adapter_name = ""
    adapter_version = "1"
    extensions: Tuple[str, ...] = ()
    capabilities: FrozenSet[Capability] = frozenset({Capability.ENTITIES})
    ir_schema_version = 1

    def __init__(self, catalog=None):
        self.catalog = catalog or SemanticCatalog.load()

    def supports(self, path: Path) -> bool:
        return path.suffix.lower() in self.extensions

    def descriptor(self):
        return AdapterDescriptor(
            self.language_id,
            self.adapter_name,
            self.adapter_version,
            self.ir_schema_version,
            tuple(self.extensions),
            frozenset(self.capabilities),
        )

    @abstractmethod
    def parse_file(self, path: Path) -> SemanticIR:
        raise NotImplementedError

    def parse_project(self, root: Path) -> SemanticIR:
        files = sorted(path for path in glob_source(root, "*") if path.is_file() and self.supports(path))
        parts = [self.parse_file(path) for path in files]
        if not parts:
            from ..ir import IRBuilder
            return IRBuilder(self.language_id, self.adapter_name, self.adapter_version).build(self.capabilities)
        from ..ir import SemanticIR
        return SemanticIR(
            self.language_id, self.adapter_name, self.adapter_version, 1,
            tuple(entity for part in parts for entity in part.entities),
            tuple(edge for part in parts for edge in part.edges),
            frozenset().union(*(part.capabilities for part in parts)),
            tuple(message for part in parts for message in part.diagnostics),
        )
