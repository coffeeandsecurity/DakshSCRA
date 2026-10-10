"""Reusable conformance checks for third-party language adapters."""

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Tuple


@dataclass(frozen=True)
class ConformanceIssue:
    code: str
    message: str
    path: str = ""


def check_adapter(adapter, paths: Iterable[Path]) -> Tuple[ConformanceIssue, ...]:
    issues = []
    descriptor = adapter.descriptor()
    if not descriptor.language_id or not descriptor.adapter_name or not descriptor.adapter_version:
        issues.append(ConformanceIssue("ADAPTER001", "adapter identity and versions are required"))
    if descriptor.ir_schema_version != 1:
        issues.append(ConformanceIssue("ADAPTER002", "unsupported IR schema version"))
    for path in paths:
        path = Path(path)
        if not adapter.supports(path):
            issues.append(ConformanceIssue("ADAPTER003", "fixture extension is not supported", path.as_posix()))
            continue
        semantic_ir = adapter.parse_file(path)
        if semantic_ir.diagnostics:
            issues.extend(ConformanceIssue("ADAPTER004", message, path.as_posix()) for message in semantic_ir.diagnostics)
            continue
        if not semantic_ir.capabilities.issubset(descriptor.capabilities):
            issues.append(ConformanceIssue("ADAPTER005", "IR declares capabilities absent from descriptor", path.as_posix()))
        entity_ids = [entity.entity_id for entity in semantic_ir.entities]
        if len(entity_ids) != len(set(entity_ids)):
            issues.append(ConformanceIssue("ADAPTER006", "entity IDs must be unique", path.as_posix()))
        known = set(entity_ids)
        for entity in semantic_ir.entities:
            if entity.language != descriptor.language_id:
                issues.append(ConformanceIssue("ADAPTER007", "entity language does not match adapter", path.as_posix()))
            if entity.location.path != path.as_posix() or entity.location.line < 1:
                issues.append(ConformanceIssue("ADAPTER008", "entity provenance is invalid", path.as_posix()))
        for edge in semantic_ir.edges:
            if edge.source_id not in known or edge.target_id not in known:
                issues.append(ConformanceIssue("ADAPTER009", "edge references an unknown entity", path.as_posix()))
    return tuple(issues)
