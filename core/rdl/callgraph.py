"""Bounded Python call graphs and interprocedural flow transfers."""

import ast
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .ast import EntityType
from .flow import DataFlowGraph, FlowEdge
from .project import local_imports


@dataclass(frozen=True)
class CallGraphEdge:
    caller_id: str
    call_id: str
    callee_id: str
    resolution: str


@dataclass(frozen=True)
class UnresolvedCall:
    call_id: str
    callee: str
    reason: str


class CallGraph:
    def __init__(self, functions, edges, unresolved=(), truncated=False, max_depth=12):
        self.functions = dict(functions)
        self.edges = tuple(edges)
        self.unresolved = tuple(unresolved)
        self.truncated = truncated
        self.max_depth = max_depth

    def reachable(self, caller_id, callee_id):
        adjacency = {}
        for edge in self.edges:
            adjacency.setdefault(edge.caller_id, []).append(edge.callee_id)
        queue = deque([(caller_id, 0)])
        visited = {caller_id}
        while queue:
            current, depth = queue.popleft()
            if current == callee_id:
                return True
            if depth >= self.max_depth:
                continue
            for target in adjacency.get(current, ()):
                if target not in visited:
                    visited.add(target)
                    queue.append((target, depth + 1))
        return False

    def augment_flow(self, graph: DataFlowGraph, semantic_ir) -> DataFlowGraph:
        resolved_calls = {edge.call_id for edge in self.edges}
        edges = [edge for edge in graph.edges if not (edge.kind == "argument" and edge.target_id in resolved_calls)]
        incoming = {}
        for edge in graph.edges:
            if edge.kind == "argument":
                incoming.setdefault(edge.target_id, []).append(edge)
        contains = {}
        for edge in semantic_ir.edges:
            if edge.kind.value == "contains":
                contains.setdefault(edge.source_id, []).append(edge.target_id)
        for call_edge in self.edges:
            parameters = [
                entity for entity in semantic_ir.entities
                if entity.kind == EntityType.PARAMETER
                and entity.location.path == self.functions[call_edge.callee_id].location.path
                and self.functions[call_edge.callee_id].location.line <= entity.location.line <= self.functions[call_edge.callee_id].location.end_line
            ]
            returns = [
                entity.entity_id for entity in semantic_ir.entities
                if entity.kind == EntityType.RETURN
                and entity.location.path == self.functions[call_edge.callee_id].location.path
                and self.functions[call_edge.callee_id].location.line <= entity.location.line <= self.functions[call_edge.callee_id].location.end_line
            ]
            for incoming_edge in incoming.get(call_edge.call_id, ()):
                argument = incoming_edge.argument
                targets = ([parameters[argument]] if isinstance(argument, int) and argument < len(parameters)
                           else [p for p in parameters if p.name == argument])
                for parameter in targets:
                    edges.append(FlowEdge(incoming_edge.source_id, parameter.entity_id, "argument-parameter", callsite=call_edge.call_id))
            for returned in returns:
                edges.append(FlowEdge(returned, call_edge.call_id, "return-call", callsite=call_edge.call_id))
        unique = {(edge.source_id, edge.target_id, edge.kind, edge.callsite): edge for edge in edges}
        return DataFlowGraph(graph.entities, tuple(unique.values()), graph.max_path_depth, graph.truncated)


class PythonCallGraphProvider:
    def __init__(self, max_edges=100000, max_depth=12):
        self.max_edges = max_edges
        self.max_depth = max_depth

    def build(self, root: Path, semantic_ir) -> CallGraph:
        root = root if root.is_dir() else root.parent
        imports = {}
        for path in {entity.location.path for entity in semantic_ir.entities}:
            try:
                imports[path] = local_imports(Path(path), root)
            except (OSError, SyntaxError, UnicodeError):
                imports[path] = {}
        functions = {entity.entity_id: entity for entity in semantic_ir.entities if entity.kind in {EntityType.FUNCTION, EntityType.METHOD}}
        calls = [entity for entity in semantic_ir.entities if entity.kind == EntityType.CALL]
        by_name = {}
        for function in functions.values():
            by_name.setdefault(function.name, []).append(function)
        edges = []
        unresolved = []
        truncated = False
        for call in calls:
            caller_candidates = [
                function for function in functions.values()
                if function.location.path == call.location.path
                and function.location.line <= call.location.line <= function.location.end_line
            ]
            caller = min(caller_candidates, key=lambda item: item.location.end_line - item.location.line) if caller_candidates else None
            if caller is None:
                caller = next((entity for entity in semantic_ir.entities
                               if entity.kind == EntityType.MODULE and entity.location.path == call.location.path), None)
            callee_text = call.attribute("callee", "")
            name = callee_text.rsplit(".", 1)[-1]
            candidates = [item for item in by_name.get(name, ()) if item.location.path == call.location.path]
            if '.' in callee_text:
                prefix = callee_text.rsplit('.', 1)[0]
                candidates = [item for item in candidates if item.qualified_name == callee_text
                              or prefix == Path(item.location.path).stem]
            resolution = "same-file"
            if len(candidates) != 1:
                candidates = []
                for alias, (target_path, symbol) in imports.get(call.location.path, {}).items():
                    if callee_text == alias or callee_text.startswith(alias + '.'):
                        target_name = symbol or callee_text[len(alias):].lstrip('.')
                        candidates.extend(item for item in by_name.get(target_name, ())
                                          if Path(item.location.path).resolve() == target_path
                                          and item.qualified_name == target_name)
                resolution = "project-import"
            if caller and len(candidates) == 1:
                if len(edges) >= self.max_edges:
                    truncated = True
                    break
                edges.append(CallGraphEdge(caller.entity_id, call.entity_id, candidates[0].entity_id, resolution))
            elif caller and (candidates or len(by_name.get(name, ())) > 1):
                unresolved.append(UnresolvedCall(call.entity_id, callee_text, "ambiguous target"))
            elif caller and name not in {"print", "len", "str", "bytes", "int", "open"}:
                unresolved.append(UnresolvedCall(call.entity_id, callee_text, "target not in analyzed project"))
        return CallGraph(functions, edges, unresolved, truncated, self.max_depth)
