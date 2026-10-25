"""Normalized bounded intraprocedural data-flow graph services."""

import ast
from collections import deque
from functools import cached_property
from dataclasses import dataclass
from pathlib import Path
from utils.source_cache import read_source_text
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

from .ast import EntityType
from .ir import SemanticEntity, SemanticIR
from .cache import AnalysisBudgetExceeded


def _python_qualified_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _python_qualified_name(node.value)
        return "{0}.{1}".format(prefix, node.attr) if prefix else node.attr
    return ""


@dataclass(frozen=True)
class FlowEdge:
    source_id: str
    target_id: str
    kind: str
    argument: object = None
    callsite: str = ''


@dataclass(frozen=True)
class FlowPath:
    entity_ids: Tuple[str, ...]
    edge_kinds: Tuple[str, ...]


@dataclass(frozen=True)
class DataFlowGraph:
    entities: Dict[str, SemanticEntity]
    edges: Tuple[FlowEdge, ...]
    max_path_depth: int = 64
    truncated: bool = False

    @cached_property
    def adjacency(self):
        adjacency = {}
        for edge in self.edges:
            adjacency.setdefault(edge.source_id, []).append((edge.target_id, edge.kind, edge.callsite))
        return adjacency

    @cached_property
    def reverse_adjacency(self):
        result = {}
        for edge in self.edges:
            result.setdefault(edge.target_id, set()).add(edge.source_id)
        return result

    @cached_property
    def source_cache(self):
        return {}

    def possible_sources(self, target_id):
        """Cheap over-approximation; balanced call paths still require find_path."""
        if target_id not in self.source_cache:
            pending, seen = [target_id], set()
            while pending:
                current = pending.pop()
                if current in seen:
                    continue
                seen.add(current)
                pending.extend(self.reverse_adjacency.get(current, ()))
            if len(seen) + sum(len(value) for value in self.source_cache.values()) > 200000:
                self.source_cache.clear()
            self.source_cache[target_id] = seen
        return self.source_cache[target_id]

    def find_path(self, source_id: str, target_id: str, excluded_concepts=()) -> Optional[FlowPath]:
        if source_id not in self.possible_sources(target_id):
            return None
        adjacency = self.adjacency
        queue = deque([(source_id, (source_id,), (), ())])
        visited = {(source_id, ())}
        exhausted = False
        while queue:
            current, nodes, kinds, callstack = queue.popleft()
            if current == target_id:
                return FlowPath(nodes, kinds)
            if len(nodes) > self.max_path_depth:
                exhausted = exhausted or bool(adjacency.get(current))
                continue
            for next_id, kind, callsite in adjacency.get(current, []):
                if next_id not in self.possible_sources(target_id):
                    continue
                if self.entities[next_id].concepts.intersection(excluded_concepts):
                    continue
                next_stack = callstack
                if kind == 'argument-parameter' and callsite:
                    if callsite in callstack:
                        exhausted = True
                        continue
                    next_stack = callstack + (callsite,)
                elif kind == 'return-call' and callsite and callstack:
                    if callstack[-1] != callsite:
                        continue
                    next_stack = callstack[:-1]
                identity = (next_id, next_stack)
                if identity in visited:
                    continue
                visited.add(identity)
                if len(visited) > 10000:
                    raise AnalysisBudgetExceeded('data-flow search budget exceeded')
                queue.append((next_id, nodes + (next_id,), kinds + (kind,), next_stack))
        if exhausted:
            raise AnalysisBudgetExceeded('data-flow path depth budget exceeded')
        return None

    def concepts_on_path(self, path: FlowPath) -> FrozenSet[str]:
        concepts = set()
        for entity_id in path.entity_ids:
            entity = self.entities.get(entity_id)
            if entity:
                concepts.update(entity.concepts)
        return frozenset(concepts)


class PythonDataFlowProvider:
    """Build conservative intraprocedural flow edges from Python AST syntax."""

    def __init__(self, max_edges=500000, max_path_depth=64):
        self.max_edges = max_edges
        self.max_path_depth = max_path_depth

    def build(self, root: Path, semantic_ir: SemanticIR) -> DataFlowGraph:
        entities = {entity.entity_id: entity for entity in semantic_ir.entities}
        by_location = {}
        for entity in semantic_ir.entities:
            key = (entity.location.path, entity.location.line, entity.location.column, entity.kind)
            by_location.setdefault(key, []).append(entity)
        edges: List[FlowEdge] = []
        paths = sorted({Path(entity.location.path) for entity in semantic_ir.entities})
        for path in paths:
            try:
                tree = ast.parse(read_source_text(path, encoding="utf-8"), filename=str(path))
            except (OSError, UnicodeError, SyntaxError):
                continue
            _PythonFlowWalker(path, by_location, edges, self.max_edges).walk(tree)
            if len(edges) >= self.max_edges:
                break
        unique = {(edge.source_id, edge.target_id, edge.kind, edge.argument): edge for edge in edges}
        return DataFlowGraph(entities, tuple(unique.values()), self.max_path_depth, len(edges) >= self.max_edges)


class _PythonFlowWalker:
    def __init__(self, path, by_location, edges, max_edges):
        self.path = path.as_posix()
        self.by_location = by_location
        self.edges = edges
        self.max_edges = max_edges
        self.environments: List[Dict[str, str]] = []

    def entity(self, node, kind):
        key = (self.path, int(getattr(node, "lineno", 1)), int(getattr(node, "col_offset", 0)) + 1, kind)
        values = self.by_location.get(key, ())
        if kind == EntityType.CALL and len(values) > 1 and isinstance(node, ast.Call):
            callee = _python_qualified_name(node.func) or "<dynamic>"
            matched = next((entity for entity in values if entity.attribute("callee") == callee), None)
            if matched:
                return matched
        return values[0] if values else None

    def edge(self, source_id, target_id, kind, argument=None):
        if source_id and target_id and source_id != target_id and len(self.edges) < self.max_edges:
            self.edges.append(FlowEdge(source_id, target_id, kind, argument))

    def walk(self, tree):
        self.environments.append({})
        for statement in tree.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.function(statement)
            elif isinstance(statement, ast.ClassDef):
                for method in statement.body:
                    if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self.function(method)
            else:
                self.statement(statement)
        self.environments.pop()

    def function(self, node):
        environment = {}
        self.environments.append(environment)
        for argument in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
            entity = self.entity(argument, EntityType.PARAMETER)
            if entity:
                environment[argument.arg] = {entity.entity_id}
        for statement in node.body:
            self.statement(statement)
            if isinstance(statement, (ast.Return, ast.Raise)):
                break
        self.environments.pop()

    @property
    def environment(self):
        return self.environments[-1]

    def statement(self, node):
        if isinstance(node, ast.Assign):
            sources = self.expression(node.value)
            for target in node.targets:
                self.assign_target(target, sources)
        elif isinstance(node, ast.AnnAssign):
            sources = self.expression(node.value) if node.value else set()
            self.assign_target(node.target, sources)
        elif isinstance(node, ast.AugAssign):
            sources = self.expression(node.value) | self.expression(node.target)
            self.assign_target(node.target, sources)
        elif isinstance(node, ast.Return):
            sources = self.expression(node.value) if node.value else set()
            target = self.entity(node, EntityType.RETURN)
            for source in sources:
                self.edge(source, target.entity_id if target else "", "return")
        elif isinstance(node, ast.Expr):
            self.expression(node.value)
        elif isinstance(node, ast.If):
            self.expression(node.test)
            if isinstance(node.test, ast.Constant):
                for statement in node.body if node.test.value else node.orelse:
                    self.statement(statement)
                    if isinstance(statement, (ast.Return, ast.Raise)):
                        break
                return
            before = dict(self.environment)
            for statement in node.body:
                self.statement(statement)
                if isinstance(statement, (ast.Return, ast.Raise)):
                    break
            body_env = dict(self.environment)
            body_exits = bool(node.body and isinstance(node.body[-1], (ast.Return, ast.Raise)))
            self.environments[-1] = dict(before)
            for statement in node.orelse:
                self.statement(statement)
                if isinstance(statement, (ast.Return, ast.Raise)):
                    break
            else_env = dict(self.environment)
            else_exits = bool(node.orelse and isinstance(node.orelse[-1], (ast.Return, ast.Raise)))
            if body_exits:
                body_env = {}
            if else_exits:
                else_env = {}
            merged = {key: body_env.get(key, set()) | else_env.get(key, set()) for key in body_env.keys() | else_env.keys()}
            self.environments[-1] = merged
        elif isinstance(node, (ast.For, ast.While)):
            if isinstance(node, ast.While) and isinstance(node.test, ast.Constant) and not node.test.value:
                for statement in node.orelse:
                    self.statement(statement)
                return
            before = dict(self.environment)
            if isinstance(node, ast.For):
                sources = self.expression(node.iter)
                self.assign_target(node.target, sources)
            else:
                self.expression(node.test)
            for statement in node.body:
                self.statement(statement)
            for statement in node.orelse:
                self.statement(statement)
            after = self.environment
            self.environments[-1] = {key: before.get(key, set()) | after.get(key, set()) for key in before.keys() | after.keys()}
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                sources = self.expression(item.context_expr)
                if item.optional_vars:
                    self.assign_target(item.optional_vars, sources)
            for statement in node.body:
                self.statement(statement)
        elif isinstance(node, ast.Try):
            before = dict(self.environment)
            for statement in node.body + node.orelse:
                self.statement(statement)
            branches = [dict(self.environment)]
            for handler in node.handlers:
                self.environments[-1] = dict(before)
                for statement in handler.body:
                    self.statement(statement)
                branches.append(dict(self.environment))
            keys = set().union(*(branch.keys() for branch in branches))
            self.environments[-1] = {key: set().union(*(branch.get(key, set()) for branch in branches)) for key in keys}
            for statement in node.finalbody:
                self.statement(statement)

    def assign_target(self, target, sources):
        if isinstance(target, (ast.Name, ast.Attribute)):
            entity = self.entity(target, EntityType.VARIABLE)
            if entity:
                for source in sources:
                    self.edge(source, entity.entity_id, "assignment")
                self.environment[_python_qualified_name(target)] = {entity.entity_id}
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self.assign_target(item, sources)

    def expression(self, node):
        if node is None:
            return set()
        if isinstance(node, ast.Name):
            entity = self.entity(node, EntityType.VARIABLE)
            if entity and isinstance(node.ctx, ast.Load):
                for previous in self.environment.get(node.id, ()):
                    self.edge(previous, entity.entity_id, "reference")
            return {entity.entity_id} if entity else set()
        if isinstance(node, ast.Call):
            sources = set()
            call = self.entity(node, EntityType.CALL)
            sensitive_arguments = call.attribute('sensitive_arguments') if call else None
            if isinstance(node.func, ast.Attribute) and sensitive_arguments is None:
                sources.update(self.expression(node.func.value))
            for index, argument in enumerate(node.args):
                selected_elements = call.attribute('argv_taint_indices') if call and index == 0 else None
                if selected_elements is not None and isinstance(argument, (ast.List, ast.Tuple)):
                    values = set().union(*(self.expression(value) for position, value in enumerate(argument.elts) if position in selected_elements))
                else:
                    values = self.expression(argument)
                if sensitive_arguments is None or index in sensitive_arguments:
                    sources.update(values)
                    if call:
                        for source in values:
                            self.edge(source, call.entity_id, 'argument', index)
            for keyword in node.keywords:
                selected_elements = call.attribute('argv_taint_indices') if call and keyword.arg == 'args' else None
                if selected_elements is not None and isinstance(keyword.value, (ast.List, ast.Tuple)):
                    values = set().union(*(self.expression(value) for position, value in enumerate(keyword.value.elts) if position in selected_elements))
                else:
                    values = self.expression(keyword.value)
                if sensitive_arguments is None or keyword.arg in sensitive_arguments:
                    sources.update(values)
                    if call:
                        for source in values:
                            self.edge(source, call.entity_id, 'argument', keyword.arg)
            if call:
                if isinstance(node.func, ast.Attribute) and sensitive_arguments is None:
                    for source in self.expression(node.func.value):
                        self.edge(source, call.entity_id, 'receiver')
                return {call.entity_id}
            return sources
        if isinstance(node, ast.Attribute):
            values = self.expression(node.value)
            entity = self.entity(node, EntityType.VARIABLE)
            if entity:
                for previous in self.environment.get(_python_qualified_name(node), ()):
                    self.edge(previous, entity.entity_id, 'reference')
                values.add(entity.entity_id)
            return values
        if isinstance(node, (ast.GeneratorExp, ast.ListComp, ast.SetComp, ast.DictComp)):
            before = dict(self.environment)
            for generator in node.generators:
                self.assign_target(generator.target, self.expression(generator.iter))
                for condition in generator.ifs:
                    self.expression(condition)
            values = (self.expression(node.key) | self.expression(node.value)
                      if isinstance(node, ast.DictComp) else self.expression(node.elt))
            self.environments[-1] = before
            return values
        if isinstance(node, ast.Subscript):
            return self.expression(node.value) | self.expression(node.slice)
        if isinstance(node, ast.BinOp):
            return self.expression(node.left) | self.expression(node.right)
        if isinstance(node, ast.BoolOp):
            return set().union(*(self.expression(value) for value in node.values))
        if isinstance(node, ast.UnaryOp):
            return self.expression(node.operand)
        if isinstance(node, ast.Compare):
            return self.expression(node.left) | set().union(*(self.expression(item) for item in node.comparators))
        if isinstance(node, ast.IfExp):
            return self.expression(node.test) | self.expression(node.body) | self.expression(node.orelse)
        if isinstance(node, ast.JoinedStr):
            return set().union(*(self.expression(value) for value in node.values))
        if isinstance(node, ast.FormattedValue):
            return self.expression(node.value)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return set().union(*(self.expression(item) for item in node.elts)) if node.elts else set()
        if isinstance(node, ast.Dict):
            values = [item for item in node.keys + node.values if item is not None]
            return set().union(*(self.expression(item) for item in values)) if values else set()
        return set()
