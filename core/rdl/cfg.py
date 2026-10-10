"""Normalized bounded control-flow graphs and a Python AST provider."""

import ast
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple


@dataclass(frozen=True)
class CFGNode:
    node_id: str
    function_id: str
    kind: str
    label: str
    line: int
    end_line: int
    entity_ids: Tuple[str, ...] = ()


@dataclass(frozen=True)
class CFGEdge:
    source_id: str
    target_id: str
    kind: str = "normal"
    condition: str = ""


@dataclass(frozen=True)
class ControlPath:
    node_ids: Tuple[str, ...]
    conditions: Tuple[str, ...] = ()


class ControlFlowGraph:
    def __init__(self, nodes, edges, entries, exits, entity_nodes, truncated=False):
        self.nodes: Dict[str, CFGNode] = {node.node_id: node for node in nodes}
        self.edges: Tuple[CFGEdge, ...] = tuple(edges)
        self.entries: Dict[str, str] = dict(entries)
        self.exits: Dict[str, str] = dict(exits)
        self.entity_nodes: Dict[str, str] = dict(entity_nodes)
        self.truncated = truncated
        self._forward: Dict[str, List[CFGEdge]] = {node_id: [] for node_id in self.nodes}
        self._reverse: Dict[str, List[CFGEdge]] = {node_id: [] for node_id in self.nodes}
        for edge in self.edges:
            if edge.source_id in self.nodes and edge.target_id in self.nodes:
                self._forward[edge.source_id].append(edge)
                self._reverse[edge.target_id].append(edge)

    def node_for_entity(self, entity_id: str) -> Optional[CFGNode]:
        return self.nodes.get(self.entity_nodes.get(entity_id, ""))

    def find_path(self, source_id: str, target_id: str, max_depth: int = 128) -> Optional[ControlPath]:
        if source_id not in self.nodes or target_id not in self.nodes:
            return None
        queue = deque([(source_id, (source_id,), ())])
        seen = {(source_id, 0)}
        while queue:
            current, path, conditions = queue.popleft()
            if current == target_id:
                return ControlPath(path, conditions)
            if len(path) > max_depth:
                continue
            for edge in self._forward.get(current, ()):
                marker = (edge.target_id, len(path))
                if edge.target_id in path or marker in seen:
                    continue
                seen.add(marker)
                next_conditions = conditions + ((edge.condition,) if edge.condition else ())
                queue.append((edge.target_id, path + (edge.target_id,), next_conditions))
        return None

    def reachable_entity(self, entity_id: str) -> Optional[ControlPath]:
        node = self.node_for_entity(entity_id)
        if node is None:
            return None
        entry = self.entries.get(node.function_id)
        return self.find_path(entry, node.node_id) if entry else None

    def _fixed_point(self, function_id: str, reverse: bool = False) -> Dict[str, Set[str]]:
        members = {node.node_id for node in self.nodes.values() if node.function_id == function_id}
        root = self.exits.get(function_id) if reverse else self.entries.get(function_id)
        if not members or root not in members:
            return {}
        result = {node_id: ({node_id} if node_id == root else set(members)) for node_id in members}
        incoming = self._forward if reverse else self._reverse
        changed = True
        while changed:
            changed = False
            for node_id in members - {root}:
                predecessors = [edge.target_id if reverse else edge.source_id for edge in incoming.get(node_id, ())]
                predecessors = [item for item in predecessors if item in members]
                merged = set.intersection(*(result[item] for item in predecessors)) if predecessors else set()
                updated = {node_id} | merged
                if updated != result[node_id]:
                    result[node_id] = updated
                    changed = True
        return result

    def dominates_entities(self, dominator_id: str, target_id: str) -> bool:
        dominator = self.node_for_entity(dominator_id)
        target = self.node_for_entity(target_id)
        if dominator is None or target is None or dominator.function_id != target.function_id:
            return False
        return dominator.node_id in self._fixed_point(target.function_id).get(target.node_id, set())

    def post_dominates_entities(self, post_dominator_id: str, target_id: str) -> bool:
        post_dominator = self.node_for_entity(post_dominator_id)
        target = self.node_for_entity(target_id)
        if post_dominator is None or target is None or post_dominator.function_id != target.function_id:
            return False
        return post_dominator.node_id in self._fixed_point(target.function_id, reverse=True).get(target.node_id, set())


class _PythonCFGBuilder:
    def __init__(self, path: Path, semantic_ir, max_nodes: int, max_edges: int):
        self.path = path
        self.semantic_ir = semantic_ir
        self.max_nodes = max_nodes
        self.max_edges = max_edges
        self.nodes: List[CFGNode] = []
        self.edges: List[CFGEdge] = []
        self.entries = {}
        self.exits = {}
        self._counter = 0
        self.truncated = False

    def add_node(self, function_id, kind, label, node=None):
        if len(self.nodes) >= self.max_nodes:
            self.truncated = True
            return self.exits.get(function_id, "")
        self._counter += 1
        node_id = "cfg:{0}:{1}".format(function_id, self._counter)
        line = int(getattr(node, "lineno", 0))
        end_line = int(getattr(node, "end_lineno", line))
        self.nodes.append(CFGNode(node_id, function_id, kind, label, line, end_line))
        return node_id

    def add_edge(self, source, target, kind="normal", condition=""):
        if not source or not target:
            return
        if len(self.edges) >= self.max_edges:
            self.truncated = True
            return
        edge = CFGEdge(source, target, kind, condition)
        if edge not in self.edges:
            self.edges.append(edge)

    @staticmethod
    def expression(node):
        try:
            return ast.unparse(node)
        except (AttributeError, ValueError):
            if isinstance(node, ast.Name):
                return node.id
            if isinstance(node, ast.Attribute):
                return "{0}.{1}".format(_PythonCFGBuilder.expression(node.value), node.attr)
            if isinstance(node, ast.Constant):
                return repr(node.value)
            if isinstance(node, ast.Compare):
                return "comparison at line {0}".format(getattr(node, "lineno", 0))
            return type(node).__name__

    def condition_chain(self, expression, true_target, false_target, function_id):
        if isinstance(expression, ast.BoolOp) and expression.values:
            values = expression.values
            if isinstance(expression.op, ast.And):
                target = true_target
                for value in reversed(values):
                    target = self.condition_chain(value, target, false_target, function_id)
                return target
            target = false_target
            for value in reversed(values):
                target = self.condition_chain(value, true_target, target, function_id)
            return target
        label = self.expression(expression)
        current = self.add_node(function_id, "condition", label, expression)
        self.add_edge(current, true_target, "true", label)
        self.add_edge(current, false_target, "false", "not ({0})".format(label))
        return current

    def sequence(self, statements, follow, function_id, exit_id, break_target=None, continue_target=None, exception_target=None):
        current = follow
        for statement in reversed(statements):
            current = self.statement(statement, current, function_id, exit_id, break_target, continue_target, exception_target)
        return current

    def statement(self, node, follow, function_id, exit_id, break_target, continue_target, exception_target):
        if isinstance(node, ast.If):
            body = self.sequence(node.body, follow, function_id, exit_id, break_target, continue_target, exception_target)
            alternate = self.sequence(node.orelse, follow, function_id, exit_id, break_target, continue_target, exception_target) if node.orelse else follow
            return self.condition_chain(node.test, body, alternate, function_id)
        if isinstance(node, (ast.While, ast.For, ast.AsyncFor)):
            placeholder = self.add_node(function_id, "loop", self.expression(node.test) if isinstance(node, ast.While) else "iterate " + self.expression(node.target), node)
            body = self.sequence(node.body, placeholder, function_id, exit_id, follow, placeholder, exception_target)
            if isinstance(node, ast.While):
                condition = self.condition_chain(node.test, body, follow, function_id)
                self.add_edge(placeholder, condition, "loop-back")
                return condition
            self.add_edge(placeholder, body, "loop-body", "next item")
            self.add_edge(placeholder, follow, "loop-exit", "iteration complete")
            return placeholder
        if isinstance(node, ast.Break):
            current = self.add_node(function_id, "break", "break", node)
            self.add_edge(current, break_target or follow, "break")
            return current
        if isinstance(node, ast.Continue):
            current = self.add_node(function_id, "continue", "continue", node)
            self.add_edge(current, continue_target or follow, "continue")
            return current
        if isinstance(node, ast.Return):
            current = self.add_node(function_id, "return", "return", node)
            self.add_edge(current, exit_id, "return")
            return current
        if isinstance(node, ast.Raise):
            current = self.add_node(function_id, "raise", "raise", node)
            self.add_edge(current, exception_target or exit_id, "exception")
            return current
        if isinstance(node, ast.Try):
            final_entry = self.sequence(node.finalbody, follow, function_id, exit_id, break_target, continue_target, exception_target) if node.finalbody else follow
            normal_follow = self.sequence(node.orelse, final_entry, function_id, exit_id, break_target, continue_target, exception_target) if node.orelse else final_entry
            handlers = [self.sequence(handler.body, final_entry, function_id, exit_id, break_target, continue_target, exception_target) for handler in node.handlers]
            handler_target = handlers[0] if handlers else exception_target
            return self.sequence(node.body, normal_follow, function_id, exit_id, break_target, continue_target, handler_target)
        current = self.add_node(function_id, "statement", type(node).__name__, node)
        self.add_edge(current, follow)
        if exception_target and any(isinstance(item, (ast.Call, ast.Await)) for item in ast.walk(node)):
            self.add_edge(current, exception_target, "exception")
        return current

    def build_function(self, node, ordinal):
        function_id = "{0}:{1}:{2}".format(node.name, node.lineno, ordinal)
        entry = self.add_node(function_id, "entry", "entry " + node.name, node)
        exit_id = self.add_node(function_id, "exit", "exit " + node.name, node)
        self.entries[function_id] = entry
        self.exits[function_id] = exit_id
        body = self.sequence(node.body, exit_id, function_id, exit_id)
        self.add_edge(entry, body)

    def attach_entities(self):
        entity_nodes = {}
        function_nodes = {}
        for node in self.nodes:
            if node.kind not in {"entry", "exit"} and node.line:
                function_nodes.setdefault(node.function_id, []).append(node)
        for entity in self.semantic_ir.entities:
            candidates = []
            for function_id, nodes in function_nodes.items():
                function_line = int(function_id.split(":")[1])
                function_entity = next((item for item in self.semantic_ir.entities if item.name == function_id.split(":")[0] and item.location.line == function_line), None)
                if function_entity and function_entity.location.line <= entity.location.line <= function_entity.location.end_line:
                    candidates.extend(nodes)
            containing = [node for node in candidates if node.line <= entity.location.line <= node.end_line]
            if containing:
                selected = min(containing, key=lambda item: (item.end_line - item.line, 0 if item.kind == "condition" else 1))
                entity_nodes[entity.entity_id] = selected.node_id
        return entity_nodes


class PythonControlFlowProvider:
    def __init__(self, max_nodes=50000, max_edges=100000):
        self.max_nodes = max_nodes
        self.max_edges = max_edges

    def build(self, path: Path, semantic_ir) -> ControlFlowGraph:
        source = Path(path).read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        builder = _PythonCFGBuilder(Path(path), semantic_ir, self.max_nodes, self.max_edges)
        functions = [node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for ordinal, function in enumerate(sorted(functions, key=lambda item: (item.lineno, item.col_offset)), 1):
            builder.build_function(function, ordinal)
        entity_nodes = builder.attach_entities()
        return ControlFlowGraph(builder.nodes, builder.edges, builder.entries, builder.exits, entity_nodes, builder.truncated)
