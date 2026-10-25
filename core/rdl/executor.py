"""Bounded Phase 3 executor for text and entity-aware RDL v2 plans."""

import re
import time
from itertools import product
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from utils.scan_scope import glob_source, allows_file, allows_check
from utils.source_cache import read_source_text
from typing import Dict, List, Optional, Tuple

from .adapters.registry import default_registry
from .ast import BinaryExpression, Predicate, UnaryExpression
from .ir import SemanticEntity, SemanticIR
from .plan import Capability
from .flow import PythonDataFlowProvider
from .cfg import PythonControlFlowProvider
from .state import StateMachineAnalyzer
from .adapters.c import CStateProvider
from .callgraph import PythonCallGraphProvider
from .cache import AnalysisBudgetExceeded, IncrementalIRCache


class ExecutionOutcome(str, Enum):
    MATCH = "MATCH"
    NO_MATCH = "NO_MATCH"
    RULE_ERROR = "RULE_ERROR"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True)
class Evidence:
    predicate: str
    matched: bool
    entity_id: str = ""
    location: object = None
    explanation: str = ""
    transition: str = ""


@dataclass(frozen=True)
class ExecutionResult:
    outcome: ExecutionOutcome
    rule_id: str
    evidence: Tuple[Evidence, ...]
    unavailable_capabilities: Tuple[str, ...] = ()
    errors: Tuple[str, ...] = ()
    witnesses: Tuple[Tuple[Evidence, ...], ...] = ()


class SemanticExecutor:
    def __init__(self, registry=None, max_entities=200000, max_evidence=1000, cache=None, max_elapsed_ms=10000):
        self.registry = registry or default_registry()
        self.max_entities = max_entities
        self.max_evidence = max_evidence
        self.cache = cache or IncrementalIRCache()
        self.max_elapsed_ms = max(1, int(max_elapsed_ms))
        self._portable_graphs = []
        self._php_graphs = []
        self._python_graphs = []
        self._path_snapshot = None
        self._snapshot_paths = {}
        self._portable_ir_limits = []

    def execute(self, document, root, language, source_paths=None, project_root=None, file_text=None):
        try:
            plan = getattr(document, 'execution_plan', None)
            if document.valid and plan and not (plan.capabilities - {Capability.TEXT, Capability.PATH, Capability.PROJECT}):
                from .text import execute_text
                return execute_text(document, root, project_root, file_text, self.max_elapsed_ms, self.max_evidence)
            return self._execute(document, root, language, source_paths, project_root)
        except AnalysisBudgetExceeded as exc:
            plan = getattr(document, 'execution_plan', None)
            return ExecutionResult(ExecutionOutcome.INDETERMINATE, getattr(plan, 'rule_id', ''), (), errors=(str(exc),))

    def _execute(self, document, root, language, source_paths=None, project_root=None):
        deadline = time.perf_counter() + self.max_elapsed_ms / 1000.0
        plan = getattr(document, "execution_plan", None)
        if not document.valid or plan is None or document.rule is None:
            return ExecutionResult(ExecutionOutcome.RULE_ERROR, getattr(plan, "rule_id", ""), (), errors=tuple(item.message for item in document.diagnostics))
        adapter = self.registry.get(language)
        if adapter is None:
            return ExecutionResult(ExecutionOutcome.RULE_ERROR, plan.rule_id, (), errors=("no adapter registered for language: {0}".format(language),))
        from .portable_profiles import EXTENSIONS
        portable = language in EXTENSIONS and Capability.DATA_FLOW in plan.capabilities
        if portable:
            from .adapters.portable import PortableAdapter
            adapter = PortableAdapter(language, catalog=adapter.catalog)
            if source_paths is None and project_root and Path(root).is_file():
                from .project import portable_dependency_scope
                source_paths, _ = portable_dependency_scope(root, project_root, language)
        root_path = Path(root)
        from utils.source_cache import current_snapshot
        snapshot = current_snapshot()
        if snapshot is not None and snapshot.key(root_path) is not None:
            if self._path_snapshot is not snapshot:
                self._path_snapshot = snapshot
                self._snapshot_paths = {}
            resolved_paths = self._snapshot_paths
            if len(resolved_paths) > 8192:
                resolved_paths.clear()
        else:
            resolved_paths = {}

        def is_entry(entity):
            # Thousands of entities share a handful of source files. Resolve
            # each file once per execution, retaining symlink-aware identity.
            origins = (entity.location.path,) + tuple(entity.attribute('php_input_origins') or ())
            for value in origins + (str(root_path),):
                if value not in resolved_paths:
                    resolved_paths[value] = Path(value).resolve()
            return any(resolved_paths[value] == resolved_paths[str(root_path)] for value in origins)

        try:
            semantic_ir = self.cache.parse(adapter, root_path, source_paths)
        except AnalysisBudgetExceeded as exc:
            return ExecutionResult(ExecutionOutcome.INDETERMINATE, plan.rule_id, (), errors=(str(exc),))
        if time.perf_counter() > deadline:
            return ExecutionResult(ExecutionOutcome.INDETERMINATE, plan.rule_id, (), errors=("execution time budget exceeded",))
        if semantic_ir.diagnostics:
            return ExecutionResult(ExecutionOutcome.RULE_ERROR, plan.rule_id, (), errors=semantic_ir.diagnostics)
        if len(semantic_ir.entities) > self.max_entities:
            return ExecutionResult(ExecutionOutcome.INDETERMINATE, plan.rule_id, (), errors=("entity budget exceeded",))

        # PHP project scopes can include large model libraries. If the entry file
        # has no source for a required binding, call-graph construction cannot
        # create one; retain the same decisive no-match without rebuilding it.
        if (language == 'php' or portable) and Capability.DATA_FLOW in plan.capabilities:
            for declaration in document.rule.bindings:
                if not (declaration.concept.startswith('input.') or declaration.concept == 'secret.literal-key-fallback'):
                    continue
                candidates = self._entities(semantic_ir, declaration.entity_type, declaration.concept)
                if source_paths is not None:
                    candidates = [entity for entity in candidates if is_entry(entity)]
                if not candidates and not (language == 'php' and
                        any(entity.attribute('php_upload_temporary_path') for entity in semantic_ir.entities) and
                        any(entity.native_kind == 'ReadContents' for entity in semantic_ir.entities)):
                    limits = ()
                    if portable:
                        cached_limits = next((item for item in self._portable_ir_limits if item[0] is semantic_ir), None)
                        if cached_limits is None:
                            coverage = tuple((entity, entity.attribute('flow_limits'))
                                             for entity in semantic_ir.entities
                                             if entity.attribute('flow_limits'))
                            self._portable_ir_limits = (self._portable_ir_limits + [(semantic_ir, coverage)])[-4:]
                        else:
                            coverage = cached_limits[1]
                        # Inputs for this evaluation are explicitly restricted
                        # to the entry file. If that file has no input binding,
                        # unrelated helper syntax cannot create an entry-file
                        # source. Retain every entry-file limit and keep global
                        # limits for project-wide evaluations. Reviews with an
                        # actual source still use all graph/dependency limits.
                        limits = tuple(sorted({reason for entity, reasons in coverage
                                               if source_paths is None or is_entry(entity)
                                               for reason in reasons}))
                    return ExecutionResult(ExecutionOutcome.INDETERMINATE if limits else ExecutionOutcome.NO_MATCH, plan.rule_id,
                        (Evidence('LET ' + declaration.name, False, explanation=declaration.concept),), errors=limits)

        flow_graph = None
        portable_limits = ()
        control_graph = None
        state_events = ()
        call_graph = None
        incomplete_php_flow = False
        runtime_capabilities = set(semantic_ir.capabilities) | {Capability.TEXT, Capability.PATH, Capability.PROJECT}
        if portable:
            from .portable_flow import build_project_flow
            cache_key = tuple(id(entity) for entity in semantic_ir.entities)
            cached = next((item for item in self._portable_graphs if item[0] == cache_key), None)
            if cached is None:
                try:
                    graph, limits = build_project_flow(semantic_ir)
                    cached = (cache_key, semantic_ir, graph, limits)
                except AnalysisBudgetExceeded as exc:
                    cached = (cache_key, semantic_ir, None, (str(exc),))
                self._portable_graphs = (self._portable_graphs + [cached])[-4:]
            if cached[2] is None:
                raise AnalysisBudgetExceeded(cached[3][0])
            flow_graph, portable_limits = cached[2:]
            if time.perf_counter() > deadline:
                raise AnalysisBudgetExceeded('project flow execution time budget exceeded')
            semantic_ir = replace(semantic_ir, entities=tuple(flow_graph.entities.values()))
            runtime_capabilities.update({Capability.DATA_FLOW, Capability.CALL_GRAPH})
        if Capability.DATA_FLOW in plan.capabilities and language == 'php':
            from .php_flow import PHPDataFlowProvider
            incomplete_php_flow = sorted({reason for entity in semantic_ir.entities for reason in (entity.attribute('flow_incomplete') or ())})
            identity = (str(root_path), tuple(id(entity) for entity in semantic_ir.entities),
                        tuple(id(edge) for edge in semantic_ir.edges))
            cached = next((item for item in self._php_graphs if item[0] == identity), None)
            if cached is None:
                flow_graph = PHPDataFlowProvider().build(root_path, semantic_ir)
                # Eviction changes reuse only, never the analyzed scope or evidence.
                if len(flow_graph.entities) + len(flow_graph.edges) <= 100000:
                    self._php_graphs = (self._php_graphs + [(identity, semantic_ir, flow_graph)])[-2:]
            else:
                flow_graph = cached[2]
            semantic_ir = replace(semantic_ir, entities=tuple(flow_graph.entities.values()))
            runtime_capabilities.add(Capability.DATA_FLOW)
        if Capability.DATA_FLOW in plan.capabilities and language == "python":
            identity = (str(root_path), str(project_root or root_path),
                        tuple(id(entity) for entity in semantic_ir.entities),
                        tuple(id(edge) for edge in semantic_ir.edges))
            cached = next((item for item in self._python_graphs if item[0] == identity), None)
            original_ir = semantic_ir
            call_graph = cached[3] if cached else PythonCallGraphProvider().build(Path(project_root or root_path), semantic_ir)
            local_calls = {edge.call_id for edge in call_graph.edges}
            # An explicitly resolved project function is modeled by its body,
            # not by a library API name heuristic (for example worker.execute).
            sink_concepts = {'sql.execution', 'command.execution', 'network.outbound-request',
                             'filesystem.access', 'deserialization.object-construction', 'navigation.redirect',
                             'web.origin-response', 'model.bulk-binding', 'crypto.key-material'}
            semantic_ir = cached[2] if cached else replace(semantic_ir, entities=tuple(
                replace(entity, concepts=entity.concepts - sink_concepts,
                        attributes=tuple((key, value) for key, value in entity.attributes
                                         if key not in {'sensitive_arguments', 'argv_taint_indices'}))
                if entity.entity_id in local_calls else entity for entity in semantic_ir.entities))
            flow_graph = cached[4] if cached else PythonDataFlowProvider().build(root_path, semantic_ir)
            if cached is None and len(flow_graph.entities) + len(flow_graph.edges) <= 100000:
                self._python_graphs = (self._python_graphs + [(identity, original_ir, semantic_ir, call_graph, flow_graph)])[-2:]
            if time.perf_counter() > deadline:
                return ExecutionResult(ExecutionOutcome.INDETERMINATE, plan.rule_id, (), errors=("execution time budget exceeded",))
            runtime_capabilities.add(Capability.DATA_FLOW)
            if flow_graph.truncated:
                return ExecutionResult(ExecutionOutcome.INDETERMINATE, plan.rule_id, (), errors=('data-flow edge budget exceeded',))
        if language == "python" and (Capability.CALL_GRAPH in plan.capabilities or flow_graph is not None or root_path.is_dir()):
            if call_graph is None:
                call_graph = PythonCallGraphProvider().build(Path(project_root or root_path), semantic_ir)
            if time.perf_counter() > deadline:
                return ExecutionResult(ExecutionOutcome.INDETERMINATE, plan.rule_id, (), errors=("execution time budget exceeded",))
            if call_graph.truncated:
                return ExecutionResult(ExecutionOutcome.INDETERMINATE, plan.rule_id, (), errors=("call-graph budget exceeded",))
            runtime_capabilities.add(Capability.CALL_GRAPH)
            if flow_graph is not None:
                flow_graph = call_graph.augment_flow(flow_graph, semantic_ir)
        if Capability.CONTROL_FLOW in plan.capabilities and language == "python":
            control_graph = PythonControlFlowProvider().build(root_path, semantic_ir)
            if time.perf_counter() > deadline:
                return ExecutionResult(ExecutionOutcome.INDETERMINATE, plan.rule_id, (), errors=("execution time budget exceeded",))
            if control_graph.truncated:
                return ExecutionResult(ExecutionOutcome.INDETERMINATE, plan.rule_id, (), errors=("control-flow graph budget exceeded",))
            runtime_capabilities.add(Capability.CONTROL_FLOW)
        if Capability.STATE in plan.capabilities and language == "c":
            state_events, straight_line, interprocedural_state = CStateProvider().build(root_path, semantic_ir)
            if time.perf_counter() > deadline:
                return ExecutionResult(ExecutionOutcome.INDETERMINATE, plan.rule_id, (), errors=("execution time budget exceeded",))
            runtime_capabilities.add(Capability.STATE)
            if interprocedural_state:
                runtime_capabilities.add(Capability.CALL_GRAPH)
            if straight_line:
                runtime_capabilities.add(Capability.CONTROL_FLOW)
        unavailable = sorted(item.value for item in plan.capabilities - runtime_capabilities)
        if unavailable:
            return ExecutionResult(ExecutionOutcome.INDETERMINATE, plan.rule_id, (), tuple(unavailable))

        bindings: Dict[str, SemanticEntity] = {}
        binding_options: Dict[str, List[SemanticEntity]] = {}
        evidence: List[Evidence] = []
        execution_context = {"last_flow_path": None, "last_control_path": None, "last_state_trace": None}
        for declaration in document.rule.bindings:
            candidates = self._entities(semantic_ir, declaration.entity_type, declaration.concept)
            if source_paths is not None and (declaration.concept.startswith('input.') or declaration.concept == 'secret.literal-key-fallback'):
                candidates = [entity for entity in candidates if is_entry(entity)]
            matched = bool(candidates)
            entity = candidates[0] if candidates else None
            if entity:
                bindings[declaration.name.lower()] = entity
                binding_options[declaration.name.lower()] = candidates
            evidence.append(Evidence("LET {0}".format(declaration.name), matched, entity.entity_id if entity else "", entity.location if entity else None, declaration.concept))
            if not matched:
                return ExecutionResult(ExecutionOutcome.INDETERMINATE if portable_limits else ExecutionOutcome.NO_MATCH,
                                       plan.rule_id, tuple(evidence), errors=portable_limits)


        for planned_state in plan.states:
            trace, truncated = StateMachineAnalyzer().evaluate(planned_state, state_events)
            if truncated:
                return ExecutionResult(ExecutionOutcome.INDETERMINATE, plan.rule_id, tuple(evidence), errors=("state-event budget exceeded",))
            if trace is None:
                evidence.append(Evidence("STATE VIOLATION", False, explanation=planned_state.binding))
                return ExecutionResult(ExecutionOutcome.NO_MATCH, plan.rule_id, tuple(evidence))
            execution_context["last_state_trace"] = trace
            violating = trace.violation
            bound_entity = semantic_ir.entity(trace.object_id)
            if bound_entity:
                bindings[planned_state.binding.lower()] = bound_entity
            for step in trace.steps:
                evidence.append(Evidence(
                    "STATE VIOLATION" if step.violation else "STATE TRANSITION",
                    True,
                    step.event.entity_id,
                    step.event.location,
                    "{0}: {1} -> {2}{3}".format(
                        step.event.event,
                        step.before,
                        step.after,
                        " via " + " -> ".join(step.event.call_path) if len(step.event.call_path) > 1 else "",
                    ),
                ))

        expressions = document.rule.conditions + document.rule.requirements
        # Evaluate each binding, so a safe first sink cannot hide a later unsafe
        # sink and a safe first configuration entry cannot hide an insecure one.
        for expression in expressions:
            if isinstance(expression, Predicate) and expression.name.upper() == 'EXISTS' and expression.binding:
                options = self._entities(semantic_ir, expression.entity_type, expression.arguments[0] if expression.arguments else '')
                if options:
                    binding_options[expression.binding.lower()] = options
        excluded = set()
        for expression in expressions:
            if isinstance(expression, UnaryExpression) and isinstance(expression.operand, Predicate):
                name = expression.operand.name.lower()
                if name.startswith(('sanitizer.', 'policy.')):
                    excluded.add(name)
        names = list(binding_options)
        combinations = product(*(binding_options[name] for name in names))
        witnesses, seen = [], set()
        negative = list(evidence)
        index = 0
        php_limits = set(incomplete_php_flow or ()) | set(portable_limits)
        if language == 'php':
            php_limits.update(reason for values in binding_options.values() for entity in values for reason in entity.attribute('php_limits', ()))
        for considered, combination in enumerate(combinations):
            if considered >= 1000000 or (considered % 256 == 0 and time.perf_counter() > deadline):
                errors = tuple(sorted(php_limits | {'binding or execution time budget exceeded'}))
                if language == 'php' and witnesses and not incomplete_php_flow:
                    return ExecutionResult(ExecutionOutcome.MATCH, plan.rule_id, witnesses[0], errors=errors, witnesses=tuple(witnesses))
                return ExecutionResult(ExecutionOutcome.INDETERMINATE, plan.rule_id, tuple(negative), errors=errors, witnesses=tuple(witnesses))
            if language == 'php' and flow_graph and len(combination) == 2 and len(document.rule.bindings) == 2:
                first, second = combination
                if document.rule.bindings[0].concept.startswith('input.') and first.entity_id not in flow_graph.possible_sources(second.entity_id):
                    continue
            index += 1
            if index >= 10000 or time.perf_counter() > deadline:
                if language == 'php' and witnesses and not incomplete_php_flow:
                    return ExecutionResult(ExecutionOutcome.MATCH, plan.rule_id, witnesses[0], errors=tuple(sorted(php_limits | {'binding or execution time budget exceeded'})), witnesses=tuple(witnesses))
                return ExecutionResult(ExecutionOutcome.INDETERMINATE, plan.rule_id, tuple(negative), errors=('binding or execution time budget exceeded',), witnesses=tuple(witnesses))
            selected = dict(zip(names, combination))
            current_bindings = dict(bindings, **selected)
            current_options = {name: [entity] for name, entity in selected.items()}
            current_evidence = list(evidence)
            for position, item in enumerate(current_evidence):
                if item.predicate.startswith('LET '):
                    chosen = selected.get(item.predicate[4:].lower())
                    if chosen:
                        current_evidence[position] = Evidence(item.predicate, True, chosen.entity_id, chosen.location, item.explanation)
            context = dict(execution_context, excluded_concepts=excluded, selected=selected)
            try:
                matched = all(self._evaluate(expression, semantic_ir, root_path, current_bindings, current_options, current_evidence, flow_graph, control_graph, context) for expression in expressions)
            except AnalysisBudgetExceeded as exc:
                if language != 'php':
                    return ExecutionResult(ExecutionOutcome.INDETERMINATE, plan.rule_id, tuple(current_evidence), errors=(str(exc),), witnesses=tuple(witnesses))
                php_limits.add(str(exc))
                matched = False
            if matched:
                location_ids = tuple(e.entity_id for e in current_evidence if e.predicate in {'FLOWS TO', 'EXISTS', 'STATE VIOLATION'} and e.matched)
                if location_ids not in seen:
                    seen.add(location_ids)
                    witnesses.append(tuple(current_evidence))
            elif len(current_evidence) > len(negative):
                negative = current_evidence
        if witnesses and not incomplete_php_flow:
            return ExecutionResult(ExecutionOutcome.MATCH, plan.rule_id, witnesses[0], errors=tuple(sorted(php_limits)), witnesses=tuple(witnesses))
        if php_limits:
            return ExecutionResult(ExecutionOutcome.INDETERMINATE, plan.rule_id, tuple(negative), errors=tuple(sorted(php_limits)))
        return ExecutionResult(ExecutionOutcome.NO_MATCH, plan.rule_id, tuple(negative))

    @staticmethod
    def _entities(semantic_ir: SemanticIR, kind, concept):
        candidates = [
            entity for entity in (semantic_ir.concept_index.get(concept, ()) if concept else semantic_ir.entities)
            if (entity.kind == kind or kind.value == 'VARIABLE' and entity.kind.value in {'PARAMETER', 'CALL'} and concept.startswith('input.')) and (not concept or concept in entity.concepts)
        ]
        return sorted(candidates, key=lambda entity: (-len(entity.concepts), entity.location.path, entity.location.line))

    def _evaluate(self, expression, semantic_ir, root, bindings, binding_options, evidence, flow_graph, control_graph, execution_context):
        if isinstance(expression, UnaryExpression):
            matched = not self._evaluate(expression.operand, semantic_ir, root, bindings, binding_options, evidence, flow_graph, control_graph, execution_context)
            evidence.append(Evidence("NOT", matched))
            return matched
        if isinstance(expression, BinaryExpression):
            left = self._evaluate(expression.left, semantic_ir, root, bindings, binding_options, evidence, flow_graph, control_graph, execution_context)
            if expression.operator == "AND":
                right = self._evaluate(expression.right, semantic_ir, root, bindings, binding_options, evidence, flow_graph, control_graph, execution_context) if left else False
                return left and right
            right = self._evaluate(expression.right, semantic_ir, root, bindings, binding_options, evidence, flow_graph, control_graph, execution_context) if not left else True
            return left or right
        if not isinstance(expression, Predicate):
            return False
        name = expression.name.upper()
        if name == "EXISTS":
            candidates = self._entities(semantic_ir, expression.entity_type, expression.arguments[0] if expression.arguments else "")
            entity = execution_context.get('selected', {}).get(expression.binding.lower()) or (candidates[0] if candidates else None)
            if entity and expression.binding:
                bindings[expression.binding.lower()] = entity
                binding_options[expression.binding.lower()] = candidates
            evidence.append(Evidence("EXISTS", bool(entity), entity.entity_id if entity else "", entity.location if entity else None, expression.arguments[0] if expression.arguments else ""))
            return bool(entity)
        if name in {"PRESENT", "MISSING", "MATCHES", "CONTAINS"}:
            operand = expression.arguments[0]
            pattern = operand
            flags = 0
            match = re.match(r"^/(.*)/([imsIMS]*)$", operand, re.DOTALL)
            if match:
                pattern = match.group(1)
                if "i" in match.group(2).lower():
                    flags |= re.IGNORECASE
                if "m" in match.group(2).lower():
                    flags |= re.MULTILINE
                if "s" in match.group(2).lower():
                    flags |= re.DOTALL
            texts = []
            paths = [root] if root.is_file() else sorted(path for path in glob_source(root, "*") if path.is_file() and path.suffix.lower() in {".py", ".dks"})
            for path in paths:
                try:
                    texts.append(read_source_text(path, encoding="utf-8"))
                except (OSError, UnicodeError):
                    continue
            found = any(re.search(pattern, text, flags) for text in texts)
            matched_result = not found if name == "MISSING" else found
            evidence.append(Evidence(name, matched_result, explanation=operand))
            return matched_result

        source_name = expression.name.lower()
        if source_name == "reachable" and execution_context.get("last_state_trace") and not control_graph:
            trace = execution_context["last_state_trace"]
            evidence.append(Evidence("REACHABLE PATH", True, explanation="ordered state-event path for {0}".format(trace.object_id)))
            return True
        if source_name == "interprocedural.path":
            path = execution_context.get("last_flow_path")
            matched = bool(path and any(kind in {"argument-parameter", "return-call"} for kind in path.edge_kinds))
            evidence.append(Evidence("INTERPROCEDURAL PATH", matched, explanation=" -> ".join(path.edge_kinds) if path else "no flow path"))
            return matched
        if control_graph and source_name == "reachable":
            bound = next((bindings.get(argument.lower()) for argument in expression.arguments if argument.lower() in bindings), None)
            if bound:
                path = control_graph.reachable_entity(bound.entity_id)
                execution_context["last_control_path"] = path
                conditions = "; ".join(path.conditions) if path else ""
                evidence.append(Evidence("REACHABLE", bool(path), bound.entity_id, bound.location, conditions or "entry-to-entity path"))
                return bool(path)
            matched = any(control_graph.find_path(entry, control_graph.exits[function_id]) for function_id, entry in control_graph.entries.items())
            evidence.append(Evidence("REACHABLE PATH", matched, explanation="function entry-to-exit path"))
            return matched

        if control_graph and source_name in bindings and expression.arguments:
            relation = expression.arguments[0].upper()
            target_name = expression.arguments[-1].lower()
            target = bindings.get(target_name)
            source = bindings.get(source_name)
            if relation in {"DOMINATES", "POST_DOMINATES"} and source and target:
                matched = control_graph.dominates_entities(source.entity_id, target.entity_id) if relation == "DOMINATES" else control_graph.post_dominates_entities(source.entity_id, target.entity_id)
                evidence.append(Evidence(relation, matched, source.entity_id, source.location, "{0} {1} {2}".format(source.qualified_name, relation.lower(), target.qualified_name)))
                return matched

        if control_graph and source_name == "authorization.dominates":
            target = next((bindings.get(argument.lower()) for argument in expression.arguments if argument.lower() in bindings), None)
            authorizers = [entity for entity in semantic_ir.entities if "authorization.check" in entity.concepts]
            matched_authorizer = next((entity for entity in authorizers if target and control_graph.dominates_entities(entity.entity_id, target.entity_id)), None)
            matched = matched_authorizer is not None
            evidence.append(Evidence("DOMINATES", matched, matched_authorizer.entity_id if matched_authorizer else "", matched_authorizer.location if matched_authorizer else None, "authorization.check"))
            return matched

        if flow_graph and source_name in binding_options and expression.arguments and expression.arguments[0].upper() == "FLOWS":
            target_name = expression.arguments[-1].lower()
            sources = binding_options.get(source_name, ())
            targets = binding_options.get(target_name, ())
            for source in sources:
                for target in targets:
                    path = flow_graph.find_path(source.entity_id, target.entity_id, execution_context.get('excluded_concepts', ()))
                    if path is None:
                        path = flow_graph.find_path(source.entity_id, target.entity_id)
                    if path:
                        limits = {reason for item in path.entity_ids for reason in flow_graph.entities[item].attribute('php_limits', ())}
                        if limits:
                            raise AnalysisBudgetExceeded('; '.join(sorted(limits)))
                        bindings[source_name] = source
                        bindings[target_name] = target
                        execution_context["last_flow_path"] = path
                        rendered = " -> ".join(flow_graph.entities[item].qualified_name or flow_graph.entities[item].name for item in path.entity_ids if item in flow_graph.entities)
                        evidence.append(Evidence("FLOWS TO", True, target.entity_id, target.location, rendered))
                        for position, entity_id in enumerate(path.entity_ids):
                            entity = flow_graph.entities[entity_id]
                            role = 'SOURCE' if position == 0 else 'SINK' if position == len(path.entity_ids) - 1 else 'PROPAGATION'
                            transition = path.edge_kinds[position - 1] if position else ''
                            symbol = entity.attribute('resolved_callee') or entity.qualified_name or entity.name
                            if symbol.startswith('<local>.'):
                                symbol = symbol[len('<local>.'):]
                            evidence.append(Evidence(role, True, entity_id, entity.location, symbol, transition))
                        return True
            evidence.append(Evidence("FLOWS TO", False, explanation="no modeled source-to-sink path in the analyzed scope"))
            return False

        concept = source_name
        bound = next((bindings.get(argument.lower()) for argument in reversed(expression.arguments) if argument.lower() in bindings), None)
        matched = False
        if bound:
            matched = concept in bound.concepts
            if concept == "security.relevant":
                matched = bool(bound.concepts - {"program.function", "program.type", "variable.reference"})
            if flow_graph and concept.startswith(("sanitizer.", "policy.")) and execution_context.get("last_flow_path"):
                matched = concept in flow_graph.concepts_on_path(execution_context["last_flow_path"])
        evidence.append(Evidence(expression.name, matched, bound.entity_id if bound else "", bound.location if bound else None, concept))
        return matched
