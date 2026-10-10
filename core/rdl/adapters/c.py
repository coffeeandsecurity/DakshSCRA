"""Structured C token/scope adapter for memory-lifetime state events."""

from dataclasses import dataclass
from pathlib import Path
from utils.source_cache import read_source_text

from .base import LanguageAdapter
from ..ast import EntityType
from ..ir import IRBuilder, SourceLocation
from ..plan import Capability
from ..state import StateEvent


@dataclass(frozen=True)
class _Token:
    text: str
    line: int


@dataclass(frozen=True)
class _CallSite:
    caller: str
    callee: str
    arguments: tuple
    sequence: float


def _tokens(source):
    result = []
    index = 0
    line = 1
    while index < len(source):
        char = source[index]
        if char == "\n":
            line += 1
            index += 1
        elif char.isspace():
            index += 1
        elif source.startswith("//", index):
            index = source.find("\n", index)
            if index < 0:
                break
        elif source.startswith("/*", index):
            end = source.find("*/", index + 2)
            segment = source[index:] if end < 0 else source[index:end + 2]
            line += segment.count("\n")
            index = len(source) if end < 0 else end + 2
        elif char in {'"', "'"}:
            quote = char
            start = index
            index += 1
            while index < len(source):
                if source[index] == "\\":
                    index += 2
                elif source[index] == quote:
                    index += 1
                    break
                else:
                    index += 1
            result.append(_Token(source[start:index], line))
        elif char.isalpha() or char == "_":
            start = index
            index += 1
            while index < len(source) and (source[index].isalnum() or source[index] == "_"):
                index += 1
            result.append(_Token(source[start:index], line))
        elif char.isdigit():
            start = index
            index += 1
            while index < len(source) and (source[index].isalnum() or source[index] in "._"):
                index += 1
            result.append(_Token(source[start:index], line))
        else:
            pair = source[index:index + 2]
            if pair in {"->", "++", "--", "==", "!=", "<=", ">=", "&&", "||", "+=", "-=", "*=", "/="}:
                result.append(_Token(pair, line))
                index += 2
            else:
                result.append(_Token(char, line))
                index += 1
    return result


def _matching(tokens, start, opening="(", closing=")"):
    depth = 0
    for index in range(start, len(tokens)):
        if tokens[index].text == opening:
            depth += 1
        elif tokens[index].text == closing:
            depth -= 1
            if depth == 0:
                return index
    return len(tokens) - 1


class CMemoryModel:
    allocation_calls = {"malloc", "calloc", "realloc", "aligned_alloc"}

    def __init__(self, path, source, builder):
        self.path = path.as_posix()
        self.tokens = _tokens(source)
        self.builder = builder
        self.events = []
        self.objects = {}
        self.aliases = {}
        self.straight_line = True
        self.control_ranges = []
        self.functions = {}
        self.calls = []

    def location(self, line):
        return SourceLocation(self.path, line, 1, line, 1)

    def canonical(self, name):
        seen = set()
        while name in self.aliases and name not in seen:
            seen.add(name)
            name = self.aliases[name]
        return name

    def object(self, name, line, allocated=False, extra_concepts=()):
        canonical = self.canonical(name)
        if canonical not in self.objects:
            concepts = {"memory.object"}
            if allocated:
                concepts.add("memory.allocation")
            concepts.update(extra_concepts)
            self.objects[canonical] = self.builder.add_entity(
                EntityType.RESOURCE, canonical, canonical, self.location(line), "CObject", concepts=concepts,
            )
        return self.objects[canonical]

    def event(self, event, name, line, function, sequence):
        object_entity = self.object(name, line)
        event_entity = self.builder.add_entity(
            EntityType.CALL, event.split(".")[-1], event, self.location(line), "CStateEvent", concepts={event},
            attributes={"object_id": object_entity.entity_id},
        )
        self.events.append(StateEvent(event, object_entity.entity_id, event_entity.entity_id, function, sequence, event_entity.location, name))

    def analyze(self):
        tokens = self.tokens
        index = 0
        sequence = 0
        current_function = "<file>"
        while index < len(tokens):
            token = tokens[index]
            if token.text in {"if", "for", "while", "switch"} and index + 1 < len(tokens) and tokens[index + 1].text == "(":
                condition_end = _matching(tokens, index + 1)
                if condition_end + 1 < len(tokens) and tokens[condition_end + 1].text == "{":
                    body_end = _matching(tokens, condition_end + 1, "{", "}")
                    self.control_ranges.append((token.line, tokens[body_end].line))
                else:
                    self.control_ranges.append((token.line, tokens[min(condition_end + 2, len(tokens) - 1)].line))
            elif token.text == "goto":
                self.straight_line = False
            if token.text == "(" and index and tokens[index - 1].text not in {"if", "for", "while", "switch", "sizeof"}:
                end = _matching(tokens, index)
                if end + 1 < len(tokens) and tokens[end + 1].text == "{":
                    current_function = tokens[index - 1].text
                    parameters = []
                    segment = []
                    for item in tokens[index + 1:end] + [_Token(",", token.line)]:
                        if item.text == ",":
                            identifiers = [part.text for part in segment if part.text.isidentifier() and part.text not in {"void", "char", "int", "long", "short", "const", "unsigned", "signed", "size_t", "FILE"}]
                            if identifiers:
                                parameters.append(identifiers[-1])
                            segment = []
                        else:
                            segment.append(item)
                    self.functions[current_function] = tuple(parameters)
                else:
                    callee = tokens[index - 1].text
                    if callee not in {"free", "malloc", "calloc", "realloc", "aligned_alloc", "fopen", "fclose", "fgetc", "fputc", "rewind", "memcpy", "memmove", "memset"}:
                        arguments = []
                        depth = 0
                        for item in tokens[index + 1:end]:
                            if item.text in {"(", "["}:
                                depth += 1
                            elif item.text in {")", "]"}:
                                depth -= 1
                            elif depth == 0 and item.text.isidentifier():
                                arguments.append(item.text)
                        self.calls.append(_CallSite(current_function, callee, tuple(arguments), sequence + 0.5))
            if token.text == "=" and index and index + 1 < len(tokens):
                left = tokens[index - 1].text
                right = tokens[index + 1].text
                if right in self.allocation_calls and index + 2 < len(tokens) and tokens[index + 2].text == "(":
                    self.object(left, token.line, allocated=True)
                    sequence += 1
                    self.event("memory.allocate", left, token.line, current_function, sequence)
                elif right == "fopen" and index + 2 < len(tokens) and tokens[index + 2].text == "(":
                    self.object(left, token.line, extra_concepts={"resource.closeable"})
                    sequence += 1
                    self.event("resource.open", left, token.line, current_function, sequence)
                elif right.isidentifier() and left.isidentifier() and right in self.objects:
                    self.aliases[left] = self.canonical(right)
            if token.text == "[" and index and tokens[index - 1].text.isidentifier():
                name = tokens[index - 1].text
                if name in self.objects or self.canonical(name) in self.objects:
                    sequence += 1
                    self.event("memory.use", name, token.line, current_function, sequence)
            if token.text == "free" and index + 2 < len(tokens) and tokens[index + 1].text == "(":
                name = tokens[index + 2].text
                if name.isidentifier():
                    sequence += 1
                    self.event("memory.free", name, token.line, current_function, sequence)
            if token.text == "fclose" and index + 2 < len(tokens) and tokens[index + 1].text == "(":
                name = tokens[index + 2].text
                if name.isidentifier():
                    sequence += 1
                    self.event("resource.close", name, token.line, current_function, sequence)
            if token.text in {"fgetc", "fputc", "rewind"} and index + 2 < len(tokens) and tokens[index + 1].text == "(":
                name = tokens[index + 2].text
                if name.isidentifier():
                    sequence += 1
                    self.event("resource.use", name, token.line, current_function, sequence)
            if token.text in {"memcpy", "memmove", "memset"} and index + 2 < len(tokens):
                name = tokens[index + 2].text
                if name.isidentifier():
                    sequence += 1
                    self.event("memory.use", name, token.line, current_function, sequence)
            if token.text == "[" and index and index + 1 < len(tokens) and tokens[index - 1].text.isidentifier():
                # Stack arrays are objects but never receive a heap-allocation event.
                previous = tokens[index - 1].text
                if previous not in self.objects:
                    self.object(previous, token.line)
            index += 1
        if any(start <= event.location.line <= end for start, end in self.control_ranges for event in self.events):
            self.straight_line = False
        return tuple(self.events)

    def expanded_events(self, events):
        local_callees = {call.callee for call in self.calls if call.callee in self.functions}
        roots = [name for name in self.functions if name not in local_callees]
        used_interprocedural = False
        complete = True
        expanded = []

        def expand(function, environment, stack, root, path):
            nonlocal used_interprocedural, complete
            if function in stack:
                complete = False
                return
            items = [(event.sequence, "event", event) for event in events if event.function_id == function]
            items += [(call.sequence, "call", call) for call in self.calls if call.caller == function and call.callee in self.functions]
            for _, kind, item in sorted(items, key=lambda value: value[0]):
                if kind == "event":
                    object_id = environment.get(item.detail, item.object_id)
                    expanded.append(StateEvent(item.event, object_id, item.entity_id, root, len(expanded) + 1, item.location, item.detail, path))
                else:
                    used_interprocedural = True
                    parameters = self.functions.get(item.callee, ())
                    child_environment = {}
                    for parameter, argument in zip(parameters, item.arguments):
                        canonical = self.canonical(argument)
                        object_entity = self.objects.get(canonical)
                        child_environment[parameter] = environment.get(argument, object_entity.entity_id if object_entity else "")
                    expand(item.callee, child_environment, stack + (function,), root, path + (item.callee,))

        for root in roots or list(self.functions):
            expand(root, {}, (), root, (root,))
        return tuple(expanded), used_interprocedural, complete


class CAdapter(LanguageAdapter):
    language_id = "c"
    adapter_name = "c-token-scope"
    adapter_version = "1"
    extensions = (".c", ".h")
    capabilities = frozenset({Capability.ENTITIES, Capability.TYPES})

    def parse_file(self, path: Path):
        builder = IRBuilder(self.language_id, self.adapter_name, self.adapter_version)
        try:
            source = read_source_text(path, encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            builder.diagnostics.append("{0}: {1}".format(path, exc))
            return builder.build(self.capabilities)
        CMemoryModel(path, source, builder).analyze()
        return builder.build(self.capabilities)


class CStateProvider:
    def build(self, path: Path, semantic_ir):
        source = read_source_text(Path(path), encoding="utf-8")
        builder = IRBuilder("c", "c-token-scope", "1")
        model = CMemoryModel(Path(path), source, builder)
        events = model.analyze()
        expanded, used_interprocedural, complete = model.expanded_events(events)
        # Remap model event object/entity IDs to the adapter IR by stable order.
        adapter_objects = [entity for entity in semantic_ir.entities if entity.kind == EntityType.RESOURCE]
        model_objects = [entity for entity in builder.entities if entity.kind == EntityType.RESOURCE]
        object_map = {old.entity_id: new.entity_id for old, new in zip(model_objects, adapter_objects)}
        adapter_events = [entity for entity in semantic_ir.entities if entity.native_kind == "CStateEvent"]
        event_map = {old.entity_id: new.entity_id for old, new in zip([entity for entity in builder.entities if entity.native_kind == "CStateEvent"], adapter_events)}
        remapped = tuple(
            StateEvent(event.event, object_map.get(event.object_id, event.object_id), event_map.get(event.entity_id, event.entity_id), event.function_id, event.sequence, event.location, event.detail, event.call_path)
            for event in expanded
        )
        return remapped, model.straight_line and complete, used_interprocedural
