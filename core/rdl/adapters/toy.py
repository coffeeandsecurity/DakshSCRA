"""Adapter for DakshScript, a small proprietary-language integration example."""

import re
from pathlib import Path
from utils.source_cache import read_source_text

from .base import LanguageAdapter
from ..ast import EntityType
from ..ir import EdgeKind, IRBuilder, SourceLocation
from ..plan import Capability


_MODULE_RE = re.compile(r"^module\s+([A-Za-z_][\w.]*)$")
_FUNCTION_RE = re.compile(r"^function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)$")
_CALL_RE = re.compile(r"^call\s+([A-Za-z_][\w.]*)\s*\((.*)\)$")
_LET_RE = re.compile(r'^let\s+([A-Za-z_]\w*)\s*=\s*(.+)$')


class DakshScriptAdapter(LanguageAdapter):
    language_id = "dakshscript"
    adapter_name = "dakshscript-reference"
    adapter_version = "1"
    extensions = (".dks",)
    capabilities = frozenset({Capability.ENTITIES, Capability.TYPES})

    def parse_file(self, path: Path):
        builder = IRBuilder(self.language_id, self.adapter_name, self.adapter_version)
        parent = None
        module_name = path.stem
        try:
            lines = read_source_text(path, encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            builder.diagnostics.append("{0}: {1}".format(path, exc))
            return builder.build(self.capabilities)

        def location(number, text):
            return SourceLocation(path.as_posix(), number, 1, number, len(text) + 1)

        for number, raw in enumerate(lines, 1):
            text = raw.strip()
            if not text or text.startswith("#"):
                continue
            match = _MODULE_RE.match(text)
            if match:
                module_name = match.group(1)
                parent = builder.add_entity(EntityType.MODULE, module_name, module_name, location(number, text), "module")
                continue
            match = _FUNCTION_RE.match(text)
            if match:
                function = builder.add_entity(EntityType.FUNCTION, match.group(1), "{0}.{1}".format(module_name, match.group(1)), location(number, text), "function", concepts={"program.function"})
                if parent:
                    builder.add_edge(parent, function, EdgeKind.CONTAINS)
                parent = function
                for name in (item.strip() for item in match.group(2).split(",") if item.strip()):
                    parameter = builder.add_entity(EntityType.PARAMETER, name, "{0}.{1}".format(function.qualified_name, name), location(number, text), "parameter", concepts={"input.parameter"})
                    builder.add_edge(function, parameter, EdgeKind.DECLARES)
                continue
            match = _CALL_RE.match(text)
            if match:
                name = match.group(1)
                call = builder.add_entity(EntityType.CALL, name.split(".")[-1], name, location(number, text), "call", concepts=self.catalog.concepts_for_call("dakshscript", name), attributes={"callee": name})
                if parent:
                    builder.add_edge(parent, call, EdgeKind.CALLS)
                continue
            match = _LET_RE.match(text)
            if match:
                name, value = match.groups()
                variable = builder.add_entity(EntityType.VARIABLE, name, "{0}.{1}".format(module_name, name), location(number, text), "let")
                if parent:
                    builder.add_edge(parent, variable, EdgeKind.DECLARES)
                if value.startswith('"') and value.endswith('"'):
                    raw_value = value[1:-1]
                    concepts = {"secret.credential"} if self.catalog.secret_name(name) and self.catalog.weak_secret_literal(raw_value) else set()
                    literal = builder.add_entity(EntityType.LITERAL, repr(raw_value), variable.qualified_name, location(number, text), "string", type_name="string", concepts=concepts, attributes={"value": raw_value})
                    builder.add_edge(variable, literal, EdgeKind.ASSIGNS)
                continue
            builder.diagnostics.append("{0}:{1}: unrecognized DakshScript statement".format(path, number))
        return builder.build(self.capabilities)
