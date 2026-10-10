"""Python AST adapter for the RDL semantic IR."""

import ast
from pathlib import Path
from utils.source_cache import read_source_text

from .base import LanguageAdapter
from ..ast import EntityType
from ..ir import EdgeKind, IRBuilder, SourceLocation
from ..plan import Capability
from .python_security import INPUT_CONCEPTS, proven_guards, call_semantics


def _qualified_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _qualified_name(node.value)
        return "{0}.{1}".format(prefix, node.attr) if prefix else node.attr
    return ""


class _Visitor(ast.NodeVisitor):
    def __init__(self, path, builder, catalog):
        self.path = path.as_posix()
        self.builder = builder
        self.catalog = catalog
        self.parents = []
        self.scopes = []
        self.assignment_names = []
        self.parameter_names = []
        self.aliases = {}
        self.guards = {}
        self.call_depth = 0
        self.local_callables = set()

    def location(self, node):
        return SourceLocation(
            self.path,
            int(getattr(node, "lineno", 1)),
            int(getattr(node, "col_offset", 0)) + 1,
            int(getattr(node, "end_lineno", getattr(node, "lineno", 1))),
            int(getattr(node, "end_col_offset", getattr(node, "col_offset", 0))) + 1,
        )

    def add(self, kind, name, node, native_kind=None, concepts=(), attributes=None, type_name=""):
        prefix = ".".join(scope.name for scope in self.scopes)
        qualified = "{0}.{1}".format(prefix, name) if prefix and name else (name or prefix)
        entity = self.builder.add_entity(
            kind, name, qualified, self.location(node), native_kind or type(node).__name__,
            type_name, concepts, attributes,
        )
        if self.parents:
            self.builder.add_edge(self.parents[-1], entity, EdgeKind.CONTAINS)
        return entity

    def visit_Module(self, node):
        self.local_callables = {statement.name for statement in node.body if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
        for statement in ast.walk(node):
            if isinstance(statement, ast.Import):
                for alias in statement.names:
                    self.aliases[alias.asname or alias.name.split('.')[0]] = alias.name if alias.asname else alias.name.split('.')[0]
            elif isinstance(statement, ast.ImportFrom):
                for alias in statement.names:
                    self.aliases[alias.asname or alias.name] = (statement.module or '') + '.' + alias.name
        self.guards = proven_guards(node, self.catalog)
        entity = self.add(EntityType.MODULE, Path(self.path).stem, node, "Module")
        self.parents.append(entity)
        self.generic_visit(node)
        self.parents.pop()

    def _visit_function(self, node, kind):
        entity = self.add(kind, node.name, node, concepts={"program.function"})
        self.parents.append(entity)
        self.scopes.append(entity)
        arguments = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
        route = any(isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in {'route', 'get', 'post', 'put', 'delete', 'patch', 'api_route'} for d in node.decorator_list)
        self.parameter_names.append({argument.arg for argument in arguments})
        for argument in arguments:
            concepts = {'input.parameter'}
            if route or argument.arg.lower() in {'request', 'req', 'input', 'payload', 'user_input', 'data', 'body', 'query', 'params'}:
                concepts.update(INPUT_CONCEPTS)
            parameter = self.add(EntityType.PARAMETER, argument.arg, argument, concepts=concepts)
            self.builder.add_edge(entity, parameter, EdgeKind.DECLARES)
        for statement in node.body:
            self.visit(statement)
        self.parameter_names.pop()
        self.scopes.pop()
        self.parents.pop()

    def visit_FunctionDef(self, node):
        self._visit_function(node, EntityType.FUNCTION)

    def visit_AsyncFunctionDef(self, node):
        self._visit_function(node, EntityType.FUNCTION)

    def visit_ClassDef(self, node):
        entity = self.add(EntityType.CLASS, node.name, node, concepts={"program.type"})
        self.parents.append(entity)
        self.scopes.append(entity)
        for statement in node.body:
            self.visit(statement)
        self.scopes.pop()
        self.parents.pop()

    def visit_Call(self, node):
        name = _qualified_name(node.func) or "<dynamic>"
        first, dot, rest = name.partition('.')
        resolved = self.aliases.get(first, first) + (dot + rest if dot else '')
        if resolved.startswith('flask.request.'):
            resolved = resolved[len('flask.'):]
        shadowed = not dot and name in self.local_callables
        if shadowed:
            resolved = '<local>.' + name
        concepts = set() if shadowed else self.catalog.concepts_for_call("python", resolved)
        concepts = {item for item in concepts if not item.startswith(('sanitizer.', 'policy.'))}
        concepts.update(self.guards.get(name, ()))
        concepts, attributes = call_semantics(node, resolved, concepts, self.aliases)
        attributes.update(callee=name, resolved_callee=resolved)
        entity = self.add(EntityType.CALL, name.split(".")[-1], node, concepts=concepts, attributes=attributes)
        if self.parents:
            self.builder.add_edge(self.parents[-1], entity, EdgeKind.CALLS)
        self.parents.append(entity)
        self.call_depth += 1
        if isinstance(node.func, ast.Attribute):
            self.visit(node.func.value)
        for index, argument in enumerate(node.args):
            credential_default = resolved in {'os.getenv', 'os.environ.get'} and index == 1
            if credential_default:
                self.call_depth -= 1
            self.visit(argument)
            if credential_default:
                self.call_depth += 1
        for keyword in node.keywords:
            direct_credential = isinstance(keyword.value, ast.Constant) and self.catalog.secret_name(keyword.arg or '')
            if direct_credential:
                self.assignment_names.append(keyword.arg)
                self.call_depth -= 1
            self.visit(keyword.value)
            if direct_credential:
                self.call_depth += 1
                self.assignment_names.pop()
        self.parents.pop()
        self.call_depth -= 1

    def visit_Assign(self, node):
        names = [self.assignment_name(target) for target in node.targets]
        name = next((item for item in names if item), "<assignment>")
        concepts = set()
        if name.upper().split('.')[-1] in {'DEBUG', 'TESTING', 'VERIFY_SSL', 'SSL_VERIFY', 'SESSION_COOKIE_SECURE', 'SESSION_COOKIE_HTTPONLY'}:
            concepts.add("config.security-control")
            insecure_value = name.upper().split('.')[-1] in {'DEBUG', 'TESTING'}
            if isinstance(node.value, ast.Constant) and node.value.value is insecure_value:
                concepts.add("config.insecure")
            kind = EntityType.CONFIGURATION_ENTRY
        else:
            kind = EntityType.ASSIGNMENT
        entity = self.add(kind, name, node, concepts=concepts)
        self.parents.append(entity)
        self.assignment_names.append(name)
        self.visit(node.value)
        for target in node.targets:
            self.visit(target)
        self.assignment_names.pop()
        self.parents.pop()

    def visit_AnnAssign(self, node):
        synthetic = ast.Assign(targets=[node.target], value=node.value or ast.Constant(value=None))
        ast.copy_location(synthetic, node)
        synthetic.end_lineno = getattr(node, "end_lineno", node.lineno)
        synthetic.end_col_offset = getattr(node, "end_col_offset", node.col_offset)
        self.visit_Assign(synthetic)

    def visit_Name(self, node):
        concepts = {"variable.reference"}
        self.add(EntityType.VARIABLE, node.id, node, concepts=concepts, attributes={"context": type(node.ctx).__name__})

    def visit_Attribute(self, node):
        name = _qualified_name(node)
        first, dot, rest = name.partition('.')
        resolved = self.aliases.get(first, first) + dot + rest
        if resolved.startswith('flask.request.') or resolved == 'sys.argv':
            self.add(EntityType.VARIABLE, name, node, concepts=INPUT_CONCEPTS)
        self.generic_visit(node)

    @staticmethod
    def assignment_name(node):
        if isinstance(node, ast.Subscript):
            index = node.slice.value if isinstance(node.slice, ast.Index) else node.slice
            if isinstance(index, ast.Constant) and isinstance(index.value, str):
                return index.value
        return _qualified_name(node)

    def visit_Dict(self, node):
        for key, value in zip(node.keys, node.values):
            name = key.value if isinstance(key, ast.Constant) and isinstance(key.value, str) else ''
            self.assignment_names.append(name)
            self.visit(value)
            self.assignment_names.pop()

    def visit_Constant(self, node):
        value = node.value
        concepts = set()
        assigned_name = self.assignment_names[-1] if self.assignment_names else ""
        if not self.call_depth and isinstance(value, str) and self.catalog.secret_name(assigned_name) and self.catalog.weak_secret_literal(value, assigned_name):
            concepts.add("secret.credential")
        self.add(EntityType.LITERAL, repr(value), node, type_name=type(value).__name__, concepts=concepts, attributes={"value": value})

    def visit_Return(self, node):
        entity = self.add(EntityType.RETURN, "return", node)
        self.parents.append(entity)
        if node.value:
            self.visit(node.value)
        self.parents.pop()


class PythonAdapter(LanguageAdapter):
    language_id = "python"
    adapter_name = "python-ast"
    adapter_version = "2"
    extensions = (".py",)
    capabilities = frozenset({Capability.ENTITIES, Capability.TYPES, Capability.CONFIGURATION})

    def parse_file(self, path: Path):
        builder = IRBuilder(self.language_id, self.adapter_name, self.adapter_version)
        try:
            source = read_source_text(path, encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
        except (OSError, UnicodeError, SyntaxError) as exc:
            builder.diagnostics.append("{0}: {1}".format(path, exc))
            return builder.build(self.capabilities)
        _Visitor(path, builder, self.catalog).visit(tree)
        return builder.build(self.capabilities)
