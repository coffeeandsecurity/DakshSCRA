"""Python AST adapter for the RDL semantic IR."""

import ast
import re
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
        self.local_bindings = []
        self.resource_classes = []
        self.fallback_fields = set()

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
        bindings = {argument.arg for argument in arguments}
        bindings.update(child.id for statement in node.body for child in ast.walk(statement)
                        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store))
        self.local_bindings.append(bindings)
        route = any(isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in {'route', 'get', 'post', 'put', 'delete', 'patch', 'api_route'} for d in node.decorator_list)
        route = route or (bool(self.resource_classes and self.resource_classes[-1])
                          and node.name.lower() in {'get', 'post', 'put', 'patch', 'delete', 'head', 'options'})
        self.parameter_names.append({argument.arg for argument in arguments})
        for argument in arguments:
            concepts = {'input.parameter'}
            if argument.arg not in {'self', 'cls'} and (route or argument.arg.lower() in {'request', 'req', 'input', 'payload', 'user_input', 'data', 'body', 'query', 'params'}):
                concepts.update(INPUT_CONCEPTS)
            parameter = self.add(EntityType.PARAMETER, argument.arg, argument, concepts=concepts)
            self.builder.add_edge(entity, parameter, EdgeKind.DECLARES)
        for statement in node.body:
            self.visit(statement)
        self.parameter_names.pop()
        self.local_bindings.pop()
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
        bases = [_qualified_name(base) for base in node.bases]
        self.resource_classes.append(any(
            self.aliases.get(base.partition('.')[0], '') +
            ('.' + base.partition('.')[2] if '.' in base else '') == 'flask_restful.Resource'
            and base.partition('.')[0] not in self.local_callables for base in bases))
        for statement in node.body:
            self.visit(statement)
        self.scopes.pop()
        self.resource_classes.pop()
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
        if (not shadowed and first in self.aliases
                and not any(first in bindings for bindings in self.local_bindings)
                and resolved in {'random.random', 'random.choice', 'random.choices', 'random.randint',
                                 'random.randrange', 'random.getrandbits', 'random.uniform'}):
            concepts.add('random.predictable')
        concepts = {item for item in concepts if not item.startswith(('sanitizer.', 'policy.'))}
        concepts.update(self.guards.get(name, ()))
        visible_aliases = {key: value for key, value in self.aliases.items()
                           if key not in self.local_callables
                           and not any(key in bindings for bindings in self.local_bindings)}
        concepts, attributes = call_semantics(node, resolved, concepts, visible_aliases)
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
        from ..security_operations import python_fallback, FALLBACK
        visible_aliases = {key:value for key,value in self.aliases.items() if key not in self.local_callables
                           and not any(key in bindings for bindings in self.local_bindings)}
        if python_fallback(node.value, visible_aliases):
            concepts.add(FALLBACK)
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
            if FALLBACK in concepts and isinstance(target, ast.Attribute):
                self.fallback_fields.add(_qualified_name(target))
            start = len(self.builder.entities)
            self.visit(target)
            if FALLBACK in concepts:
                from dataclasses import replace
                for index in range(start, len(self.builder.entities)):
                    value = self.builder.entities[index]
                    if value.kind == EntityType.VARIABLE and value.attribute('context') == 'Store':
                        self.builder.entities[index] = replace(value, concepts=value.concepts | {FALLBACK})
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
        if isinstance(node.ctx, ast.Store) and self.security_value_name(node.id):
            concepts.add('auth.token-material')
        self.add(EntityType.VARIABLE, node.id, node, concepts=concepts, attributes={"context": type(node.ctx).__name__})

    def visit_Attribute(self, node):
        name = _qualified_name(node)
        first, dot, rest = name.partition('.')
        resolved = self.aliases.get(first, first) + dot + rest
        if resolved.startswith('flask.request.') or resolved == 'sys.argv':
            self.add(EntityType.VARIABLE, name, node, concepts=INPUT_CONCEPTS)
        elif name in self.fallback_fields:
            concepts = {'variable.reference'}
            if isinstance(node.ctx, ast.Store) and self.security_value_name(name):
                concepts.add('auth.token-material')
            self.add(EntityType.VARIABLE, name, node, concepts=concepts, attributes={'context':type(node.ctx).__name__})
        elif self.security_value_name(name):
            concepts = {'variable.reference'}
            if isinstance(node.ctx, ast.Store):
                concepts.add('auth.token-material')
            self.add(EntityType.VARIABLE, name, node, concepts=concepts)
        self.generic_visit(node)

    @staticmethod
    def security_value_name(name):
        name = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', '_', name)
        return bool(re.search(r'(?:^|[._])(?:token|api_token|access_token|auth_token|refresh_token|reset_token|session_id|session_token|csrf_token|nonce|otp|password|passwd|secret)(?:$|_)', name, re.I))

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

    def visit_Compare(self, node):
        def password_operand(value):
            if isinstance(value, ast.Attribute):
                return value.attr.lower() in {'password', 'passwd', 'pwd'}
            if isinstance(value, ast.Subscript):
                key = value.slice.value if isinstance(value.slice, ast.Index) else value.slice
                return isinstance(key, ast.Constant) and str(key.value).lower() in {'password', 'passwd', 'pwd'}
            return False
        operands = [node.left] + list(node.comparators)
        for index, operator in enumerate(node.ops):
            pair = operands[index:index + 2]
            if (isinstance(operator, (ast.Eq, ast.NotEq)) and all(password_operand(v) for v in pair)
                    and any(isinstance(v, ast.Attribute) for v in pair)):
                self.add(EntityType.EXPRESSION, 'password comparison', node,
                         concepts={'auth.direct-password-comparison'})
                break
        self.generic_visit(node)


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
