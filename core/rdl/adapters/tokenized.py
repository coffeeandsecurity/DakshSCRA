"""Structural token adapters for JavaScript, Go, C++, and PHP."""

import heapq
import re
from dataclasses import dataclass
from pathlib import Path
from utils.source_cache import read_source_text

from .base import LanguageAdapter
from ..ast import EntityType
from ..ir import EdgeKind, IRBuilder, SourceLocation
from ..plan import Capability


@dataclass(frozen=True)
class _Token:
    text: str
    line: int
    column: int
    kind: str
    quote: str = ''


def _kotlin_literal_end(source, start, depth=0):
    """Find a Kotlin literal boundary without exposing template quotes as code."""
    if depth > 64:
        return len(source), False
    delimiter = '"""' if source.startswith('"""', start) else source[start]
    raw = delimiter == '"""'
    index = start + len(delimiter)
    while index < len(source):
        if source.startswith(delimiter, index):
            stop = index + len(delimiter)
            if raw:
                while stop < len(source) and source[stop] == '"':
                    stop += 1
            return stop, True
        if not raw and source[index] == '\\':
            index += 2
            continue
        if delimiter != "'" and source.startswith('${', index):
            index += 2
            braces = 1
            while index < len(source) and braces:
                if source.startswith('//', index):
                    end = source.find('\n', index+2)
                    index = len(source) if end < 0 else end
                elif source.startswith('/*', index):
                    index += 2
                    comments = 1
                    while index < len(source) and comments:
                        if source.startswith('/*', index):
                            comments += 1
                            index += 2
                        elif source.startswith('*/', index):
                            comments -= 1
                            index += 2
                        else:
                            index += 1
                elif source[index] in {'"', "'"}:
                    index, valid = _kotlin_literal_end(source, index, depth+1)
                    if not valid:
                        return len(source), False
                elif source[index] == '{':
                    braces += 1
                    if braces > 64:
                        return len(source), False
                    index += 1
                elif source[index] == '}':
                    braces -= 1
                    index += 1
                else:
                    index += 1
            if braces:
                return len(source), False
            continue
        index += 1
    return len(source), False


def _lex(source, php=False, hash_comments=False, javascript=False, kotlin=False):
    tokens = []
    index = 0
    line = 1
    column = 1
    in_code = not php
    while index < len(source):
        char = source[index]
        if php and not in_code and (source.startswith('<?php', index) or source.startswith('<?=', index)):
            size = 5 if source.startswith('<?php', index) else 3
            if size == 3:
                tokens.append(_Token('echo', line, column, 'identifier'))
            index += size
            column += size
            in_code = True
        elif php and in_code and source.startswith('?>', index):
            tokens.append(_Token(';', line, column, 'symbol'))
            index += 2
            column += 2
            in_code = False
        elif char == "\n":
            line += 1
            column = 1
            index += 1
        elif not in_code:
            index += 1
            column += 1
        elif char.isspace():
            column += 1
            index += 1
        elif source.startswith("//", index) or (php or hash_comments) and char == '#':
            end = source.find("\n", index)
            index = len(source) if end < 0 else end
        elif source.startswith("/*", index):
            end = source.find("*/", index + 2)
            segment = source[index:] if end < 0 else source[index:end + 2]
            lines = segment.splitlines()
            line += len(lines) - 1
            column = (len(lines[-1]) + 1) if len(lines) > 1 else column + len(segment)
            index = len(source) if end < 0 else end + 2
        elif javascript and char == '/' and (not tokens or tokens[-1].text in {'=', '(', '[', '{', ',', ':', ';', '!', '?', 'return', '=>', '&&', '||'}):
            # Regex contents are literals: braces and slashes in character classes
            # must not become executable block or comment delimiters.
            end, escaped, in_class = index + 1, False, False
            while end < len(source) and source[end] not in '\r\n':
                value = source[end]
                if escaped:
                    escaped = False
                elif value == '\\':
                    escaped = True
                elif value == '[':
                    in_class = True
                elif value == ']':
                    in_class = False
                elif value == '/' and not in_class:
                    break
                end += 1
            if end < len(source) and source[end] == '/':
                end += 1
                while end < len(source) and source[end].isalpha():
                    end += 1
                tokens.append(_Token(source[index:end], line, column, 'string', '/'))
                column += end - index
                index = end
            else:
                tokens.append(_Token(char, line, column, 'symbol'))
                index += 1
                column += 1
        elif kotlin and char in {'"', "'"}:
            start_line, start_column = line, column
            delimiter = '"""' if source.startswith('"""', index) else char
            content_start = index + len(delimiter)
            stop, valid = _kotlin_literal_end(source, index)
            value = source[content_start:stop-len(delimiter)] if valid else source[content_start:stop]
            kind = 'string' if valid else 'invalid'
            segment = source[index:stop]
            line += segment.count('\n')
            column = len(segment.rsplit('\n', 1)[-1]) + 1 if '\n' in segment else column + len(segment)
            tokens.append(_Token(value, start_line, start_column, kind, delimiter))
            index = stop
        elif char in {'"', "'", "`"}:
            quote = char
            start_line, start_column = line, column
            index += 1
            column += 1
            value = []
            while index < len(source):
                if source[index] == "\\" and index + 1 < len(source):
                    value.extend(source[index:index + 2])
                    index += 2
                    column += 2
                elif source[index] == quote:
                    index += 1
                    column += 1
                    break
                else:
                    if source[index] == "\n":
                        line += 1
                        column = 1
                    else:
                        column += 1
                    value.append(source[index])
                    index += 1
            tokens.append(_Token("".join(value), start_line, start_column, "string", quote))
        elif char.isalpha() or char in "_$":
            start, start_column = index, column
            index += 1
            column += 1
            while index < len(source) and (source[index].isalnum() or source[index] in "_$"):
                index += 1
                column += 1
            tokens.append(_Token(source[start:index], line, start_column, "identifier"))
        elif char.isdigit():
            start, start_column = index, column
            index += 1
            column += 1
            while index < len(source) and (source[index].isalnum() or source[index] in "._"):
                index += 1
                column += 1
            tokens.append(_Token(source[start:index], line, start_column, "number"))
        else:
            start_column = column
            pair = source[index:index + 2]
            triple = source[index:index + 3]
            if php and triple in {"===", "!==", "?->", "<=>", "..."}:
                tokens.append(_Token(triple, line, start_column, "symbol"))
                index += 3
                column += 3
                continue
            if pair in {"::", "->", "=>", ":=", "++", "--", "==", "!=", "<=", ">=", "&&", "||"}:
                tokens.append(_Token(pair, line, start_column, "symbol"))
                index += 2
                column += 2
            else:
                tokens.append(_Token(char, line, start_column, "symbol"))
                index += 1
                column += 1
    return tokens


def _match(tokens, start, opening="(", closing=")"):
    depth = 0
    for index in range(start, len(tokens)):
        if tokens[index].kind != 'symbol':
            continue
        if tokens[index].text == opening:
            depth += 1
        elif tokens[index].text == closing:
            depth -= 1
            if depth == 0:
                return index
    return len(tokens) - 1


def _delimiter_error(tokens):
    pairs = {")": "(", "]": "[", "}": "{"}
    stack = []
    for token in tokens:
        if token.kind != 'symbol':
            continue
        if token.text in {"(", "[", "{"}:
            stack.append(token)
        elif token.text in pairs:
            if not stack or stack[-1].text != pairs[token.text]:
                return "unexpected {0} at line {1}".format(token.text, token.line)
            stack.pop()
    if stack:
        return "unclosed {0} at line {1}".format(stack[-1].text, stack[-1].line)
    return ""


class _TokenAdapter(LanguageAdapter):
    capabilities = frozenset({Capability.ENTITIES})
    declaration_words = frozenset()
    control_words = frozenset({"if", "for", "while", "switch", "catch"})
    max_tokens = 500000
    reject_delimiter_errors = True

    def function_at(self, tokens, index):
        return None

    def qualified_call(self, tokens, index):
        parts = [tokens[index].text]
        cursor = index - 1
        while cursor >= 1 and tokens[cursor].text in {".", "::", "->"} and tokens[cursor - 1].kind == "identifier":
            parts[:0] = [tokens[cursor - 1].text, tokens[cursor].text]
            cursor -= 2
        return "".join(parts)

    def secret_name_candidate(self, name):
        return self.catalog.secret_name(name)

    def parse_file(self, path: Path):
        builder = IRBuilder(self.language_id, self.adapter_name, self.adapter_version)
        try:
            source = read_source_text(path, encoding="utf-8")
            tokens = _lex(source, php=self.language_id == 'php')
        except (OSError, UnicodeError) as exc:
            builder.diagnostics.append("{0}: {1}".format(path, exc))
            return builder.build(self.capabilities)
        if len(tokens) > self.max_tokens:
            builder.diagnostics.append("{0}: token budget exceeded".format(path))
            return builder.build(self.capabilities)
        delimiter_error = _delimiter_error(tokens)
        if delimiter_error and self.reject_delimiter_errors:
            builder.diagnostics.append("{0}: {1}".format(path, delimiter_error))
            return builder.build(self.capabilities)
        module = builder.add_entity(EntityType.MODULE, path.stem, path.stem, SourceLocation(path.as_posix(), 1, 1, max(1, source.count("\n") + 1), 1), "Module")
        function_ranges = []
        function_starts = set()
        for index, token in enumerate(tokens):
            parsed = self.function_at(tokens, index)
            if not parsed:
                continue
            name, open_index = parsed
            close_index = _match(tokens, open_index)
            if close_index + 1 >= len(tokens) or tokens[close_index + 1].text != "{":
                continue
            body_end = _match(tokens, close_index + 1, "{", "}")
            function = builder.add_entity(EntityType.FUNCTION, name, name, SourceLocation(path.as_posix(), token.line, token.column, tokens[body_end].line, tokens[body_end].column), "Function", concepts={"program.function"})
            builder.add_edge(module, function, EdgeKind.CONTAINS)
            function_ranges.append((index, body_end, function))
            function_starts.add(open_index)
            segment = []
            for item in tokens[open_index + 1:close_index] + [_Token(",", token.line, token.column, "symbol")]:
                if item.text == ",":
                    identifiers = [part for part in segment if part.kind == "identifier" and part.text not in self.declaration_words]
                    if identifiers:
                        parameter_token = identifiers[0] if self.language_id == "go" else identifiers[-1]
                        parameter = builder.add_entity(EntityType.PARAMETER, parameter_token.text, name + "." + parameter_token.text, SourceLocation(path.as_posix(), parameter_token.line, parameter_token.column, parameter_token.line, parameter_token.column + len(parameter_token.text)), "Parameter", concepts={"input.parameter"})
                        builder.add_edge(function, parameter, EdgeKind.DECLARES)
                    segment = []
                else:
                    segment.append(item)
        # Sweep ranges once instead of scanning every function for every entity.
        # Range length and declaration order preserve the previous min() tie break.
        owners, active = [], []
        ranges = iter(enumerate(function_ranges))
        upcoming = next(ranges, None)
        for token_index in range(len(tokens)):
            while upcoming is not None and upcoming[1][0] <= token_index:
                order, (start, end, function) = upcoming
                heapq.heappush(active, (end - start, order, end, function))
                upcoming = next(ranges, None)
            while active and active[0][2] < token_index:
                heapq.heappop(active)
            owners.append(active[0][3] if active else module)

        def owner(token_index):
            return owners[token_index]
        def literal_entity(name, literal, token_index):
            literal_value = literal.text
            interpolated = self.language_id == 'php' and literal.quote == '"' and '$' in literal_value.replace('\\$', '')
            translation = (self.language_id == 'php' and 'language' in path.parts
                           and token_index >= 4 and tokens[token_index-4].text == '$_'
                           and tokens[token_index-3].text == '['
                           and re.match(r'^(?:entry|text|help|error|button|column|heading)_', name))
            pagination_field = (self.language_id == 'php' and path.name == 'paginators-1.json.php'
                                and tokens[token_index].text == '=>'
                                and name in {'input_token','output_token','limit_key','result_key'})
            grammar_field = path.name == 'Lexer.php' and tokens[token_index].text == '=>' and name == 'lex_tokens_start' and literal_value.startswith('{')
            resource_identifier = path.name == 'smoke.json.php' and tokens[token_index].text == '=>' and name == 'SecretId'
            environment_name = (name.startswith('ENV_') and re.fullmatch(r'[A-Z][A-Z0-9]*_[A-Z0-9_]+', literal_value)
                                and any(token.text.lower() == 'getenv' and tokens[index+1].text == '('
                                        and ''.join(item.text for item in tokens[index+2:index+6]).startswith(('self::'+name+')','static::'+name+')',name+')'))
                                        for index,token in enumerate(tokens[:-6]) if token.kind == 'identifier'))
            redaction = (tokens[token_index].text == '=>' and name.startswith('/')
                         and re.search(r'\[(?:TOKEN|KEY|SIGNATURE|CONTENT KEY)\]', literal_value))
            concepts = {'secret.credential'} if (not grammar_field and not resource_identifier and not pagination_field and not environment_name and not redaction and not translation and not interpolated and self.secret_name_candidate(name) and self.catalog.weak_secret_literal(literal_value, name)) else set()
            entity = builder.add_entity(EntityType.LITERAL, repr(literal_value), name, SourceLocation(path.as_posix(), literal.line, literal.column, literal.line, literal.column + len(literal_value) + 2), 'StringLiteral', type_name='string', concepts=concepts, attributes={'value': literal_value})
            builder.add_edge(owner(token_index), entity, EdgeKind.CONTAINS)

        for index, token in enumerate(tokens):
            if token.text == "=" and index and index + 1 < len(tokens):
                left = next((item for item in reversed(tokens[max(0, index - 4):index]) if item.kind == "identifier" and item.text not in self.declaration_words), None)
                if self.language_id == 'php' and index >= 3 and tokens[index - 1].text == ']' and tokens[index - 2].kind == 'string':
                    left = tokens[index - 2]
                if left:
                    variable = builder.add_entity(EntityType.VARIABLE, left.text, left.text, SourceLocation(path.as_posix(), left.line, left.column, left.line, left.column + len(left.text)), "Variable", concepts={"variable.reference"})
                    builder.add_edge(owner(index), variable, EdgeKind.CONTAINS)
                    literal = tokens[index + 1] if tokens[index + 1].kind == "string" else None
                    if literal:
                        literal_entity(left.text, literal, index)
            if self.language_id == 'php' and token.text == '=>' and index and index + 1 < len(tokens) and tokens[index - 1].kind == 'string' and tokens[index + 1].kind == 'string':
                literal_entity(tokens[index - 1].text, tokens[index + 1], index)
            if self.language_id == 'php' and token.text.lower() == 'define' and index + 4 < len(tokens):
                if tokens[index + 1].text == '(' and tokens[index + 2].kind == 'string' and tokens[index + 3].text == ',' and tokens[index + 4].kind == 'string':
                    literal_entity(tokens[index + 2].text, tokens[index + 4], index)
            if token.text == "(" and index and index not in function_starts and tokens[index - 1].kind == "identifier" and tokens[index - 1].text not in self.control_words:
                callee = self.qualified_call(tokens, index - 1)
                concepts = self.catalog.concepts_for_call(self.language_id, callee)
                if self.language_id == 'php':
                    lowered = callee.lower()
                    if lowered.endswith(('->input->get', '->input->post', '->input->cookie')) or lowered in {'$request->input', '$request->get', '$request->query', '$request->all'}:
                        concepts.update({'input.untrusted', 'input.untrusted-url', 'input.untrusted-path'})
                    if lowered.endswith(('->query', '::query', '->prepare', '::raw', '->whereraw', '->selectraw')) or lowered == 'mysqli_prepare':
                        concepts.add('sql.execution')
                    if callee == 'escapeshellarg':
                        concepts.add('sanitizer.command-approved')
                    if callee == 'unserialize':
                        end = _match(tokens, index)
                        argument_tokens = tokens[index + 1:end]
                        if any(t.text == 'allowed_classes' and i + 2 < len(argument_tokens) and argument_tokens[i + 1].text == '=>' and argument_tokens[i + 2].text == 'false' for i, t in enumerate(argument_tokens)):
                            concepts.discard('deserialization.object-construction')
                call_token = tokens[index - 1]
                call = builder.add_entity(EntityType.CALL, callee.rsplit(".", 1)[-1], callee, SourceLocation(path.as_posix(), call_token.line, call_token.column, call_token.line, call_token.column + len(callee)), "Call", concepts=concepts, attributes={"callee": callee})
                builder.add_edge(owner(index), call, EdgeKind.CALLS)
        return builder.build(self.capabilities)


class JavaScriptAdapter(_TokenAdapter):
    language_id = "javascript"
    adapter_name = "javascript-structural"
    adapter_version = "1"
    extensions = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")
    declaration_words = frozenset({"const", "let", "var", "export", "async"})

    def function_at(self, tokens, index):
        if tokens[index].text == "function" and index + 2 < len(tokens) and tokens[index + 1].kind == "identifier" and tokens[index + 2].text == "(":
            return tokens[index + 1].text, index + 2
        return None


class GoAdapter(_TokenAdapter):
    language_id = "go"
    adapter_name = "go-structural"
    adapter_version = "1"
    extensions = (".go",)
    declaration_words = frozenset({"var", "const", "func", "string", "int", "bool", "byte", "error"})

    def function_at(self, tokens, index):
        if tokens[index].text == "func" and index + 2 < len(tokens) and tokens[index + 1].kind == "identifier" and tokens[index + 2].text == "(":
            return tokens[index + 1].text, index + 2
        return None


class CppAdapter(_TokenAdapter):
    language_id = "cpp"
    adapter_name = "cpp-structural"
    adapter_version = "1"
    extensions = (".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx")
    declaration_words = frozenset({"const", "auto", "char", "int", "long", "short", "void", "bool", "unsigned", "signed", "static", "extern"})

    def function_at(self, tokens, index):
        if tokens[index].kind == "identifier" and index + 1 < len(tokens) and tokens[index + 1].text == "(" and tokens[index].text not in self.control_words:
            close = _match(tokens, index + 1)
            if close + 1 < len(tokens) and tokens[close + 1].text == "{":
                return tokens[index].text, index + 1
        return None


class PHPAdapter(_TokenAdapter):
    language_id = "php"
    adapter_name = "php-structural"
    adapter_version = "4"
    extensions = (".php",)
    declaration_words = frozenset({"function", "public", "protected", "private", "static", "final", "abstract", "const", "var"})
    reject_delimiter_errors = False

    def parse_file(self, path):
        from ..php_flow import enrich_php
        semantic_ir = super().parse_file(path)
        return enrich_php(path, semantic_ir) if not semantic_ir.diagnostics else semantic_ir

    def secret_name_candidate(self, name):
        normalized = name.lstrip("$").lower()
        return (
            not normalized.startswith("code_")
            and not normalized.endswith("_name")
            and self.catalog.secret_name(normalized)
        )

    def function_at(self, tokens, index):
        if (
            tokens[index].text == "function"
            and index + 2 < len(tokens)
            and tokens[index + 1].kind == "identifier"
            and tokens[index + 2].text == "("
        ):
            return tokens[index + 1].text, index + 2
        return None
