"""Bounded PHP flow analysis with branch joins and explicit project call edges.

The graph is a conservative may-flow model, not a proof of branch feasibility.
Unsupported syntax is retained as an analysis limit instead of a safe verdict.
"""
from dataclasses import replace
from collections import deque
from utils.source_cache import read_source_text
import re

from .adapters.tokenized import _lex
from .ast import EntityType
from .ir import IRBuilder, SourceLocation, SemanticEdge, EdgeKind
from .flow import DataFlowGraph, FlowEdge
from .cache import AnalysisBudgetExceeded
from .catalog import SemanticCatalog

INPUTS = {'$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES', '$_SERVER'}
INPUT_CONCEPTS = {'input.untrusted', 'input.untrusted-url', 'input.untrusted-path'}
SINK_CONCEPTS = {'command.execution', 'sql.execution', 'network.outbound-request',
                 'filesystem.access', 'deserialization.object-construction',
                 'dynamic.evaluation', 'output.html', 'redirect.destination',
                 'code.inclusion', 'model.mass-assignment', 'variable.extraction', 'regex.execution', 'xml.external-entities'}


def _merge(*environments):
    result = {}
    for environment in environments:
        for name, values in environment.items():
            result.setdefault(name, set()).update(values)
    return result


def _normalize_template_controls(tokens):
    """Normalize PHP's colon/end-keyword blocks without changing source locations."""
    result, pending, parentheses = [], '', 0
    endings = {'endif', 'endwhile', 'endfor', 'endforeach', 'endswitch'}
    for token in tokens:
        lower = token.text.lower()
        if token.kind == 'identifier' and lower in endings:
            result.append(replace(token, text='}', kind='symbol'))
            pending = ''
            continue
        if token.kind == 'identifier' and lower in {'if', 'elseif', 'else', 'while', 'for', 'foreach', 'switch'}:
            pending = lower
        if token.kind == 'symbol':
            if token.text == '(': parentheses += 1
            elif token.text == ')': parentheses -= 1
            elif token.text == ':' and pending and parentheses == 0:
                if pending in {'else', 'elseif'}:
                    # Insert the previous branch's closing brace before its keyword.
                    marker = next((i for i in range(len(result)-1,-1,-1) if result[i].text.lower() == pending),len(result))
                    result.insert(marker,replace(token,text='}',kind='symbol'))
                result.append(replace(token,text='{'))
                pending = ''
                continue
            elif token.text in {'{', ';'} and parentheses == 0:
                pending = ''
        result.append(token)
    return result


class _Limits(dict):
    def __init__(self, walker):
        super().__init__()
        self.walker = walker

    def add(self, reason):
        self.setdefault(self.walker.scope, set()).add(reason)


class _Walker:
    def __init__(self, path, semantic_ir):
        self.path = path
        self.tokens = _normalize_template_controls(_lex(read_source_text(path, encoding='utf-8'), php=True))
        self.builder = IRBuilder('php-flow', 'php-structured-flow', '3')
        self.catalog = SemanticCatalog.load()
        self.nodes, self.edges, self.functions = {}, {}, []
        self.scope = '<module>'
        self.limits = _Limits(self)
        self.class_name = ''
        self.namespace = ''
        self.imports = {}
        self.return_ids = set()
        self.object_types = {}
        self.pairs = {}
        stack = []
        for index, token in enumerate(self.tokens):
            if token.kind != 'symbol':
                continue
            if token.text in {'(', '[', '{'}:
                stack.append(index)
            elif token.text in {')', ']', '}'}:
                if not stack or self.tokens[stack[-1]].text != {')': '(', ']': '[', '}': '{'}[token.text]:
                    self.limits.add('unbalanced PHP delimiters')
                else:
                    opening = stack.pop()
                    self.pairs[opening] = index
        if stack:
            self.limits.add('unbalanced PHP delimiters')
        if any(self.text(i) == '<' and self.text(i+1) == '<' and self.text(i+2) == '<' for i in range(len(self.tokens))):
            self.limits.add('PHP heredoc/nowdoc requires string normalization')
        if any(t.kind == 'identifier' and t.text.lower() in {'fn', 'match'} for t in self.tokens):
            self.limits.add('PHP arrow function or match expression requires expression lowering')
        self.semantic_ir = semantic_ir
        self.steps = 0

    def tick(self):
        self.steps += 1
        if self.steps > 200000 or len(self.edges) > 200000:
            raise AnalysisBudgetExceeded('PHP statement or edge budget exceeded')

    def text(self, index):
        return self.tokens[index].text if 0 <= index < len(self.tokens) else ''

    def node(self, index, role, name=None, concepts=(), attributes=None, kind=EntityType.VARIABLE):
        key = (index, role, self.scope)
        if key not in self.nodes:
            token = self.tokens[index]
            self.nodes[key] = self.builder.add_entity(kind, name or token.text, name or token.text,
                SourceLocation(self.path.as_posix(), token.line, token.column, token.line, token.column + len(token.text)),
                role, concepts=concepts, attributes=dict(attributes or {}, php_scope=self.scope))
        return self.nodes[key]

    def edge(self, source, target, kind='reference', argument=None, callsite=''):
        if source != target:
            self.edges[(source, target, kind, argument, callsite)] = FlowEdge(source, target, kind, argument, callsite)

    def attach(self, values, node, kind='argument', argument=None):
        for value in values:
            self.edge(value, node.entity_id, kind, argument)
        return {node.entity_id}

    def split(self, start, end, separator=','):
        pieces, first, cursor = [], start, start
        while cursor < end:
            if cursor in self.pairs:
                cursor = self.pairs[cursor] + 1
                continue
            if self.text(cursor) == separator and self.tokens[cursor].kind == 'symbol':
                pieces.append((first, cursor))
                first = cursor + 1
            cursor += 1
        pieces.append((first, end))
        return pieces

    def call_concepts(self, callee, args, argument_names=()):
        lower = callee.lower().lstrip('\\')
        concepts = self.catalog.concepts_for_call('php', lower)
        if (lower.endswith(('->input->get', '->input->post', '->input->get_post', '->input->post_get', '->input->cookie', '->input->raw_input_stream'))
                or re.search(r'\$(?:request|req)->(?:input|get|post|query|all|cookie|file|json|param)$', lower)
                or lower in {'request::input', 'request::get', 'request::query', 'request', 'input::get', 'filter_input'}
                or re.search(r'\$(?:request|req)->(?:query|request|cookies|files|headers)->get$', lower)):
            concepts.update(INPUT_CONCEPTS)
        if lower.endswith(('->query', '::query', '->prepare', '::raw', '->whereraw', '->selectraw', '::selectraw', '::select', '::statement', '::unprepared', '->havingraw', '->orderbyraw', '->exec', '->executequery', '->executestatement', '->createcommand')):
            concepts.add('sql.execution')
        # HTML escaping is contextual; ENT_NOQUOTES must not prove quoted-attribute safety.
        if lower in {'htmlspecialchars', 'htmlentities', 'esc_html', 'esc_attr', 'html_escape', 'e'}:
            if not any(self.text(i) == 'ENT_NOQUOTES' for a, b in args for i in range(a, b)):
                concepts.add('sanitizer.contextual-output-encoding')
        if lower in {'intval', 'floatval'}:
            concepts.update({'sanitizer.sql-parameterization', 'sanitizer.command-approved', 'sanitizer.contextual-output-encoding'})
        if lower == 'escapeshellarg':
            concepts.add('sanitizer.command-approved')
        if lower in {'redirect', 'wp_redirect'} and args:
            concepts.add('redirect.destination')
        if lower in {'md5', 'sha1'} and args and not any(argument_names) and (
                len(args) == 1 or len(args) == 2 and args[1][1] == args[1][0]+1 and self.text(args[1][0]).lower() in {'false', '0'}):
            # Default hexadecimal digests cannot contain path separators or
            # traversal components. Raw binary output is not a path guard.
            # This does not make the hash cryptographically suitable.
            concepts.add('sanitizer.path-containment')
        if lower == 'header' and args:
            first = self.tokens[args[0][0]]
            if first.kind == 'string':
                name = re.match(r'^\s*([A-Za-z][A-Za-z0-9-]*)\s*:', first.text)
                if name and name.group(1).lower() != 'location':
                    # A filename or length response header is not a redirect.
                    # Unknown/dynamic header names retain the conservative sink.
                    concepts.discard('redirect.destination')
        if lower in {'file_get_contents', 'fopen', 'readfile', 'file'} and args:
            first = self.tokens[args[0][0]]
            if first.kind == 'string' and re.match(r'^(?:/|[A-Za-z0-9_.-]+/|[A-Za-z]:[\\/])', first.text):
                # A fixed local-path prefix cannot become a URL scheme. Keep
                # filesystem access so attacker-controlled suffixes are reviewed.
                concepts.discard('network.outbound-request')
        if lower.endswith(('->where','->andwhere','->orwhere')) and args and self.text(args[0][0]) != '[':
            concepts.add('sql.execution')
        if lower.endswith('->setattributes') or lower == '$model->load':
            concepts.add('model.mass-assignment')
        if lower == 'parse_str' and len(args) > 1:
            concepts.discard('variable.extraction')
        if lower == 'proc_open' and args and self.text(args[0][0]) == '[':
            # PHP's argv form bypasses the shell; data arguments are not shell text.
            first = self.split(args[0][0]+1, args[0][1]-1)[0]
            if first[1] == first[0]+1 and self.tokens[first[0]].kind == 'string':
                concepts.discard('command.execution')
        if lower == 'ini_set' and len(args) > 1:
            setting = ''.join(self.text(i) for i in range(*args[0])).lower()
            value = ''.join(self.text(i) for i in range(*args[1])).lower()
            if setting in {'display_errors', 'display_startup_errors', 'register_globals', 'allow_url_include'} and value in {'1', 'true', 'on'}:
                concepts.add('php.insecure-setting')
        if lower == 'unserialize' and len(args) == 2 and not any(argument_names):
            from .php_call_review import _classes_disabled
            a, b = args[1]
            if _classes_disabled(self.tokens[a:b]):
                concepts.discard('deserialization.object-construction')
        if lower in {'preg_replace', 'preg_filter'}:
            concepts.discard('regex.execution')
            if args and any(self.tokens[i].kind == 'string' and re.search(r'[/#~]([a-z]*e[a-z]*)$', self.text(i)) for i in range(*args[0])):
                concepts.add('dynamic.evaluation')
        if lower.endswith(('->loadxml', '->load', '->xml')) or lower in {'simplexml_load_string', 'simplexml_load_file'}:
            if any(self.text(i) in {'LIBXML_NOENT', 'LIBXML_DTDLOAD'} for a, b in args for i in range(a, b)):
                concepts.add('xml.external-entities')
        return concepts

    def configuration(self, index, name, start, end):
        key = name.lower().replace("'", '').replace('"', '')
        values = [self.text(i).lower() for i in range(start,end)]
        enabled = len(values) == 1 and values[0] in {'true','1','on'}
        debug_key = key in {'app_debug','wp_debug','yii_debug','$debug'} or key.endswith(('[debug]', '[display_errors]'))
        if debug_key and enabled:
            self.node(index,'Setting',name,{'php.insecure-setting'},kind=EntityType.CALL)
        if any(marker in key for marker in ('allowed_origins','allowedorigin','cors_origin')) and '*' in values:
            self.node(index,'Setting',name,{'web.permissive-cors'},kind=EntityType.CALL)

    def expression(self, start, end, env):
        self.tick()
        if end <= start:
            return set()
        # Assignment expressions (including concatenation assignment) update the environment.
        for a, b in self.split(start, end, '=')[:-1]:
            if self.text(b-1) not in {'=', '!', '<', '>'} and self.tokens[a].kind == 'identifier' and self.text(a).startswith('$'):
                target_end = b - 1 if self.text(b-1) in {'.', '+', '-'} else b
                key = ''.join(self.text(i) for i in range(a, target_end))
                values = self.expression(b+1, end, env)
                if self.text(b+1).lower() == 'new':
                    self.object_types[(self.scope,key)] = self.text(b+2).lower()
                if target_end != b:
                    values |= self.expression(a, target_end, env)
                self.configuration(a,key,b+1,end)
                node = self.node(a, 'Assignment', key)
                env[key] = self.attach(values, node, 'assignment')
                if '[' in key:
                    base = key.split('[',1)[0]
                    env[base] = set().union(*(v for k,v in env.items() if k.startswith(base+'[')))
                return env[key]
        values, cursor = set(), start
        while cursor < end:
            token = self.tokens[cursor]
            word = token.text.lower()
            if token.kind == 'identifier' and word in {'eval', 'assert', 'include', 'include_once', 'require', 'require_once', 'echo', 'print'}:
                if self.text(cursor+1) != '(':
                    concepts = {'output.html'} if word in {'echo', 'print'} else {'code.inclusion'} if word.startswith(('include','require')) else {'dynamic.evaluation'}
                    call = self.node(cursor, 'Call', word, concepts, {'callee': word}, EntityType.CALL)
                    self.attach(self.expression(cursor+1, end, env), call)
                    return values | {call.entity_id}
            if token.kind == 'symbol' and token.text == '(' and cursor in self.pairs:
                close = self.pairs[cursor]
                # Casts remove injection-relevant string syntax, but retain evidence.
                if close == cursor+2 and self.text(cursor+1).lower() in {'int', 'integer', 'float', 'double', 'bool', 'boolean'}:
                    cast = self.node(cursor, 'Cast', self.text(cursor+1), {'sanitizer.sql-parameterization', 'sanitizer.command-approved', 'sanitizer.contextual-output-encoding'})
                    return values | self.attach(self.expression(close+1, end, env), cast)
                values |= self.expression(cursor+1, min(close, end), env)
                cursor = close+1
                continue
            if token.kind == 'identifier':
                tail = cursor
                while tail+2 < end and self.text(tail+1) in {'->', '?->', '::', '\\'} and self.tokens[tail+2].kind == 'identifier':
                    tail += 2
                callee = ''.join(self.text(i) for i in range(cursor, tail+1))
                if cursor >= 2 and self.text(cursor-1) in {'->','?->'} and self.text(cursor-2) == ')':
                    callee = '<result>->' + callee
                if tail+1 < end and self.text(tail+1) == '(' and tail+1 in self.pairs:
                    close = self.pairs[tail+1]
                    args = self.split(tail+2, close) if close > tail+2 else []
                    argument_names = tuple(self.text(a) if a+1 < b and self.text(a+1) == ':' else '' for a,b in args)
                    args = [(a+2,b) if name else (a,b) for (a,b),name in zip(args,argument_names)]
                    if any(self.text(a) == '...' for a,b in args):
                        self.limits.add('PHP argument unpacking requires runtime argument resolution')
                    concepts = self.call_concepts(callee, args, argument_names)
                    call = self.node(tail, 'Call', callee, concepts,
                                     {'callee': callee, 'php_class': self.class_name, 'php_namespace':self.namespace, 'php_imports':tuple(sorted(self.imports.items())), 'php_receiver_type': self.object_types.get((self.scope,callee.rsplit('->',1)[0]),''), 'php_arguments': len(args), 'php_argument_names':argument_names}, EntityType.CALL)
                    arguments = [self.expression(a, b, env) for a, b in args]
                    lower = callee.lower()
                    if lower == 'define' and len(args) > 1:
                        self.configuration(tail,''.join(self.text(i) for i in range(*args[0])),*args[1])
                    if lower == 'header' and args:
                        a,b = args[0]
                        if any(self.tokens[i].kind == 'string' and re.match(r'(?i)^access-control-allow-origin:\s*\*$',self.text(i)) for i in range(a,b)):
                            self.node(tail,'CorsHeader',callee,{'web.permissive-cors'},kind=EntityType.CALL)
                    selected = list(range(len(args)))
                    if concepts & SINK_CONCEPTS:
                        selected = [1] if lower in {'mysqli_query', 'mysqli_multi_query', 'mysqli_prepare', 'pg_query_params'} and len(args) > 1 else [0]
                        if lower == 'pg_query' and len(args) > 1:
                            selected = [1]
                        if lower == 'copy' and len(args) > 1:
                            selected = [0, 1]
                        if lower == 'move_uploaded_file' and len(args) > 1:
                            # PHP verifies the source is an uploaded temporary file;
                            # traversal depends on the destination, not its contents.
                            selected = [1]
                        if lower in {'preg_replace', 'preg_filter', 'create_function'}:
                            selected = [1]
                        if lower in {'printf', 'vprintf'}:
                            selected = list(range(len(args)))
                    # Preserve all call arguments for resolved project methods, but keep sink roles precise.
                    for number, sources in enumerate(arguments):
                        for source in sources:
                            self.edge(source, call.entity_id, 'call-argument', number)
                        if number in selected:
                            self.attach(sources, call, 'argument', number)
                    if lower == 'curl_setopt' and len(args) >= 3:
                        option = ''.join(self.text(i) for i in range(*args[1]))
                        if option == 'CURLOPT_URL':
                            handle = ''.join(self.text(i) for i in range(*args[0]))
                            env['curl:'+handle] = arguments[2]
                    if lower == 'curl_setopt_array' and len(args) > 1:
                        handle = ''.join(self.text(i) for i in range(*args[0]))
                        a, b = args[1]
                        for i in range(a, b):
                            if self.text(i) == 'CURLOPT_URL' and self.text(i+1) == '=>':
                                stop = next((j for j in range(i+2,b) if self.text(j) == ','), b-1)
                                env['curl:'+handle] = self.expression(i+2,stop,env)
                    if lower == 'curl_exec' and args:
                        handle = ''.join(self.text(i) for i in range(*args[0]))
                        self.attach(env.get('curl:'+handle, set()), call)
                    if lower in {'include', 'include_once', 'require', 'require_once'}:
                        pass
                    if token.text.startswith('$') and tail == cursor:
                        self.limits.add('dynamic PHP callable requires runtime resolution')
                    if lower in {'file_get_contents', 'file', 'fread', 'fgets', 'stream_get_contents'} and arguments:
                        contents = self.node(tail, 'ReadContents', callee + ' contents')
                        values |= self.attach({call.entity_id}, contents, 'file-read')
                    else:
                        values.add(call.entity_id)
                    cursor = close+1
                    continue
                if token.text.startswith('$'):
                    # Track constant array slots independently; dynamic indexing conservatively reads the base.
                    key = callee
                    after = tail+1
                    while after < end and self.text(after) == '[' and after in self.pairs:
                        close = self.pairs[after]
                        key += ''.join(self.text(i) for i in range(after,close+1))
                        values |= self.expression(after+1,close,env) if token.text not in INPUTS else set()
                        after = close+1
                    concepts = INPUT_CONCEPTS if token.text in INPUTS else set()
                    upload_temporary = (token.text == '$_FILES' and
                            re.fullmatch(r'\$_FILES\[[^\[\]]+\]\[tmp_name\](?:\[[^\[\]]+\])*', key))
                    if upload_temporary:
                        # PHP assigns upload temporary paths. The uploaded contents
                        # become untrusted when read, but this path is not a
                        # client-selected URL or filename.
                        concepts = set()
                    node = self.node(cursor, 'Reference', key, concepts,
                                     {'php_upload_temporary_path': bool(upload_temporary)})
                    sources = env.get(key, env.get(callee,set()))
                    values |= self.attach(sources, node, 'reference')
                    cursor = after
                    continue
                cursor = tail+1
                continue
            if token.kind == 'string' and token.quote in {'"', '`'}:
                interpolated = set()
                for match in re.finditer(r'(?<!\\)\$[A-Za-z_][A-Za-z0-9_]*', token.text):
                    name = match.group()
                    node = self.node(cursor, 'Interpolation:'+name, name, INPUT_CONCEPTS if name in INPUTS else ())
                    interpolated |= self.attach(env.get(name,set()),node,'reference')
                if token.quote == '`':
                    call = self.node(cursor,'Call','backtick',{'command.execution'},{'callee':'backtick'},EntityType.CALL)
                    values |= self.attach(interpolated,call)
                else:
                    values |= interpolated
            cursor += 1
        return values

    def body_end(self, start, end):
        if self.text(start) == '{' and start in self.pairs:
            return self.pairs[start]+1
        cursor = start
        while cursor < end:
            if cursor in self.pairs:
                cursor = self.pairs[cursor]+1
                continue
            if self.text(cursor) == ';':
                return cursor+1
            cursor += 1
        return end

    def statement(self, start, end, env, depth):
        self.tick()
        if depth > 80:
            raise AnalysisBudgetExceeded('PHP syntax nesting budget exceeded')
        word = self.text(start).lower()
        if word == '{':
            close = self.pairs.get(start,end-1)
            state, stop = self.block(start+1,close,dict(env),depth+1)
            return close+1,state,stop
        # Visibility, return types and class modifiers do not change flow.
        if word in {'public','protected','private','static','final','abstract','readonly'}:
            return self.statement(start+1,end,env,depth+1)
        if word == 'namespace':
            boundary = next((i for i in range(start+1,end) if self.text(i) in {';', '{'}),end)
            previous=self.namespace
            self.namespace=''.join(self.text(i) for i in range(start+1,boundary)).lower()
            if self.text(boundary) == '{':
                result=self.statement(boundary,end,env,depth+1)
                self.namespace=previous
                return result
            return min(boundary+1,end),env,''
        if word == 'use':
            boundary=self.body_end(start,end)
            first=start+2 if self.text(start+1).lower() in {'function','const'} else start+1
            for a,b in self.split(first,boundary-1):
                alias_at=next((i for i in range(a,b) if self.text(i).lower()=='as'),b)
                name=''.join(self.text(i) for i in range(a,alias_at)).lstrip('\\').lower()
                alias=self.text(alias_at+1).lower() if alias_at<b else name.rsplit('\\',1)[-1]
                self.imports[alias]=name
            return boundary,env,''
        if word in {'class','trait','interface'}:
            opening = next((i for i in range(start+1,end) if self.text(i) == '{'),end)
            close = self.pairs.get(opening,end-1)
            previous = self.class_name
            self.class_name = (self.namespace+'\\' if self.namespace else '')+self.text(start+1)
            self.block(opening+1,close,{},depth+1)
            self.class_name = previous
            return close+1,env,''
        if word == 'function':
            opening = next((i for i in range(start+1,end) if self.text(i) == '('),end)
            closing = self.pairs.get(opening,opening)
            body = next((i for i in range(closing+1,end) if self.text(i) in {'{',';'}),end)
            if self.text(body) != '{':
                return min(body+1,end),env,''
            close = self.pairs.get(body,end-1)
            name = self.text(opening-1)
            if name in {'function','&'}:
                self.limits.add('PHP closures require captured-variable resolution')
                return close+1,env,''
            previous = self.scope,self.return_ids
            self.scope = (self.class_name+'::' if self.class_name else '')+name+'@'+str(start)
            self.return_ids = set()
            params, parameter_names, local = [], [], {}
            for a,b in self.split(opening+1,closing):
                index = next((i for i in range(a,b) if self.text(i).startswith('$')),None)
                if index is None:continue
                if any(self.text(i) == '&' for i in range(a,index)):
                    self.limits.add('PHP by-reference parameters require alias analysis')
                # Public framework controller arguments represent route inputs.
                route = 'controllers' in self.path.parts and not name.startswith('_')
                parameter = self.node(index,'Parameter',concepts=INPUT_CONCEPTS if route else (),kind=EntityType.PARAMETER)
                params.append(parameter.entity_id);parameter_names.append(self.text(index).lstrip('$'));local[self.text(index)]={parameter.entity_id}
            self.block(body+1,close,local,depth+1)
            function = self.node(start,'Function',name,attributes={'php_name':(self.namespace+'\\' if self.namespace and not self.class_name else '')+name.lower(), 'php_class':self.class_name.lower(), 'php_parameters':tuple(params), 'php_parameter_names':tuple(parameter_names), 'php_returns':tuple(sorted(self.return_ids))},kind=EntityType.FUNCTION)
            self.functions.append(function)
            self.scope,self.return_ids = previous
            return close+1,env,''
        if word in {'if','elseif'} and self.text(start+1) == '(':
            closing = self.pairs.get(start+1,start+1)
            self.expression(start+2,closing,env)
            truth = self.constant_truth(start+2,closing)
            body = closing+1
            true_env = self.guarded_environment(start+2,closing,env,True)
            false_env = self.guarded_environment(start+2,closing,env,False)
            if self.text(body) == ':':
                self.limits.add('PHP alternative control syntax requires normalization')
            next_index,left,left_stop = self.statement(body,end,true_env,depth+1) if truth is not False else (self.body_end(body,end),dict(env),'dead')
            right,right_stop = false_env,''
            if self.text(next_index).lower() in {'else','elseif'}:
                alternate = next_index if self.text(next_index).lower() == 'elseif' else next_index+1
                if truth is True:
                    next_index = self.skip_statement(alternate,end)
                    right_stop = 'dead'
                else:
                    next_index,right,right_stop = self.statement(alternate,end,false_env,depth+1)
            elif truth is True:
                right_stop = 'dead'
            live = [state for state,stop in [(left,left_stop),(right,right_stop)] if not stop]
            return next_index,_merge(*live) if live else _merge(left,right),'' if live else left_stop or right_stop
        if word in {'while','for','foreach','do'}:
            body = start+1 if word == 'do' else self.pairs.get(start+1,start+1)+1
            condition_start, condition_end = (start+2,body-1) if word != 'do' else (0,0)
            increment = None
            if word == 'for':
                parts = self.split(condition_start,condition_end,';')
                if len(parts) == 3:
                    self.expression(*parts[0],env)
                    condition_start,condition_end = parts[1]
                    increment = parts[2]
            self.expression(condition_start,condition_end,env)
            if word in {'while','for'} and self.constant_truth(condition_start,condition_end) is False:
                return self.body_end(body,end),env,''
            seed = dict(env)
            if word == 'foreach':
                as_index = next((i for i in range(condition_start,condition_end) if self.text(i).lower() == 'as'),None)
                if as_index is not None:
                    values = self.expression(condition_start,as_index,env)
                    for i in range(as_index+1,condition_end):
                        if self.text(i).startswith('$'):
                            seed[self.text(i)] = self.attach(values,self.node(i,'LoopVariable'),'assignment')
            state = seed
            for iteration in range(16):
                next_index,result,stop = self.statement(body,end,dict(state),depth+1)
                if stop in {'return','throw','break'}:
                    break
                if increment:
                    self.expression(*increment,result)
                joined = _merge(seed,result)
                if joined == state:
                    break
                state = joined
            else:
                raise AnalysisBudgetExceeded('PHP loop fixed-point budget exceeded')
            if word == 'do':
                if self.text(next_index).lower() == 'while':
                    next_index = self.pairs.get(next_index+1,next_index+1)+2
                return next_index,result,stop if stop in {'return','throw'} else ''
            if stop in {'return','throw'}:
                return next_index,env,''
            return next_index,_merge(env,result),''
        if word == 'switch':
            closing = self.pairs.get(start+1,start+1)
            self.expression(start+2,closing,env)
            opening = closing+1; close = self.pairs.get(opening,end-1)
            starts=[]; cursor=opening+1
            while cursor<close:
                if self.text(cursor).lower() in {'case','default'}:
                    colon=next((i for i in range(cursor+1,close) if self.text(i)==':'),close)
                    starts.append((colon+1,cursor));cursor=colon+1
                elif cursor in self.pairs:cursor=self.pairs[cursor]+1
                else:cursor+=1
            states=[env];fallthrough={}
            for n,(a,_) in enumerate(starts):
                b=starts[n+1][1] if n+1<len(starts) else close
                result,stop=self.block(a,b,_merge(env,fallthrough),depth+1)
                if stop not in {'return','throw'}:states.append(result)
                fallthrough=result if not stop else {}
            return close+1,_merge(*states),''
        if word == 'try':
            next_index,result,stop=self.statement(start+1,end,dict(env),depth+1)
            states=[] if stop else [result]
            while self.text(next_index).lower() == 'catch':
                closing=self.pairs.get(next_index+1,next_index+1)
                next_index,caught,catch_stop=self.statement(closing+1,end,_merge(env,result),depth+1)
                if not catch_stop:states.append(caught)
            joined=_merge(*states) if states else result
            if self.text(next_index).lower() == 'finally':
                next_index,joined,final_stop=self.statement(next_index+1,end,joined,depth+1)
                if final_stop:stop=final_stop
            return next_index,joined,'' if states else stop
        if word in {'goto','yield','global'}:
            self.limits.add('PHP '+word+' requires runtime state resolution')
        if word in {'namespace','use'}:
            # Namespace aliases are resolved only when an unambiguous project symbol exists.
            pass
        stop_index=self.body_end(start,end)
        expression_end=stop_index-1 if self.text(stop_index-1)==';' else stop_index
        if word == 'return':
            values=self.expression(start+1,expression_end,env)
            result=self.node(start,'Return','return')
            self.attach(values,result,'return');self.return_ids.add(result.entity_id)
        else:
            self.expression(start,expression_end,env)
        return stop_index,env,word if word in {'return','throw','exit','die','break','continue'} else ''

    def skip_statement(self,start,end):
        if self.text(start).lower() in {'if','elseif'}:
            closing=self.pairs.get(start+1,start+1)
            result=self.skip_statement(closing+1,end)
            if self.text(result).lower()=='else':return self.skip_statement(result+1,end)
            if self.text(result).lower()=='elseif':return self.skip_statement(result,end)
            return result
        return self.body_end(start,end)

    def guarded_environment(self, start, end, env, branch):
        """Refine only explicit numeric or literal allowlist checks on their passing path."""
        negate = self.text(start) == '!'
        call_start = start+1 if negate else start
        name = self.text(call_start).lower()
        if branch == negate or self.text(call_start+1) != '(':
            return dict(env)
        close = self.pairs.get(call_start+1)
        if close != end-1:
            return dict(env)
        args = self.split(call_start+2,close)
        if not args or args[0][1] != args[0][0]+1 or not self.text(args[0][0]).startswith('$'):
            return dict(env)
        concepts = {'sanitizer.sql-parameterization','sanitizer.command-approved','sanitizer.contextual-output-encoding'}
        if name == 'in_array' and len(args) == 3:
            a,b = args[1]
            literals = self.split(a+1,b-1) if self.text(a) == '[' and self.text(b-1) == ']' else []
            if not literals or any(y != x+1 or self.tokens[x].kind not in {'string','number'} for x,y in literals) or self.text(args[2][0]).lower() != 'true':
                return dict(env)
            concepts.update({'sanitizer.path-containment','policy.destination-allowlist'})
        elif name != 'ctype_digit':
            return dict(env)
        variable = self.text(args[0][0])
        refined = dict(env)
        guard = self.node(call_start,'Guard:'+str(branch),name,concepts)
        refined[variable] = self.attach(self.expression(*args[0],env),guard,'validated-branch')
        return refined

    def constant_truth(self,start,end):
        text=''.join(self.text(i) for i in range(start,end)).lower()
        if text in {'false','0','null','!true'}:return False
        if text in {'true','1','!false'}:return True
        return None

    def block(self,start,end,env,depth=0):
        cursor=start
        while cursor<end:
            if self.text(cursor) in {';', '}'}:
                cursor+=1;continue
            next_index,env,stop=self.statement(cursor,end,env,depth)
            if next_index<=cursor:raise AnalysisBudgetExceeded('PHP parser made no progress')
            cursor=next_index
            if stop:return env,stop
        return env,''

    def build(self):
        self.block(0,len(self.tokens),{})
        # Keep literal security evidence from the structural adapter; use reachable calls from this walker.
        entities=[e for e in self.semantic_ir.entities if e.kind not in {EntityType.CALL,EntityType.FUNCTION,EntityType.PARAMETER}]
        entities += [replace(e,language='php') for e in self.builder.entities]
        entities=[replace(e,attributes=e.attributes+(('flow_incomplete',tuple(sorted(self.limits.get('<module>',())))),)) if e.kind==EntityType.MODULE else replace(e,attributes=e.attributes+(('php_limits',tuple(sorted(self.limits.get(e.attribute('php_scope'),())))),)) for e in entities]
        edges=tuple(SemanticEdge(e.source_id,e.target_id,EdgeKind.DERIVES_FROM,(('flow_kind',e.kind),('argument',e.argument),('callsite',e.callsite))) for e in self.edges.values())
        return replace(self.semantic_ir,entities=tuple(entities),edges=edges)


def enrich_php(path,semantic_ir):
    return _Walker(path,semantic_ir).build()


class PHPDataFlowProvider:
    def build(self,root,semantic_ir):
        entities={e.entity_id:e for e in semantic_ir.entities}
        functions=[e for e in entities.values() if e.native_kind=='Function' and e.attribute('php_name')]
        calls=[e for e in entities.values() if e.kind==EntityType.CALL]
        function_index={}
        for function in functions:
            function_index.setdefault((function.attribute('php_name'),function.attribute('php_class','')),[]).append(function)
        raw=[FlowEdge(e.source_id,e.target_id,dict(e.attributes)['flow_kind'],dict(e.attributes).get('argument')) for e in semantic_ir.edges if 'flow_kind' in dict(e.attributes)]
        resolved={}
        for call in calls:
            callee=call.attribute('callee','').lower().lstrip('\\')
            class_name=''
            if '::' in callee:
                class_name,name=callee.rsplit('::',1)
                if class_name in {'self','static'}:class_name=call.attribute('php_class','').lower()
            elif '->' in callee:
                receiver,name=callee.rsplit('->',1)
                class_name=call.attribute('php_class','').lower() if receiver=='$this' else call.attribute('php_receiver_type') or receiver.rsplit('->',1)[-1].lstrip('$')
            else:name=callee
            namespace=call.attribute('php_namespace','')
            imports=dict(call.attribute('php_imports',()))
            if class_name and class_name not in {'self','static'}:
                first,*rest=class_name.split('\\')
                class_name=imports.get(first, (namespace+'\\'+first) if namespace and not class_name.startswith(namespace+'\\') else first)+('\\'+'\\'.join(rest) if rest else '')
                # $this is already fully qualified.
                if callee.startswith('$this->') and callee.count('->') == 1:
                    class_name=call.attribute('php_class','').lower()
            if not class_name:
                first,*rest=name.split('\\')
                imported=imports.get(first)
                if imported:name=imported+('\\'+'\\'.join(rest) if rest else '')
                elif namespace and function_index.get((namespace+'\\'+name,'')):name=namespace+'\\'+name
            options=function_index.get((name,class_name),[])
            if not class_name:
                local=[f for f in options if f.location.path==call.location.path]
                options=local or options
            if len(options)==1:resolved[call.entity_id]=options[0]
        for call in calls:
            if call.entity_id not in resolved and any(call.attribute('php_argument_names',())) and call.concepts & SINK_CONCEPTS:
                entities[call.entity_id]=replace(call,attributes=call.attributes+(('php_limits',tuple(call.attribute('php_limits',()))+('PHP named library arguments require API signature resolution',)),))
        edges=[]
        for edge in raw:
            if edge.target_id in resolved:
                if edge.kind=='call-argument':
                    params=resolved[edge.target_id].attribute('php_parameters',())
                    names=entities[edge.target_id].attribute('php_argument_names',())
                    position=edge.argument
                    if position is not None and position<len(names) and names[position]:
                        param_names=resolved[edge.target_id].attribute('php_parameter_names',())
                        position=param_names.index(names[position]) if names[position] in param_names else None
                    if position is not None and position<len(params):
                        edges.append(FlowEdge(edge.source_id,params[position],'argument-parameter',callsite=edge.target_id))
            elif edge.kind!='call-argument':edges.append(edge)
        for call_id,function in resolved.items():
            for returned in function.attribute('php_returns',()):
                edges.append(FlowEdge(returned,call_id,'return-call',callsite=call_id))
            concepts=entities[call_id].concepts-SINK_CONCEPTS
            if entities[call_id].attribute('callee','').lower().lstrip('\\') in {'md5','sha1'}:
                concepts=concepts-{'sanitizer.path-containment'}
            entities[call_id]=replace(entities[call_id],concepts=concepts)
        # Reading tmp_name from an aliased PHP upload descriptor does not
        # inherit taint from the descriptor's client-controlled name/content.
        incoming = {}
        for edge in edges:
            incoming.setdefault(edge.target_id, []).append(edge.source_id)
        trusted_slots = set()
        for entity in entities.values():
            if entity.native_kind != 'Reference' or not re.search(r'\[tmp_name\](?:\[[^\[\]]+\])*$', entity.qualified_name) or entity.qualified_name.startswith('$_FILES'):
                continue
            pending_sources = list(incoming.get(entity.entity_id, ()))
            visited, roots = set(), []
            while pending_sources:
                identity = pending_sources.pop()
                if identity in visited:
                    continue
                visited.add(identity)
                source = entities[identity]
                if source.concepts & INPUT_CONCEPTS:
                    roots.append(source)
                else:
                    pending_sources.extend(incoming.get(identity, ()))
            client_fields = any(entities[identity].native_kind == 'Reference' and
                                re.search(r'\[(?:name|full_path|type|size|error)\]', entities[identity].qualified_name) for identity in visited)
            if roots and not client_fields and all(re.fullmatch(r'\$_FILES(?:\[[^\[\]]+\])?', root.qualified_name) for root in roots):
                trusted_slots.add(entity.entity_id)
        for identity in trusted_slots:
            entity = entities[identity]
            entities[identity] = replace(entity, attributes=entity.attributes + (('php_upload_temporary_path', True),))
        edges = [edge for edge in edges if edge.target_id not in trusted_slots]
        # Follow temporary-path provenance through aliases, stream handles and
        # resolved helper parameters/returns. Contents read from an upload are
        # untrusted data; the PHP-assigned filename itself is not attacker input.
        pending = deque(e.entity_id for e in entities.values() if e.attribute('php_upload_temporary_path'))
        if pending:
            origins = {identity: {entities[identity].location.path} for identity in pending}
            outgoing = {}
            for edge in edges:
                outgoing.setdefault(edge.source_id, []).append(edge.target_id)
            while pending:
                identity = pending.popleft()
                for target in outgoing.get(identity, ()):
                    known = origins.setdefault(target, set())
                    if not origins[identity] <= known:
                        known.update(origins[identity])
                        pending.append(target)
            for identity, paths in origins.items():
                entity = entities[identity]
                if entity.native_kind == 'ReadContents':
                    entities[identity] = replace(entity, concepts=entity.concepts | INPUT_CONCEPTS,
                        attributes=entity.attributes + (('php_input_origins', tuple(sorted(paths))),))
        return DataFlowGraph(entities,tuple(edges),max_path_depth=128)
