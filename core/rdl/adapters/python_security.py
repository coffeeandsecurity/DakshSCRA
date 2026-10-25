"""Argument-aware Python security semantics and narrowly proven local guards."""
import ast


INPUT_CONCEPTS = {'input.untrusted', 'input.untrusted-url', 'input.untrusted-path'}


def qualified_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = qualified_name(node.value)
        return prefix + '.' + node.attr if prefix else node.attr
    return ''


def proven_guards(tree, catalog):
    """Do not accept a validator's name as evidence that it validates anything."""
    result = {}
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        guards = [statement for statement in function.body if isinstance(statement, ast.If)
                  and any(isinstance(child, ast.Raise) for child in statement.body)]
        returns = [statement for statement in function.body if isinstance(statement, ast.Return)]
        if not guards or len(returns) != 1 or function.body.index(returns[0]) < function.body.index(guards[0]):
            continue
        concepts = catalog.concepts_for_call('python', function.name)
        test = guards[0].test
        # An alphanumeric result excludes shell metacharacters. The exact guarded
        # variable must be returned, and cannot be reassigned after the guard.
        returned = returns[0].value
        if function.body[function.body.index(guards[0]) + 1:function.body.index(returns[0])]:
            continue
        if ('sanitizer.command-approved' in concepts and isinstance(returned, ast.Name)
                and isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not)
                and isinstance(test.operand, ast.Call) and isinstance(test.operand.func, ast.Attribute)
                and test.operand.func.attr == 'isalnum'):
            receiver = test.operand.func.value
            if isinstance(receiver, ast.Call) and isinstance(receiver.func, ast.Attribute) and receiver.func.attr == 'replace':
                if len(receiver.args) == 2 and all(isinstance(a, ast.Constant) for a in receiver.args) and receiver.args[0].value == '_' and receiver.args[1].value == '':
                    receiver = receiver.func.value
            between = function.body[function.body.index(guards[0]) + 1:function.body.index(returns[0])]
            if isinstance(receiver, ast.Name) and receiver.id == returned.id and not between:
                result[function.name] = {'sanitizer.command-approved'}
        if 'sanitizer.path-containment' in concepts and isinstance(returned, ast.Name):
            if (isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.NotIn)
                    and isinstance(test.comparators[0], ast.Attribute) and test.comparators[0].attr == 'parents'
                    and qualified_name(test.comparators[0].value) == returned.id):
                assignments = [s for s in function.body[:function.body.index(guards[0])] if isinstance(s, ast.Assign)
                               and any(isinstance(t, ast.Name) and t.id == returned.id for t in s.targets)]
                if assignments and isinstance(assignments[-1].value, ast.Call) and isinstance(assignments[-1].value.func, ast.Attribute) and assignments[-1].value.func.attr == 'resolve':
                    result[function.name] = {'sanitizer.path-containment'}
        if 'policy.destination-allowlist' in concepts and isinstance(returned, ast.Name):
            assignments = [s for s in function.body if isinstance(s, ast.Assign) and isinstance(s.value, ast.Call)
                           and qualified_name(s.value.func) in {'urlparse', 'urllib.parse.urlparse'}
                           and len(s.value.args) == 1 and qualified_name(s.value.args[0]) == returned.id]
            if assignments and isinstance(test, ast.BoolOp) and isinstance(test.op, ast.Or):
                parsed = qualified_name(assignments[0].targets[0])
                comparisons = [c for c in test.values if isinstance(c, ast.Compare) and len(c.ops) == 1]
                scheme = any(qualified_name(c.left) == parsed + '.scheme' and isinstance(c.ops[0], ast.NotEq)
                             and isinstance(c.comparators[0], ast.Constant) and c.comparators[0].value == 'https' for c in comparisons)
                host = any(qualified_name(c.left) == parsed + '.hostname' and isinstance(c.ops[0], ast.NotIn)
                           and isinstance(c.comparators[0], ast.Name) and any(
                               isinstance(s, ast.Assign) and any(qualified_name(t) == c.comparators[0].id for t in s.targets)
                               and isinstance(s.value, (ast.Set, ast.Tuple, ast.List)) and s.value.elts
                               and all(isinstance(v, ast.Constant) and isinstance(v.value, str) for v in s.value.elts)
                               for s in tree.body) for c in comparisons)
                if scheme and host:
                    result[function.name] = {'policy.destination-allowlist'}
        # Other names remain candidate mitigations, never automatic suppression.
    return result


def call_semantics(node, name, concepts, aliases=None):
    concepts = set(concepts)
    from ..security_operations import python_operations
    operations, operation_positions = python_operations(node, name)
    concepts.update(operations)
    if name in {'flask.redirect', 'werkzeug.utils.redirect', 'django.shortcuts.redirect'}:
        concepts.add('navigation.redirect')
    attributes = {}
    if name in {'input', 'builtins.input', 'request.get_json'} or name.startswith(('request.args.', 'request.form.', 'request.GET.', 'request.POST.', 'request.query_params.')):
        concepts.update(INPUT_CONCEPTS)
    if name in {'eval', 'builtins.eval', 'exec', 'builtins.exec'}:
        concepts.add('command.execution')
    if name.startswith('subprocess.') and 'command.execution' in concepts:
        shell = next((kw.value for kw in node.keywords if kw.arg == 'shell'), None)
        argv = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg == 'args'), None)
        interpreter = False
        if isinstance(argv, (ast.List, ast.Tuple)) and len(argv.elts) > 1:
            executable, flag = argv.elts[:2]
            interpreter = (isinstance(executable, ast.Constant) and isinstance(executable.value, str)
                           and executable.value.rsplit('/', 1)[-1] in {'sh', 'bash', 'dash', 'zsh', 'cmd', 'cmd.exe', 'powershell', 'python', 'python3'}
                           and isinstance(flag, ast.Constant) and str(flag.value).lower() in {'-c', '/c', '-command'})
        shell_free = shell is None or isinstance(shell, ast.Constant) and shell.value is False
        fixed_executable = (isinstance(argv, ast.Constant) and isinstance(argv.value, str)
                            or isinstance(argv, (ast.List, ast.Tuple)) and argv.elts
                            and isinstance(argv.elts[0], ast.Constant) and isinstance(argv.elts[0].value, str))
        if not interpreter and shell_free and fixed_executable:
            concepts.discard('command.execution')
        elif shell_free and isinstance(argv, (ast.List, ast.Tuple)):
            attributes['argv_taint_indices'] = (2,) if interpreter else (0,)
    if name == 'yaml.load':
        loader = next((kw.value for kw in node.keywords if kw.arg == 'Loader'), None)
        if loader is None and len(node.args) > 1:
            loader = node.args[1]
        loader_name = qualified_name(loader)
        first, dot, rest = loader_name.partition('.')
        loader_name = (aliases or {}).get(first, first) + dot + rest
        if loader_name in {'yaml.SafeLoader', 'yaml.CSafeLoader'}:
            concepts.discard('deserialization.object-construction')
    if name == 'pickle.dumps' and node.args and isinstance(node.args[0], ast.Call) and qualified_name(node.args[0].func) == 'json.loads':
        concepts.add('policy.type-allowlist')
    if name.endswith(('.execute', '.executemany', '.executescript')):
        concepts.add('sql.execution')
    arguments_by_concept = {
        'navigation.redirect': (0, 'location', 'to', 'url'),
        'sql.execution': (0, 'query', 'sql', 'statement', 'operation'),
        'network.outbound-request': (0, 'url', 'fullurl'),
        'filesystem.access': (0, 'file', 'filename', 'path'),
        'deserialization.object-construction': (0, 'data', 's', 'stream'),
        'command.execution': (0, 'args', 'command', 'source'),
    }
    sensitive = set(operation_positions)
    for concept, arguments in arguments_by_concept.items():
        if concept in concepts:
            sensitive.update(arguments)
    if sensitive:
        attributes['sensitive_arguments'] = tuple(sorted(sensitive, key=str))
    if name in {'flask.redirect', 'werkzeug.utils.redirect'}:
        target = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg == 'location'), None)
        builder = qualified_name(target.func) if isinstance(target, ast.Call) else ''
        first, dot, rest = builder.partition('.')
        builder = (aliases or {}).get(first, first) + (dot + rest if dot else '')
        options = {kw.arg: kw.value for kw in target.keywords} if isinstance(target, ast.Call) else {}
        external = options.get('_external')
        if (builder == 'flask.url_for' and target.args and isinstance(target.args[0], ast.Constant)
                and '_scheme' not in options and (external is None or isinstance(external, ast.Constant) and external.value is False)):
            # Query/fragment arguments can vary without selecting a different
            # origin for this fixed local route. Keep them as input evidence,
            # but do not turn them into an open-redirect destination path.
            attributes['sensitive_arguments'] = ()
    return concepts, attributes
