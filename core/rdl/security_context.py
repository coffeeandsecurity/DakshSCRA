"""Located control declarations associated with a particular operation scope.

Declarations are evidence for review, never a sufficient suppression reason.
Global middleware, policy execution and tenant invariants remain unresolved
unless a dedicated model establishes them for the actual resource and path.
"""
import ast
import re
from functools import lru_cache
from pathlib import Path

from utils.source_cache import read_source_text, source_stat
from .cache import AnalysisBudgetExceeded


AUTH_NAMES = frozenset({'Authorize', 'AllowAnonymous', 'PreAuthorize', 'Secured',
                       'RolesAllowed', 'PermitAll', 'DenyAll', 'login_required',
                       'permission_required', 'roles_required', 'authorize'})
FIELD_NAMES = frozenset({'Bind', 'BindNever', 'JsonIgnore', 'JsonProperty',
                        'fillable', 'guarded', 'permit', 'allowedFields', 'exclude'})


def _declaration(name, scope, path, line, column, text):
    return dict(name=name, scope=scope,
                location=dict(path=str(path), line=line, column=column,
                              end_line=line, end_column=column + len(name)),
                declaration=text,
                effect='explicit anonymous access declaration' if name in {'AllowAnonymous', 'PermitAll'} else
                       'declared requirement; execution and resource association need verification')


@lru_cache(maxsize=64)
def _index(path, language, stamp):
    path = Path(path)
    if stamp[1] > 1024 * 1024:
        return (), ('Control association source size limit reached',)
    text = read_source_text(path, encoding='utf-8-sig')
    result = []
    if language == 'python':
        tree = ast.parse(text)
        def visit(node, inherited=()):
            decorators = []
            for value in getattr(node, 'decorator_list', ()):
                call = value.func if isinstance(value, ast.Call) else value
                name = call.id if isinstance(call, ast.Name) else call.attr if isinstance(call, ast.Attribute) else ''
                if name in AUTH_NAMES:
                    decorators.append(_declaration(name, 'class' if isinstance(node, ast.ClassDef) else 'method',
                                                   path, value.lineno, value.col_offset+1, ast.get_source_segment(text,value) or name))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fields = []
                for call in ast.walk(node):
                    if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr == 'permit':
                        fields.append(_declaration('permit','operation candidate',path,call.lineno,call.col_offset+1,ast.get_source_segment(text,call) or 'permit'))
                result.append(dict(first=node.lineno, last=node.end_lineno, column=node.col_offset+1,
                                   end_column=node.end_col_offset+1, name=node.name,
                                   authorization=list(inherited)+decorators, fields=fields))
            for child in getattr(node, 'body', ()):
                if isinstance(child, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    visit(child, tuple(decorators) if isinstance(node, ast.ClassDef) else ())
        visit(tree)
        return tuple(result), ()
    from .portable_flow import Walker
    walker = Walker(path, language, source=text, max_tokens=100000)
    tokens = walker.tokens
    def declarations(first, last, scope, names):
        items = []
        for i in range(first, last):
            token = tokens[i]
            if token.kind != 'identifier' or token.text.lstrip('$') not in names:
                continue
            # Attributes/annotations only; imports, variable names and comments
            # do not become control declarations.
            opening = next((j for j in reversed(range(first, i)) if tokens[j].text in {'[','@'}), None)
            if opening is None or any(tokens[j].text in {';', '{', '}'} for j in range(opening, i)):
                continue
            close = walker.pairs.get(opening, i+1)
            if tokens[opening].text == '@' and i+1 in walker.pairs:
                close = walker.pairs[i+1]
            items.append(_declaration(token.text, scope, path, token.line, token.column,
                                      walker.text(opening, min(close+1,last))))
        return items
    def prefix(index):
        first=index
        while first > 0 and index-first < 200 and tokens[first-1].text not in {';', '{', '}'}:
            first-=1
        return first
    for function in walker.functions:
        start, last = function['start'], function['end']
        first = prefix(start)
        classes = [(a,b,n) for a,b,n in walker.classes if a < start < b]
        auth = declarations(first, function['opening'], 'method', AUTH_NAMES)
        if classes:
            a,b,name = min(classes, key=lambda item:item[1]-item[0])
            class_word = next((j for j in reversed(range(max(0,a-100),a)) if tokens[j].text in {'class','struct','interface'}), a)
            auth = declarations(prefix(class_word), a, 'class', AUTH_NAMES)+auth
        fields = declarations(first, function['body'], 'parameter', FIELD_NAMES)
        result.append(dict(first=tokens[start].line, last=tokens[last].line,
                           column=tokens[start].column, end_column=tokens[last].column+len(tokens[last].text),
                           name=function['name'], authorization=auth, fields=fields))
    return tuple(result), tuple(sorted(walker.limits))


def operation_context(location, language):
    """Associate only the smallest containing method; preserve unknown controls."""
    base = dict(authorization_status='unresolved', tenant_status='application invariant required',
                field_policy_status='unresolved', declarations=[], limitations=[
                    'A declared control is not proof that it governs this user, resource and operation.',
                    'Global middleware, inherited external controls and deployment policies are not resolved by this context view.',
                    'Tenant isolation requires a declared application invariant; absence of a tenant marker is not a vulnerability verdict.'])
    if not location or not location.get('path') or not location.get('line'):
        return base
    try:
        path = Path(location['path'])
        stat = source_stat(path)
        scopes, limits = _index(str(path), language, (stat.st_mtime_ns,stat.st_size))
        point = (location['line'], location.get('column') or 1)
        matches = [scope for scope in scopes if (scope['first'],scope['column']) <= point <= (scope['last'],scope['end_column'])]
        if matches:
            scope = min(matches, key=lambda item:item['last']-item['first'])
            controls = scope['authorization']
            anonymous = any(item['name'] in {'AllowAnonymous','PermitAll'} for item in controls)
            base.update(operation_scope=scope['name'],
                        authorization_status='explicit anonymous declaration' if anonymous else 'declared requirement; enforcement unresolved' if controls else 'no associated declaration; enforcement unresolved',
                        field_policy_status='declared field policy; exact bound fields require review' if scope['fields'] else 'unresolved',
                        declarations=controls+scope['fields'])
        base['limitations'].extend(limits)
    except (OSError, UnicodeError, SyntaxError, ValueError, RecursionError, AnalysisBudgetExceeded) as exc:
        base['limitations'].append('Control association unavailable: '+str(exc))
    return base


def _type_context(walker, point):
    """Resolve declared namespaces and using aliases, never bare names alone."""
    tokens=walker.tokens
    namespaces=[]
    for i,token in enumerate(tokens):
        if token.kind!='identifier' or token.text!='namespace':continue
        end=next((j for j in range(i+1,min(len(tokens),i+100)) if tokens[j].text in {'{',';'}),None)
        if end is None:continue
        name=''.join(t.text for t in tokens[i+1:end])
        if re.fullmatch(r'\w+(?:\.\w+)*',name):
            namespaces.append((end,walker.pairs.get(end,len(tokens)),name))
    containing=sorted((row for row in namespaces if row[0]<=point<row[1]),key=lambda row:row[0])
    namespace='.'.join(row[2] for row in containing)
    imports=[];aliases={}
    for i,token in enumerate(tokens):
        if token.kind!='identifier' or token.text!='using':continue
        scopes=[row for row in namespaces if row[0]<i<row[1]]
        if any(not row[0]<=point<row[1] for row in scopes):continue
        end=next((j for j in range(i+1,min(len(tokens),i+100)) if tokens[j].text in {';','{','('}),None)
        if end is None or tokens[end].text!=';':continue
        value=''.join(t.text for t in tokens[i+1:end] if t.kind!='string')
        if '=' in value:
            alias,qualified=value.split('=',1)
            if alias.isidentifier() and re.fullmatch(r'(?:global::)?\w+(?:\.\w+)*',qualified):aliases[alias]=qualified[8:] if qualified.startswith('global::') else qualified
        elif re.fullmatch(r'(?:global::)?\w+(?:\.\w+)*',value):imports.append(value[8:] if value.startswith('global::') else value)
    return dict(namespace=namespace,imports=imports,aliases=aliases)


@lru_cache(maxsize=256)
def _model_index(path, stamp):
    from .portable_flow import Walker
    if stamp[1] > 1024 * 1024:
        raise AnalysisBudgetExceeded('Model field source size limit reached')
    walker=Walker(Path(path),'csharp',max_tokens=100000)
    tokens=walker.tokens
    result=[]
    for first,last,name in walker.classes:
        context=_type_context(walker,first)
        parents=sorted((row for row in walker.classes if row[0]<first<row[1]),key=lambda row:row[0])
        qualified='.'.join(value for value in [context['namespace']]+[row[2] for row in parents]+[name] if value)
        fields=[]
        cursor=first+1
        while cursor < last:
            if tokens[cursor].text == '{' and cursor in walker.pairs:
                end=walker.pairs[cursor]
                # Auto-properties only. Computed setters and arbitrary method
                # bodies are not writable-field proofs.
                content=tokens[cursor+1:end]
                words=[token.text for token in content]
                if cursor > first+1 and words and all(word in {'get','set','init','private','protected','internal',';'} for word in words):
                    field=tokens[cursor-1]
                    start=cursor-1
                    while start>first+1 and tokens[start-1].text not in {';','{','}'}:
                        start-=1
                    declarations=[]
                    for i in range(start,cursor-1):
                        if tokens[i].text in FIELD_NAMES and any(tokens[j].text=='[' for j in range(start,i)):
                            declarations.append(_declaration(tokens[i].text,'model property',path,tokens[i].line,tokens[i].column,walker.text(start,cursor)))
                    fields.append(dict(name=field.text,declared_setter='set' in words or 'init' in words,
                                       restricted_setter=any(word in {'private','protected','internal'} for word in words),
                                       location=dict(path=path,line=field.line,column=field.column,end_line=field.line,end_column=field.column+len(field.text)),
                                       declarations=declarations))
                cursor=end+1
            else:
                cursor+=1
        result.append(dict(name=name,qualified_name=qualified,path=path,fields=fields))
    return tuple(result)


def binding_model_context(location, language, analyzed_files):
    """Bind a typed C# deserialization to an unambiguous inspected model."""
    result=dict(status='unresolved',fields=[],limitations=[
        'Declared setters and serializer attributes do not establish the effective writable-field policy.',
        'Custom serializers, inheritance, runtime resolver settings and field ownership require review.'])
    if language != 'csharp' or not location:
        return result
    try:
        path=Path(location['path'])
        lines=read_source_text(path,encoding='utf-8-sig').splitlines()
        line=lines[location['line']-1]
        fragment=line[max(0,location.get('column',1)-1):][:500]
        match=re.match(r'(?:Newtonsoft\.Json\.)?JsonConvert\s*\.\s*DeserializeObject\s*<\s*((?:global::)?[\w.]+)\s*>',fragment)
        if not match:
            return result
        declared=match[1]
        model=declared.split('.')[-1]
        from .portable_flow import Walker
        walker=Walker(path,'csharp',max_tokens=100000)
        point=next((i for i,t in enumerate(walker.tokens) if (t.line,t.column)>=(location['line'],location.get('column',1))),len(walker.tokens)-1)
        context=_type_context(walker,point)
        first,dot,rest=declared.partition('.')
        if declared.startswith('global::'):
            qualified={declared[8:]}
        elif first in context['aliases']:
            qualified={context['aliases'][first]+(dot+rest if dot else '')}
        else:
            qualified={declared}
            if context['namespace']:qualified.add(context['namespace']+'.'+declared)
            qualified.update(imported+'.'+declared for imported in context['imports'])
            for a,b,name in walker.classes:
                if a<=point<=b:qualified.add('.'.join(value for value in (context['namespace'],name,declared) if value))
        matches=[]
        candidates=[str(p) for p in analyzed_files if str(p).lower().endswith('.cs')]
        short_names={value.rsplit('.',1)[-1] for value in qualified}
        candidates.sort(key=lambda item:(Path(item).stem not in short_names,item))
        paths=list(dict.fromkeys([str(path)]+candidates))
        if len(paths)>128:
            result['limitations'].append('Model association file budget reached')
        for name in paths[:128]:
            stat=source_stat(Path(name))
            matches.extend(item for item in _model_index(name,(stat.st_mtime_ns,stat.st_size)) if item['qualified_name'] in qualified)
        result['model']=model
        if len(matches)==1:
            result.update(status='unique inspected model; effective binding unresolved',fields=matches[0]['fields'],model_path=matches[0]['path'],qualified_model=matches[0]['qualified_name'])
        elif len(matches)>1:
            result['limitations'].append('Ambiguous or partial model declarations; no field policy inferred')
    except (OSError, UnicodeError, IndexError, ValueError, AnalysisBudgetExceeded) as exc:
        result['limitations'].append('Model association unavailable: '+str(exc))
    return result


def annotate_findings(findings, language, analyzed_files=()):
    """Enrich newly generated findings without altering their verdict or trace."""
    for finding in findings:
        finding['security_context'] = operation_context(finding.get('location'), language)
        context = finding['security_context']
        if finding.get('title') == 'Untrusted Bulk Binding Review':
            finding['binding_model'] = binding_model_context(finding.get('location'),language,analyzed_files)
        names = ', '.join(item['name']+' ('+item['scope']+')' for item in context['declarations'])
        note = 'Operation authorization: '+context['authorization_status']+'.'
        if names:
            note += ' Associated declarations: '+names+'.'
        note += ' '+context['limitations'][0]+' '+context['limitations'][2]
        model = finding.get('binding_model') or {}
        if model.get('fields'):
            note += ' Inspected model '+model['model']+' declares fields: '+', '.join(
                field['name']+(' (restricted setter)' if field['restricted_setter'] else '')+
                (' ['+', '.join(item['name'] for item in field['declarations'])+']' if field['declarations'] else '')
                for field in model['fields'])+'. Effective serializer binding remains unresolved.'
        finding['security_context_note'] = note
        finding['reviewer_note'] = '\n\n'.join(value for value in (finding.get('reviewer_note'),note) if value)
