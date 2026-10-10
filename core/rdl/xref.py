"""Bounded, persisted source-reference index independent of security matches.

Python uses its AST; other executable profiles use the structural token parser.
Only unique visible declarations resolve. Dynamic/external calls stay explicit.
"""
import ast
import hashlib
import json
import os
import posixpath
import re
import time
from collections import Counter
from functools import lru_cache
from datetime import datetime, timezone
from pathlib import Path
from utils.scan_scope import walk_source
from utils.source_cache import read_source_bytes

from .portable_profiles import EXTENSIONS
from .cache import AnalysisBudgetExceeded

INDEX_NAME = 'rdl_xref.json'
IGNORE = {'.git', '.hg', '.svn', 'node_modules', 'vendor', '.venv', 'venv',
          '__pycache__', 'dist', 'build', 'target', 'bin', 'obj', 'Pods', '.dart_tool'}
SUFFIXES = {suffix: language for language, suffixes in EXTENSIONS.items() for suffix in suffixes}
SUFFIXES.update({'.py': 'python', '.php': 'php', '.phtml': 'php'})


def identity(*parts):
    return hashlib.sha256(json.dumps(parts).encode()).hexdigest()[:24]


def excerpt(text, line, radius=3):
    lines = text if isinstance(text, list) else text.splitlines()
    return [dict(line=i + 1, text=lines[i], highlight=i + 1 == line)
            for i in range(max(0, line - radius - 1), min(len(lines), line + radius + 1))]


def symbol(path, language, name, kind, line, column=1, end_line=None, owner='', parameters=(), scope=''):
    qualified = path if kind=='module' else owner + '.' + name if owner else name
    return dict(id=identity(path, kind, qualified, line, column), name=name, qualified_name=qualified,
                kind=kind, language=language, path=path, line=line, column=column,
                end_line=end_line or line, owner=owner, parameters=list(parameters), scope=scope,
                signature='File-level execution' if kind=='module' else qualified + ('(' + ', '.join(parameters) + ')' if kind in {'function', 'method'} else ''))


def python_index(path, text):
    tree = ast.parse(text)
    symbols, calls, imports = [], [], {}
    module = symbol(path, 'python', '<module>', 'module', 1, end_line=len(text.splitlines()))
    symbols.append(module)

    def name(node):
        if isinstance(node, ast.Name): return node.id
        if isinstance(node, ast.Attribute): return name(node.value) + '.' + node.attr
        return '<dynamic>'

    class Visitor(ast.NodeVisitor):
        def __init__(self): self.stack = [module]
        def visit_Import(self, node):
            for item in node.names: imports[item.asname or item.name.split('.')[0]] = (item.name, '', 0)
        def visit_ImportFrom(self, node):
            for item in node.names:
                if item.name != '*': imports[item.asname or item.name] = (node.module or '', item.name, node.level)
        def visit_ClassDef(self, node): self.declaration(node, 'class')
        def visit_FunctionDef(self, node): self.declaration(node, 'method' if self.stack[-1]['kind'] == 'class' else 'function')
        visit_AsyncFunctionDef = visit_FunctionDef
        def declaration(self, node, kind):
            params = []
            if kind != 'class':
                params = [p.arg for p in node.args.posonlyargs + node.args.args]
                if node.args.vararg: params.append('*' + node.args.vararg.arg)
                params += [p.arg for p in node.args.kwonlyargs]
                if node.args.kwarg: params.append('**' + node.args.kwarg.arg)
            parent = self.stack[-1]
            owner = parent['qualified_name'] if parent['kind'] != 'module' else ''
            item = symbol(path, 'python', node.name, kind, node.lineno, node.col_offset + 1,
                          node.end_lineno, owner, params)
            if kind!='class':
                item['positional_count']=len(node.args.posonlyargs + node.args.args)
                item['variadic_parameter']='*'+node.args.vararg.arg if node.args.vararg else ''
            item['parent_id'] = parent['id']
            item['returns'] = []
            symbols.append(item); self.stack.append(item)
            for statement in node.body: self.visit(statement)
            self.stack.pop()
        def visit_Return(self, node):
            self.stack[-1].setdefault('returns',[]).append(dict(line=node.lineno,expression=ast.get_source_segment(text,node) or 'return'))
            self.generic_visit(node)
        def visit_Call(self, node):
            callee = name(node.func)
            arguments = [dict(expression=ast.get_source_segment(text, a) or '?', name='') for a in node.args]
            arguments += [dict(expression=ast.get_source_segment(text, a.value) or '?', name=a.arg or '**') for a in node.keywords]
            calls.append(dict(caller_id=self.stack[-1]['id'], callee=callee, path=path,
                              line=node.lineno, column=node.col_offset+1, arguments=arguments,
                              language='python', owner=self.stack[-1]['owner']))
            self.generic_visit(node)
    Visitor().visit(tree)
    return symbols, calls, imports, []


def token_index(path, text, language, absolute):
    from .portable_flow import Walker, CONTROL
    walker = Walker(absolute, language, source=text, max_tokens=25000)
    ts, pairs = walker.tokens, walker.pairs
    symbols, calls, declarations, classes = [], [], set(), []
    namespace = ''
    bindings = {}
    if language == 'php':
        if sum(t.kind=='identifier' and t.text.lower()=='namespace' for t in ts)>1:
            raise AnalysisBudgetExceeded('Multiple PHP namespace blocks require separate scope indexing')
        for i,t in enumerate(ts):
            if t.kind != 'identifier': continue
            if t.text.lower() in {'namespace','use'}:
                end=next((j for j in range(i+1,len(ts)) if ts[j].text in {';','{'}),len(ts))
                value=walker.text(i+1,end)
                if t.text.lower()=='namespace': namespace=value.strip('\\').lower()
                elif not any(ts[j].text in {',','{'} for j in range(i+1,end)):
                    aspos=next((j for j in range(i+1,end) if ts[j].text.lower()=='as'),end)
                    qualified=walker.text(i+1,aspos).strip('\\').lower()
                    alias=ts[aspos+1].text.lower() if aspos<end else qualified.rsplit('\\',1)[-1]
                    bindings[alias]=qualified
    module = symbol(path, language, '<module>', 'module', 1, end_line=len(text.splitlines()))
    symbols.append(module)
    for i, token in enumerate(ts[:-1]):
        if token.kind == 'identifier' and token.text in {'class', 'interface', 'struct', 'trait', 'object'} and ts[i+1].kind == 'identifier':
            opening = next((j for j in range(i+2, min(i+60,len(ts))) if ts[j].text in {'{',';'}), None)
            if opening in pairs:
                item = symbol(path, language, ts[i+1].text, 'class', token.line, token.column, ts[pairs[opening]].line)
                item['parent_id'] = module['id']; symbols.append(item); classes.append((opening, pairs[opening], item))
    for f in walker.functions:
        token = ts[f['start']]
        owner = next((c for a,b,c in reversed(classes) if a < f['start'] < b), None)
        item = symbol(path, language, f['name'], 'method' if owner else 'function', token.line, token.column,
                      ts[min(f['end'],len(ts)-1)].line, owner['name'] if owner else '',
                      [name for _,name,_ in f['params']], scope=str(f['start']))
        item['parent_id'] = owner['id'] if owner else module['id']
        item['_start'], item['_end'] = f['start'], f['end']
        source_lines=text.splitlines()
        item['returns'] = [dict(line=t.line, expression=source_lines[t.line-1].strip())
                           for position,t in enumerate(ts[f['body']:f['end']],start=f['body'])
                           if t.text.lower() == 'return' and t.kind == 'identifier'
                           and not any(other['start']>f['start'] and other['start']<=position<=other['end'] for other in walker.functions)][:30]
        symbols.append(item); declarations.add(f['opening'])
    lines=text.splitlines(keepends=True)
    offsets=[0]
    for line in lines: offsets.append(offsets[-1]+len(line))
    def rendered(a,b):
        if a>=b: return ''
        if language in {'ruby','vb','bash','powershell','rust'}: return walker.text(a,b)
        first,last=ts[a],ts[b-1]
        begin=offsets[first.line-1]+first.column-1
        end=offsets[last.line-1]+last.column-1+len(last.text)+(2 if last.kind=='string' else 0)
        return text[begin:end]

    for i,t in enumerate(ts):
        if t.text != '(' or t.kind != 'symbol' or i not in pairs or not i or i in declarations: continue
        last = ts[i-1]
        if last.kind != 'identifier' or last.text in CONTROL | {'function','func','fun','fn','def','sizeof','typeof','decltype','return','new'}: continue
        start=i-1
        while start>=2 and ts[start-1].text in {'.','->','?->','::','\\'} and ts[start-2].kind=='identifier': start-=2
        # Decorators and type declarations are not invocation expressions.
        if start and ts[start-1].text in {'@','class','interface','struct','function','fun','func','fn'}: continue
        caller = min((s for s in symbols if s.get('_start',len(ts)) <= start <= s.get('_end',-1)),
                     key=lambda s:s['_end']-s['_start'], default=module)
        args=[]
        for a,b in walker.segments(i+1,pairs[i]):
            if a==b: continue
            named = language == 'php' and a+1<b and ts[a+1].text==':'
            args.append(dict(expression=rendered(a+2 if named else a,b), name=ts[a].text if named else ''))
        callee=walker.text(start,i)
        calls.append(dict(caller_id=caller['id'], callee=callee, path=path, line=ts[start].line,
                          column=ts[start].column, arguments=args, language=language, owner=caller['owner']))
    if language=='php':
        for i,t in enumerate(ts[:-1]):
            if t.kind!='identifier' or t.text.lower() not in {'include','include_once','require','require_once'} or ts[i+1].text=='(': continue
            end=next((j for j in range(i+1,len(ts)) if ts[j].text==';'),len(ts))
            caller=min((s for s in symbols if s.get('_start',len(ts))<=i<=s.get('_end',-1)),key=lambda s:s['_end']-s['_start'],default=module)
            calls.append(dict(caller_id=caller['id'],callee=t.text,path=path,line=t.line,column=t.column,
                              arguments=[dict(expression=rendered(i+1,end),name='')],language=language,owner=caller['owner']))
    for item in symbols:
        item.pop('_start',None); item.pop('_end',None)
        item['namespace']=namespace
        if namespace and item['kind']!='module':
            item['qualified_name']=namespace+'\\'+item['qualified_name']
            item['signature']=namespace+'\\'+item['signature']
    for call in calls: call['namespace']=namespace
    notes=[note for note in sorted(walker.limits) if not (language=='php' and note.startswith('Embedded template'))]
    return symbols, calls, bindings, notes


def resolve_calls(symbols, calls, contents, imports, deadline=None):
    by_name = {}
    for s in symbols:
        if s['kind'] != 'module': by_name.setdefault((s['language'], s['name'].lower() if s['language']=='php' else s['name']), []).append(s)
    by_id = {s['id']:s for s in symbols}
    import_cache = {}
    source_paths = {Path('/index')/p for p in contents}
    for call in calls:
        language, name = call['language'], call['callee']
        if deadline is not None and time.monotonic()>deadline:
            call.update(id=identity(call['path'],call['line'],call['column'],name,call['caller_id']),
                        candidate_ids=[],candidate_count=0,resolution='unresolved',target_id=None,
                        reason='Reference resolution time budget reached.',resolution_limited=True)
            for argument in call['arguments']: argument['parameter']=None
            continue
        parts = re.split(r'\.|::|->|\?->|\\', name)
        short = parts[-1].lower() if language=='php' else parts[-1]
        pool = by_name.get((language, short), [])
        receiver = parts[-2] if len(parts)>1 else ''
        explicit = None
        if language == 'python':
            binding = imports.get(call['path'],{}).get(parts[0])
            if binding:
                mod, exported, level = binding
                base = Path(call['path']).parent
                if level:
                    for _ in range(level-1): base=base.parent
                else: base=Path('.')
                stem=(base / mod.replace('.', '/')).as_posix()
                target_name = parts[-1] if len(parts)>1 else exported
                pool=by_name.get((language,target_name),[])
                explicit={stem+'.py',stem+'/__init__.py'}
        elif language == 'javascript':
            from .portable_resolver import imported_target
            origin=Path('/index')/call['path']
            key=(call['path'],name)
            if key not in import_cache:
                import_cache[key]=imported_target(origin,contents[call['path']],name,source_paths,language)
            bound=import_cache[key]
            if bound is not None:
                explicit={p.relative_to('/index').as_posix() for p in bound[0]}
                if bound[1]=='<default>':
                    pool=[s for s in symbols if s['language']==language and s['path'] in explicit and re.search(r'export\s+default\s+(?:async\s+)?(?:function\s+)?'+re.escape(s['name'])+r'\b',contents[s['path']])]
                else: pool=by_name.get((language,bound[1]),[])
        if language == 'php':
            namespace=call.get('namespace','')
            bindings=imports.get(call['path'],{})
            # Explicit names and use aliases identify namespace scope.
            if '->' not in name and '::' not in name and '\\' in name:
                qualified=name.lstrip('\\').lower()
                prefix=qualified.rsplit('\\',1)[0]
                pool=[s for s in pool if s.get('namespace','')==prefix]
            elif receiver and receiver not in {'$this','self','static'} and not receiver.startswith('$'):
                qualified=bindings.get(receiver.lower(), (namespace+'\\' if namespace else '')+receiver.lower())
                ns,_,owner=qualified.rpartition('\\')
                receiver=owner; pool=[s for s in pool if s.get('namespace','')==ns]
            else:
                scoped=[s for s in pool if s.get('namespace','')==namespace]
                pool=scoped or [s for s in pool if not s.get('namespace')]
        if language=='php' and name.lower() in {'include','include_once','require','require_once'}:
            pool=[]
            expression=call['arguments'][0]['expression'] if call['arguments'] else ''
            if re.fullmatch(r"(['\"])([^'\"$]*)\1",expression.strip()):
                literal=expression.strip()[1:-1]
                if not literal.startswith('/'):
                    relative=posixpath.normpath(str(Path(call['path']).parent/literal))
                    root_relative=posixpath.normpath(literal)
                    targets=[relative] if relative in contents else [root_relative]
                    pool=[s for s in symbols if s['kind']=='module' and s['path'] in targets]
            call['reference_kind']='include'
        candidates=[]
        for target in pool:
            if explicit is not None:
                if target['path'] not in explicit: continue
            elif target['path'] != call['path']:
                text=contents[call['path']]
                other=contents[target['path']]
                if language in {'java','kotlin','csharp','go','cpp','c','swift','objc','groovy','carbon'}:
                    same_dir=Path(target['path']).parent==Path(call['path']).parent
                    if not same_dir and not re.search(r'(?:import|using|include)[^;\n]*\b'+re.escape(target['owner'] or Path(target['path']).stem)+r'\b',text): continue
                    if language in {'java','kotlin','go'} and same_dir:
                        packages=[re.search(r'\bpackage\s+([\w.]+)',x) for x in (text,other)]
                        if all(packages) and packages[0][1]!=packages[1][1]: continue
                elif language=='php':
                    pass
                elif language in {'ruby','rust','dart','bash','powershell'}:
                    if not re.search(r'(?:import|require_relative|require|source|use|mod)[^\n;]*[\"\'\s]'+re.escape(Path(target['path']).stem)+r'\b',text): continue
                else: continue
            if target['kind']=='method':
                owner=target['owner']
                if language=='php': owner=owner.lower(); receiver=receiver.lower()
                if receiver in {'self','cls','this','$this','static'}:
                    if owner!=(call['owner'].lower() if language=='php' else call['owner']): continue
                elif receiver and receiver!=owner:
                    # Resolve explicit local object construction or declared type.
                    source=contents[call['path']]
                    caller=by_id[call['caller_id']]
                    scope='\n'.join(source.splitlines()[caller['line']-1:call['line']])
                    escaped=re.escape(receiver)
                    flags=re.I if language=='php' else 0
                    if not (re.search(escaped+r'\s*=\s*(?:new\s+)?'+re.escape(owner)+r'\s*\(',scope,flags)
                            or re.search(r'\b'+re.escape(owner)+r'\s+'+escaped+r'\b',scope,flags)
                            or re.search(escaped+r'\s*:\s*'+re.escape(owner)+r'\b',scope,flags)): continue
                elif not receiver and owner!=(call['owner'].lower() if language=='php' else call['owner']): continue
            elif receiver and explicit is None and not (language=='php' and '\\' in name) and not (language=='rust' and receiver==Path(target['path']).stem):
                # Unknown object methods must not bind to a same-named free function.
                continue
            if target['kind']=='function' and target['owner']:
                caller=by_id[call['caller_id']]
                if not caller['qualified_name'].startswith(target['owner']): continue
            candidates.append(target)
        local=[s for s in candidates if s['path']==call['path']]
        if local and explicit is None: candidates=local
        call['id']=identity(call['path'],call['line'],call['column'],name,call['caller_id'])
        call['candidate_ids']=[s['id'] for s in candidates[:20]]
        call['candidate_count']=len(candidates)
        call['resolution']='resolved' if len(candidates)==1 else 'ambiguous' if candidates else 'unresolved'
        call['target_id']=candidates[0]['id'] if len(candidates)==1 else None
        call['reason']={'resolved':'Unique visible source declaration.', 'ambiguous':'Multiple source declarations fit; no target was selected.', 'unresolved':'External, dynamic, or outside the supported static resolution scope.'}[call['resolution']]
        params=list(candidates[0]['parameters']) if len(candidates)==1 else []
        if language=='python' and params and params[0] in {'self','cls'} and receiver: params=params[1:]
        expanded=False
        implicit=language=='python' and candidates and candidates[0]['parameters'] and candidates[0]['parameters'][0] in {'self','cls'} and bool(receiver)
        positional_count=candidates[0].get('positional_count',len(params))-int(bool(implicit)) if len(candidates)==1 else 0
        for position,argument in enumerate(call['arguments']):
            if argument['expression'].startswith(('*','...')): expanded=True
            if argument['name']:
                argument['parameter']=next((p for p in params if p.lstrip('$')==argument['name']),None)
            elif expanded:
                argument['parameter']=None
            elif position<positional_count and position<len(params):
                argument['parameter']=params[position]
            else:
                argument['parameter']=candidates[0].get('variadic_parameter') or None if len(candidates)==1 else None



def build_index(root, provenance='scan', max_files=2000, max_bytes=32*1024*1024, max_seconds=45, progress=None):
    root=Path(root).resolve()
    if not root.is_dir(): raise ValueError('Source directory is unavailable')
    symbols,calls,contents,imports,diagnostics,files=[],[],{},{},[],[]
    started=time.monotonic(); total=0; truncated=False; visited=0
    for directory, children, names in walk_source(root,followlinks=False):
        children[:]=sorted(n for n in children if n not in IGNORE and not (Path(directory)/n).is_symlink())
        visited+=1
        if visited>20000 or time.monotonic()-started>max_seconds: truncated=True; break
        for name in sorted(names):
            path=Path(directory)/name; language=SUFFIXES.get(path.suffix.lower())
            if not language or path.is_symlink(): continue
            if name.endswith(('.min.js','.bundle.js')): continue
            relative=path.relative_to(root).as_posix()
            if len(files)>=max_files or total>=max_bytes or len(symbols)>=25000 or len(calls)>=50000 or time.monotonic()-started>max_seconds:
                truncated=True; break
            try:
                size=path.stat().st_size
                if size>256*1024 or total+size>max_bytes:
                    diagnostics.append(relative+': source byte limit'); continue
                data=read_source_bytes(path); total+=len(data); text=data.decode('utf-8-sig')
                if any(len(line)>4000 for line in text.splitlines()):
                    diagnostics.append(relative+': generated/minified or oversized source line skipped'); continue
                s,c,bindings,notes=python_index(relative,text) if language=='python' else token_index(relative,text,language,path)
                if len(symbols)+len(s)>25000 or len(calls)+len(c)>50000:
                    diagnostics.append(relative+': symbol/reference limit'); truncated=True; break
                symbols.extend(s); calls.extend(c); imports[relative]=bindings; contents[relative]=text
                files.append(dict(path=relative,sha256=hashlib.sha256(data).hexdigest(),language=language))
                diagnostics.extend(relative+': '+n for n in notes)
                if progress: progress(relative,len(files))
            except (OSError,UnicodeError,SyntaxError,ValueError,RecursionError,AnalysisBudgetExceeded) as exc:
                diagnostics.append(relative+': '+(str(exc) if isinstance(exc,AnalysisBudgetExceeded) else type(exc).__name__))
        if truncated: break
    resolve_calls(symbols,calls,contents,imports,deadline=started+max_seconds)
    if any(c.get('resolution_limited') for c in calls):
        truncated=True; diagnostics.append('Reference resolution time budget reached; remaining targets are unresolved')
    # Deduplicate parser overlaps, preserving distinct source call sites.
    calls=list({c['id']:c for c in calls}.values())
    lines={p:text.splitlines() for p,text in contents.items()}
    for item in symbols:
        item['snippet']=excerpt(lines[item['path']],item['line'])
    for item in calls: item['snippet']=excerpt(lines[item['path']],item['line'])
    incoming=Counter(c['target_id'] for c in calls if c['target_id'])
    outgoing=Counter(c['caller_id'] for c in calls)
    for item in symbols:
        item['callers']=incoming[item['id']]; item['callees']=outgoing[item['id']]
    symbols.sort(key=lambda s:(s['path'],s['line'],s['column']))
    return dict(version=1,provenance=provenance,created_at=datetime.now(timezone.utc).isoformat(),
                symbols=symbols,calls=calls,files=files,diagnostics=diagnostics[:200],truncated=truncated,
                summary=dict(symbols=len(symbols),calls=len(calls),resolved=sum(c['resolution']=='resolved' for c in calls),
                             unresolved=sum(c['resolution']=='unresolved' for c in calls),ambiguous=sum(c['resolution']=='ambiguous' for c in calls),files=len(files)))


def write_index(path,index):
    import tempfile
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    payload=json.dumps(index,ensure_ascii=False)
    if len(payload.encode('utf-8'))>64*1024*1024: raise ValueError('Reference index exceeds storage budget')
    temporary=None
    try:
        with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',dir=path.parent,delete=False) as handle:
            temporary=Path(handle.name); handle.write(payload)
        temporary.replace(path)
    finally:
        if temporary and temporary.exists(): temporary.unlink()


def read_index(path):
    path=Path(path)
    if not path.exists(): return None
    if path.stat().st_size>64*1024*1024: raise ValueError('Reference index exceeds storage budget')
    stat=path.stat()
    return _read_snapshot(str(path),stat.st_mtime_ns,stat.st_ctime_ns,stat.st_size)


@lru_cache(maxsize=2)
def _read_snapshot(path,mtime,ctime,size):
    index=json.loads(Path(path).read_text(encoding='utf-8'))
    if index.get('version')!=1: raise ValueError('Unsupported reference index version')
    return index


def query_index(index, search='', kind='all', offset=0, limit=80, symbol_id='', direction='callees', reference_offset=0):
    if index is None: return dict(available=False,summary={})
    result={k:index[k] for k in ('summary','provenance','created_at','diagnostics','truncated')}
    result['available']=True
    symbols=index['symbols']; lookup={s['id']:s for s in symbols}
    matches=[s for s in symbols if (kind=='all' or s['kind']==kind) and search.casefold() in (s['qualified_name']+' '+s['path']).casefold()]
    result.update(total=len(matches),offset=offset,limit=limit,symbols=[{k:v for k,v in s.items() if k not in {'snippet','returns'}} for s in matches[offset:offset+limit]])
    selected=lookup.get(symbol_id) if symbol_id else (matches[0] if matches else None)
    result['selected']=selected
    if selected:
        refs=[c for c in index['calls'] if c['target_id']==selected['id']] if direction=='callers' else [c for c in index['calls'] if c['caller_id']==selected['id']]
        result['references']=[dict(c,caller=lookup[c['caller_id']],target=lookup.get(c['target_id']),candidates=[lookup[i] for i in c['candidate_ids'][:20]]) for c in refs[reference_offset:reference_offset+40]]
        members=[s for s in symbols if s.get('parent_id')==selected['id']]
        result.update(member_total=len(members),reference_total=len(refs),reference_offset=reference_offset,direction=direction,
                      members=members[:200])
    return result
