"""Saved, bounded CFG/DFG artifacts shared by every executable profile."""
import ast
import hashlib
import json
import time
import fnmatch
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from utils.scan_scope import walk_source, allows_file
from utils.source_cache import read_source_bytes
from .cache import AnalysisBudgetExceeded
from .portable_profiles import EXTENSIONS
from .program_cfg import build_cfg, identity

INDEX_NAME='program_graphs.json'
REVIEW_NAME='program_graphs_review.json'
LANGUAGES=dict(EXTENSIONS,python=('.py',),php=('.php','.phtml'))
LANGUAGES['java'] += ('.jspx',)
LANGUAGES['ruby'] += ('.ru',)
LANGUAGES['groovy'] += ('.gradle',)
SUFFIXES={suffix:language for language,suffixes in LANGUAGES.items() for suffix in suffixes}
NAMED_SOURCES={'.bashrc':'bash','.bash_profile':'bash','.profile':'bash','.bash_aliases':'bash','Gemfile':'ruby','Rakefile':'ruby','Podfile':'ruby'}
TEMPLATES={'.jsp','.jspx','.erb','.cshtml','.aspx','.asp','.phtml','.asax','.svc'}
CONFIGURATION=('terraform','dockerfile','kubernetes','filepaths','xml','yaml','json','plist')
IGNORE={'.git','.hg','.svn','node_modules','vendor','.venv','venv','__pycache__','dist','build','target','bin','obj','Pods','.dart_tool'}
DFG_ROLES={'arg':'parameter','parameter':'parameter','assign':'assignment','assignment':'assignment',
           'name':'reference','reference':'reference','functiondef':'function','function':'function','return':'return'}


def coverage():
    return [dict(language=language,extensions=list(extensions),cfg='structural',dfg='modeled',
                 note='Bounded static source model; unsupported constructs remain explicit gaps.')
            for language,extensions in sorted(LANGUAGES.items())]+[
        dict(language=name,extensions=[],cfg='not-applicable',dfg='not-applicable',
             note='Declarative configuration or path rules have no executable control/value-flow model. Review their native source and rule evidence.')
        for name in CONFIGURATION]


def platform_coverage():
    """Account for every registered scan platform, including config-only ones."""
    registry=Path(__file__).resolve().parents[2]/'rules/scanning/rulesconfig.xml'
    rows=[]
    for entry in ET.parse(registry).getroot().findall('rule'):
        platform=entry.findtext('platform') or ''
        patterns=[value.strip() for value in (entry.findtext('platform_ftypes') or '').split(',') if value.strip()]
        languages=sorted(language for language,suffixes in LANGUAGES.items()
                         if any(fnmatch.fnmatchcase('example'+suffix,pattern) for suffix in suffixes for pattern in patterns))
        rows.append(dict(platform=platform,languages=languages,cfg='structural' if languages else 'not-applicable',
                         dfg='modeled' if languages else 'not-applicable',
                         note='Frameworks share their implementation-language models; configuration and embedded templates retain separate limitations.' if languages
                         else 'This platform primarily scans declarative configuration. Its companion executable files use their own language profiles.'))
    rows.append(dict(platform='filepaths',languages=[],cfg='not-applicable',dfg='not-applicable',note='Path-only review has no executable control or data flow.'))
    return rows


def dfg_for_file(path,relative,source,language,functions,deadline):
    notes=[]
    if language=='python':
        from .adapters.python import PythonAdapter
        from .flow import PythonDataFlowProvider
        ir=PythonAdapter().parse_file(path)
        graph=PythonDataFlowProvider(max_edges=4000).build(path.parent,ir)
    elif language=='php':
        from .adapters.tokenized import PHPAdapter
        from .php_flow import PHPDataFlowProvider
        ir=PHPAdapter().parse_file(path)
        graph=PHPDataFlowProvider().build(path.parent,ir)
    else:
        from .portable_flow import Walker,build_project_flow
        ir=Walker(path,language,source=source,max_tokens=100000).parse()
        graph,notes=build_project_flow(ir,max_seconds=max(0,deadline-time.monotonic()))
    notes=list(ir.diagnostics)+list(notes)
    if graph.truncated:notes.append('Data-flow edge budget reached')
    nodes=[];lookup={};lines=source.splitlines();expected_path=path.as_posix();path_matches={}
    for entity in graph.entities.values():
        if len(nodes)>=1500:notes.append('DFG node budget reached');break
        if entity.location.path not in path_matches:
            path_matches[entity.location.path]=Path(entity.location.path).as_posix()==expected_path
        if not path_matches[entity.location.path]:continue
        if entity.attribute('role')=='coverage':
            notes.extend(entity.attribute('flow_limits',()));continue
        key=identity(relative,entity.location.line,entity.location.column,entity.kind.value,
                     entity.name,entity.native_kind,len(nodes))
        lookup[entity.entity_id]=key
        line=entity.location.line
        scopes=[f for f in functions if f['name']!='<module>' and f['line']<=line<=f['end_line']]
        scope=min(scopes,key=lambda f:f['end_line']-f['line']) if scopes else next((f for f in functions if f['name']=='<module>'),None)
        kind=entity.attribute('role') or DFG_ROLES.get(entity.native_kind.lower(),entity.kind.value.lower())
        nodes.append(dict(id=key,label=entity.qualified_name or entity.name or entity.kind.value,
                          kind=kind,native_kind=entity.native_kind,function_id=scope['id'] if scope else '',
                          concepts=sorted(entity.concepts),
                          location=dict(path=relative,line=line,column=entity.location.column,end_line=entity.location.end_line),
                          code='\n'.join(lines[line-1:min(len(lines),entity.location.end_line)])[:4000] if 0<line<=len(lines) else ''))
    edges=[]
    for edge in graph.edges:
        if edge.source_id not in lookup or edge.target_id not in lookup:continue
        if len(edges)>=4000:notes.append('DFG edge budget reached');break
        edges.append(dict(source=lookup[edge.source_id],target=lookup[edge.target_id],kind=edge.kind,label=edge.kind,
                          argument=edge.argument,callsite=identity(relative,edge.callsite.replace(str(path),relative).replace(path.as_posix(),relative)) if edge.callsite else ''))
    notes=sorted(set(str(note).replace(str(path),relative).replace(str(path.parent)+'/', '') for note in notes))
    return dict(nodes=nodes,edges=edges,status='partial' if notes else 'available',diagnostics=notes[:100],
                model='modeled-data-dependencies',limitations=['May-flow dependencies are not path-feasibility or exploitability proofs. Dynamic code, lifecycle scheduling and external library behavior may be unresolved.'])


def build_file(path,root,language,expected_hash=None,deadline=None):
    relative=path.relative_to(root).as_posix()
    if path.stat().st_size>256*1024:raise AnalysisBudgetExceeded('Source file byte budget reached')
    raw=read_source_bytes(path)
    if len(raw)>256*1024:raise AnalysisBudgetExceeded('Source file byte budget reached')
    fingerprint=hashlib.sha256(raw).hexdigest()
    if expected_hash and expected_hash!=fingerprint:raise ValueError('Source changed since indexing; no graph built from mismatched content')
    source=raw.decode('utf-8-sig')
    if any(len(line)>4000 for line in source.splitlines()):raise AnalysisBudgetExceeded('Minified or oversized source line is not modeled')
    base=dict(id=identity(relative),path=relative,language=language,sha256=fingerprint)
    if path.suffix.lower() in TEMPLATES:
        return dict(base,status='unavailable',functions=[],diagnostics=['Embedded template execution is not modeled as a complete executable CFG/DFG.'],cfg=None,dfg=None)
    cfg=build_cfg(relative,source,language,deadline)
    try:dfg=dfg_for_file(path,relative,source,language,cfg['functions'],deadline or time.monotonic()+10)
    except (OSError,UnicodeError,ValueError,SyntaxError,RecursionError,AnalysisBudgetExceeded) as exc:
        dfg=dict(nodes=[],edges=[],status='unavailable',diagnostics=[str(exc).replace(str(path),relative)],limitations=[])
    # Parsing can read files through existing adapters. Reject a file changed
    # during that work, rather than mixing evidence from source revisions.
    if hashlib.sha256(read_source_bytes(path)).hexdigest()!=fingerprint:raise ValueError('Source changed while graphs were built')
    return dict(base,status='partial' if cfg['status']!='available' or dfg['status']!='available' else 'available',
                functions=cfg['functions'],cfg=cfg,dfg=dfg,diagnostics=[])


def build_catalog(root,files=None,provenance='scan',max_files=1000,max_seconds=20,max_nodes=30000,max_bytes=16*1024*1024,scope=None):
    root=Path(root).resolve()
    if not root.is_dir():raise ValueError('Source directory is unavailable')
    started=time.monotonic();deadline=started+max_seconds
    entries=[];notes=[];truncated=False;total_nodes=total_bytes=0;visited=0
    def discover():
        nonlocal visited
        if files is not None:
            yield from files;return
        for directory,children,names in walk_source(root,followlinks=False):
            children[:]=sorted(name for name in children if name not in IGNORE and not (Path(directory)/name).is_symlink()
                               and (scope is None or scope.allows_path(Path(directory)/name)))
            visited+=1
            if visited>20000 or time.monotonic()>=deadline:return
            for name in sorted(names):
                path=Path(directory)/name;language=NAMED_SOURCES.get(name) or SUFFIXES.get(path.suffix.lower())
                if language and not name.endswith(('.min.js','.bundle.js')):
                    yield dict(path=path.relative_to(root).as_posix(),language=language)
    for item in discover():
        if len(entries)>=max_files or time.monotonic()>=deadline or total_nodes>=max_nodes:
            truncated=True;notes.append('Program graph file/time/node budget reached; remaining files are not represented');break
        raw_path=root/item['path'];path=raw_path.resolve();relative=item['path'];language=item.get('language') or SUFFIXES.get(path.suffix.lower())
        if root not in path.parents or raw_path.is_symlink() or not allows_file(path) or (scope is not None and not scope.allows_file(path)):
            notes.append(relative+': outside allowed source scope');continue
        if language not in LANGUAGES:continue
        try:
            record=build_file(path,root,language,item.get('sha256'),deadline)
        except (OSError,UnicodeError,ValueError,SyntaxError,RecursionError,AnalysisBudgetExceeded) as exc:
            record=dict(id=identity(relative),path=relative,language=language,status='unavailable',functions=[],cfg=None,dfg=None,
                        diagnostics=[str(exc).replace(str(path),relative)])
        size=len(json.dumps(record,ensure_ascii=False).encode('utf-8'))
        node_count=sum(len((record.get(kind) or {}).get('nodes',[])) for kind in ('cfg','dfg'))
        if total_nodes+node_count>max_nodes:
            truncated=True;notes.append('Program graph node budget reached; remaining files are not represented');break
        if total_bytes+size>max_bytes:
            truncated=True;notes.append('Program graph storage budget reached; remaining files are not represented');break
        entries.append(record);total_bytes+=size
        total_nodes+=node_count
    if time.monotonic()>=deadline:truncated=True;notes.append('Program graph time budget reached')
    if visited>20000:truncated=True;notes.append('Program graph directory budget reached')
    return dict(version=1,provenance=provenance,created_at=datetime.now(timezone.utc).isoformat(),files=entries,coverage=coverage(),platforms=platform_coverage(),
                diagnostics=sorted(set(notes)),truncated=truncated,
                summary=dict(files=len(entries),languages=dict(Counter(e['language'] for e in entries)),nodes=total_nodes,bytes=total_bytes))


def read_catalog(runtime):
    from .xref import read_index
    runtime=Path(runtime)
    for name in (REVIEW_NAME,INDEX_NAME):
        index=read_index(runtime/name)
        if index is not None:return index
    return None


def query_catalog(catalog,search='',language='all',offset=0,limit=40,file_id='',function_id='',kind='cfg'):
    if kind not in {'cfg','dfg'}:raise ValueError('Unknown program graph kind')
    if catalog is None:return dict(available=False,needs_rebuild=True,files=[],coverage=coverage(),platforms=platform_coverage(),summary={})
    if catalog.get('version')!=1:raise ValueError('Unsupported program graph version')
    needle=search.casefold()
    files=[item for item in catalog.get('files',[]) if (language=='all' or item['language']==language) and (not needle or needle in item['path'].casefold())]
    result={key:catalog.get(key) for key in ('summary','coverage','platforms','provenance','created_at','diagnostics','truncated')}
    result.update(available=True,needs_rebuild=False,files=[{k:v for k,v in item.items() if k not in {'cfg','dfg'}} for item in files[offset:offset+limit]],
                  total=len(files),offset=offset,limit=limit,has_more=offset+limit<len(files),selected=None,graph=None)
    if not file_id:return result
    record=next((item for item in catalog.get('files',[]) if item['id']==file_id),None)
    if record is None:raise KeyError('Program graph file not found')
    result['selected']={k:v for k,v in record.items() if k not in {'cfg','dfg'}}
    graph=record.get(kind)
    if graph is None:return result
    graph=dict(graph,nodes=list(graph['nodes']),edges=list(graph['edges']))
    if function_id:
        if not any(item['id']==function_id for item in record['functions']):raise KeyError('Program graph function not found')
        members={node['id'] for node in graph['nodes'] if node.get('function_id')==function_id}
        # Keep immediate cross-function dependency endpoints as boundary nodes;
        # do not invent intraprocedural edges between disconnected scopes.
        graph['edges']=[edge for edge in graph['edges'] if edge['source'] in members or edge['target'] in members]
        retained=members|{edge[key] for edge in graph['edges'] for key in ('source','target')}
        graph['nodes']=[dict(node,boundary=node['id'] not in members) for node in graph['nodes'] if node['id'] in retained]
    graph['kind']=kind;result['graph']=graph
    return result


def graph_svg(graph, max_nodes=80):
    """Print-safe SVG of recorded edges; tables retain the complete evidence."""
    from html import escape
    nodes=(graph or {}).get('nodes',[])[:max_nodes]
    positions={node['id']:(20+(i%3)*240,30+(i//3)*120) for i,node in enumerate(nodes)}
    height=max(160,((len(nodes)+2)//3)*120+40)
    parts=[f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 740 {height}" role="img" aria-label="Saved {escape(str((graph or {}).get("kind","program")))} graph">',
           '<defs><marker id="pg-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0 0 L7 4 L0 8" fill="none" stroke="#41658a"/></marker></defs>']
    for edge in (graph or {}).get('edges',[]):
        if edge['source'] not in positions or edge['target'] not in positions:continue
        x,y=positions[edge['source']];tx,ty=positions[edge['target']]
        parts.append(f'<path d="M{x+100} {y+72} C{x+100} {y+100} {tx+100} {ty-20} {tx+100} {ty}" fill="none" stroke="#41658a" marker-end="url(#pg-arrow)"/>')
        parts.append(f'<text x="{(x+tx)//2+104}" y="{(y+ty)//2+38}" font-size="8" fill="#254a70">{escape(str(edge.get("label") or edge.get("kind","") )[:25])}</text>')
    for node in nodes:
        x,y=positions[node['id']]
        parts.append(f'<g><title>{escape(str(node.get("label","")))}</title><rect x="{x}" y="{y}" width="205" height="72" rx="5" fill="#edf4fb" stroke="#41658a"/>')
        for offset,text in ((17,node.get('kind','')), (37,str(node.get('label',''))[:28]),(57,str((node.get('location') or {}).get('line','')))):
            parts.append(f'<text x="{x+8}" y="{y+offset}" font-family="monospace" font-size="10" fill="#18334f">{escape(str(text))}</text>')
        parts.append('</g>')
    parts.append('</svg>')
    return ''.join(parts)


def report_views(catalog):
    """Complete evidence views for portable reports; no current-source reads."""
    result=[]
    for file in (catalog or {}).get('files',[]):
        for kind in ('cfg','dfg'):
            graph=file.get(kind)
            if graph is None:
                result.append(dict(path=file['path'],language=file['language'],kind=kind,status='unavailable',
                                   diagnostics=file.get('diagnostics',[]),nodes=[],edges=[],functions=file.get('functions',[])))
            else:
                result.append(dict(graph,path=file['path'],language=file['language'],kind=kind,
                                   functions=file.get('functions',[])))
    return result
