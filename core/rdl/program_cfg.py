"""Bounded structural CFG presentation. Unsupported control remains a gap.

These graphs are review artifacts, independent of rule verdicts and dominance
services. No program code is executed and no edge is inferred from line order
without first recognizing a statement/control construct.
"""
import ast
import hashlib
import time
from dataclasses import replace
from types import SimpleNamespace

from .adapters.tokenized import _Token
from .cache import AnalysisBudgetExceeded
from .portable_flow import Walker


def identity(*parts):
    return hashlib.sha256(repr(parts).encode()).hexdigest()[:24]


class Builder:
    def __init__(self, path, source, max_nodes=1500, max_edges=4000, deadline=None):
        self.path, self.lines = path, source.splitlines()
        self.nodes, self.edges, self.functions, self.notes = [], [], [], set()
        self.max_nodes, self.max_edges, self.deadline = max_nodes, max_edges, deadline
        self.function = ''

    def check(self):
        if len(self.nodes) >= self.max_nodes or len(self.edges) >= self.max_edges:
            raise AnalysisBudgetExceeded('CFG node/edge budget reached')
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise AnalysisBudgetExceeded('CFG time budget reached')

    def node(self, kind, label, line=1, column=1, end_line=None):
        self.check()
        key = identity(self.path, self.function, len(self.nodes), kind)
        self.nodes.append(dict(id=key, function_id=self.function, kind=kind, label=label[:240],
                               location=dict(path=self.path, line=line, column=column, end_line=end_line or line),
                               code='\n'.join(self.lines[max(0,line-1):min(len(self.lines),end_line or line)])[:4000]))
        return key

    def edge(self, source, target, kind='normal', condition=''):
        if not source or not target: return
        self.check()
        value = dict(source=source, target=target, kind=kind, label=condition or kind)
        if value not in self.edges: self.edges.append(value)

    def begin(self, name, line, end_line, column=1):
        self.function = identity(self.path, name, line, column)
        self.functions.append(dict(id=self.function, name=name, line=line, end_line=end_line))
        return self.node('entry', 'entry '+name, line, column), self.node('exit', 'exit '+name, end_line)

    def result(self):
        valid = {node['id'] for node in self.nodes}
        return dict(nodes=self.nodes, edges=[edge for edge in self.edges if edge['source'] in valid and edge['target'] in valid],
                    functions=self.functions, diagnostics=sorted(self.notes), status='partial' if self.notes else 'available',
                    model='structural-control-flow', limitations=['Implicit exceptions, concurrency and runtime callback scheduling are not modeled.'])


class PythonCFG(Builder):
    def sequence(self, statements, follow, exit_id, break_to=None, continue_to=None, depth=0):
        if depth > 64: raise AnalysisBudgetExceeded('CFG nesting budget reached')
        for stmt in reversed(statements):
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)): continue
            line, end = stmt.lineno, getattr(stmt,'end_lineno',stmt.lineno)
            label = self.lines[line-1].strip() if line <= len(self.lines) else type(stmt).__name__
            if isinstance(stmt, ast.If):
                yes = self.sequence(stmt.body, follow, exit_id, break_to, continue_to, depth+1)
                no = self.sequence(stmt.orelse, follow, exit_id, break_to, continue_to, depth+1)
                follow = self.condition(stmt.test, yes, no)
            elif isinstance(stmt, (ast.While, ast.For, ast.AsyncFor)):
                loop = self.node('loop', label, line, end_line=line)
                normal = self.sequence(stmt.orelse, follow, exit_id, break_to, continue_to, depth+1)
                body = self.sequence(stmt.body, loop, exit_id, follow, loop, depth+1)
                self.edge(loop,body,'loop-body', 'true' if isinstance(stmt,ast.While) else 'next item')
                self.edge(loop,normal,'loop-exit','false' if isinstance(stmt,ast.While) else 'iteration complete')
                follow = loop
            elif isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                kind = type(stmt).__name__.lower()
                current = self.node(kind,label,line,end_line=end)
                target = break_to if kind=='break' else continue_to if kind=='continue' else exit_id
                self.edge(current,target or exit_id,kind)
                follow=current
            elif isinstance(stmt, (ast.Try, ast.With, ast.AsyncWith)) or type(stmt).__name__ in {'Match','TryStar'}:
                # Correct exceptional/finally paths require distinct continuation
                # contexts. Preserve the construct as a gap, not a false bypass.
                current=self.node('gap',label,line,end_line=end)
                self.notes.add(type(stmt).__name__+' control paths require review at line '+str(line))
                self.edge(current,follow,'unresolved','unresolved control boundary')
                follow=current
            else:
                current=self.node('statement',label,line,end_line=end)
                self.edge(current,follow);follow=current
        return follow

    def condition(self, expr, yes, no):
        if isinstance(expr,ast.BoolOp):
            current=yes if isinstance(expr.op,ast.And) else no
            for value in reversed(expr.values):
                current=self.condition(value,current,no) if isinstance(expr.op,ast.And) else self.condition(value,yes,current)
            return current
        if isinstance(expr,ast.UnaryOp) and isinstance(expr.op,ast.Not): return self.condition(expr.operand,no,yes)
        label=ast.get_source_segment('\n'.join(self.lines),expr) or 'condition'
        current=self.node('condition',label,expr.lineno,getattr(expr,'col_offset',0)+1,getattr(expr,'end_lineno',expr.lineno))
        self.edge(current,yes,'true',label);self.edge(current,no,'false','not ('+label+')')
        return current

    def build(self, tree):
        scopes=[('<module>',1,len(self.lines) or 1,tree.body,1)]
        scopes.extend((node.name,node.lineno,getattr(node,'end_lineno',node.lineno),node.body,node.col_offset+1)
                      for node in ast.walk(tree) if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)))
        for name,line,end,body,column in scopes[:100]:
            entry,exit_id=self.begin(name,line,end,column)
            self.edge(entry,self.sequence(body,exit_id,exit_id))
        if len(scopes)>100:self.notes.add('CFG function budget reached')
        return self.result()


def normalized_tokens(walker):
    """Normalize explicit keyword delimiters while preserving source locations."""
    ts, language = walker.tokens, walker.language
    if language not in {'ruby','vb','bash'}: return ts
    lines={}
    for token in ts:lines.setdefault(token.line,[]).append(token)
    result=[]
    for items in lines.values():
        first=items[0];word=first.text.lower() if first.kind=='identifier' else ''
        def tok(text):return _Token(text,first.line,first.column,'symbol' if text in {'{','}','(',')',';'} else 'identifier')
        if language=='ruby' and word in {'elsif','for','until'}:
            prefix=[tok('}'),tok('else'),tok('if')] if word=='elsif' else [tok('for' if word=='for' else 'until')]
            result.extend(prefix+items[1:]+[tok('{')]);continue
        if language=='vb':
            if word=='elseif':result.extend([tok('}'),tok('else'),tok('if')]+[t for t in items[1:] if t.text.lower()!='then']+[tok('{')]);continue
            if word in {'while','for','foreach'}:result.extend(items+[tok('{')]);continue
            if word in {'next','wend'}:result.append(tok('}'));continue
            if word=='exit' and len(items)>1:
                result.append(tok('break' if items[1].text.lower() in {'for','while','do'} else 'return'));continue
        if language=='bash':
            for token in items:
                w=token.text if token.kind=='identifier' else ''
                if w in {'then','do'}:
                    if result and result[-1].text==';':result.pop()
                    result.append(replace(token,text='{',kind='symbol'))
                elif w in {'fi','done'}:result.append(replace(token,text='}',kind='symbol'))
                elif w=='else':result.extend([replace(token,text='}',kind='symbol'),token,replace(token,text='{',kind='symbol')])
                elif w=='elif':result.extend([replace(token,text='}',kind='symbol'),replace(token,text='else'),replace(token,text='if')])
                else:result.append(token)
            continue
        result.extend(items)
    return result


class TokenCFG(Builder):
    def __init__(self,path,source,language,**options):
        super().__init__(path,source,**options)
        self.language=language
        walker=Walker(path,language,source=source,max_tokens=100000)
        self.ts=normalized_tokens(walker);walker.tokens=self.ts
        self.pairs={};stack=[]
        for i,t in enumerate(self.ts):
            if t.kind!='symbol':continue
            if t.text in {'(','[','{'}:stack.append(i)
            elif t.text in {')',']','}'}:
                if stack and self.ts[stack[-1]].text=={')':'(',']':'[','}':'{'}[t.text]:self.pairs[stack.pop()]=i
                else:self.notes.add('Unbalanced control delimiters')
        if stack:self.notes.add('Unbalanced control delimiters')
        walker.pairs=self.pairs;walker.functions=[];walker.discover()
        self.scopes=walker.functions
        # PowerShell functions may omit a parameter list.
        if language=='powershell':
            for i,t in enumerate(self.ts[:-2]):
                if t.text.lower()=='function' and self.ts[i+2].text=='{' and i+2 in self.pairs:
                    self.scopes.append(dict(start=i,body=i+3,end=self.pairs[i+2],name=self.ts[i+1].text,owner=''))
        self.scopes=list({(scope['body'],scope['end'],scope['name']):scope for scope in self.scopes}.values())
        self.skip={s['start']:s['end']+1 for s in self.scopes}
        for a,b,_ in walker.classes:self.skip.setdefault(a,b+1)
        self.notes.update(walker.limits)
        if language in {'bash','powershell'}:self.notes.add('Shell pipelines, traps, substitutions and dynamic execution require review')

    def word(self,token):
        if token.kind!='identifier':return ''
        word=token.text.lower() if self.language in {'vb','powershell'} else token.text
        if word=='when' and self.language!='kotlin':return ''
        if word=='match' and self.language not in {'rust','php'}:return ''
        if word=='unless' and self.language!='ruby':return ''
        if word=='until' and self.language not in {'ruby','bash','powershell'}:return ''
        return word

    def text(self,a,b):
        return ' '.join((t.quote+t.text+t.quote if t.kind=='string' else t.text) for t in self.ts[a:b])[:240]

    def end(self,a,b):
        i=a
        line_terminated=self.language in {'javascript','kotlin','swift','go','ruby','vb','bash','powershell','groovy'}
        while i<b:
            t=self.ts[i]
            if t.kind=='symbol' and t.text in {';','}'}:return i
            if line_terminated and i>a and t.line>self.ts[i-1].line and self.ts[i-1].text not in {'=',',','+','-','&&','||','.',':','->','=>'} and t.text not in {'.','&&','||'}:return i
            if i in self.pairs:i=self.pairs[i]+1
            else:i+=1
        return b

    def unit(self,a,b,depth=0):
        if depth>64:raise AnalysisBudgetExceeded('CFG nesting budget reached')
        self.check()
        if a>=b:return None,b
        t=self.ts[a];word=self.word(t)
        if t.kind=='symbol' and t.text==';':return ('empty',a),a+1
        if t.text=='{' and a in self.pairs:
            end=self.pairs[a];return ('block',a,a+1,end),end+1
        if word in {'if','unless','elseif','while','until','for','foreach','switch','when','match'}:
            cursor=a+1
            if cursor in self.pairs and self.ts[cursor].text=='(':
                left,right=cursor+1,self.pairs[cursor];cursor=right+1
            else:
                left=cursor
                while cursor<b and not (self.ts[cursor].kind=='symbol' and self.ts[cursor].text=='{'):
                    if cursor in self.pairs:cursor=self.pairs[cursor]+1
                    else:cursor+=1
                right=cursor
            if cursor>=b:
                end=self.end(a,b);self.notes.add('Unresolved control body at line '+str(t.line))
                return ('gap',a,end),max(a+1,end+(end<b and self.ts[end].text==';'))
            body,nxt=self.unit(cursor,b,depth+1)
            alternate=None
            if word in {'if','unless','elseif'} and nxt<b and self.word(self.ts[nxt]) in {'else','elseif','elsif'}:
                alt=self.word(self.ts[nxt])
                alternate,nxt=self.unit(nxt if alt!='else' else nxt+1,b,depth+1)
            return (word,a,left,right,body,alternate),nxt
        if word=='do':
            body,nxt=self.unit(a+1,b,depth+1)
            if nxt<b and self.word(self.ts[nxt]) in {'while','until'}:
                c=nxt+1
                if c in self.pairs:
                    right=self.pairs[c];return ('do',a,c+1,right,body,None),right+1+(right+1<b and self.ts[right+1].text==';')
            self.notes.add('Unresolved post-test loop at line '+str(t.line))
            return ('gap',a,nxt),nxt
        if word in {'try','catch','finally','defer','select','guard','case','trap'} or t.text=='#':
            end=self.end(a,b)
            # Consume a structured unsupported construct and its handlers as a
            # single unresolved boundary; do not draw a false success branch.
            opening=next((i for i in range(a,min(b,a+200)) if self.ts[i].kind=='symbol' and self.ts[i].text in {'{',';'}),None)
            if opening is not None and self.ts[opening].text=='{' and opening in self.pairs:
                end=self.pairs[opening]+1
                while end<b and self.word(self.ts[end]) in {'catch','finally','except'}:
                    c=end+1
                    if c in self.pairs:c=self.pairs[c]+1
                    if c in self.pairs and self.ts[c].text=='{':end=self.pairs[c]+1
                    else:break
            self.notes.add('Unresolved '+word+' control at line '+str(t.line))
            return ('gap',a,end),max(a+1,end)
        end=self.end(a,b)
        return ('statement',a,end),max(a+1,end+(end<b and self.ts[end].text==';'))

    def sequence(self,a,b,follow,exit_id,break_to=None,continue_to=None,depth=0):
        if depth>64:raise AnalysisBudgetExceeded('CFG nesting budget reached')
        units=[];i=a
        while i<b:
            if i in self.skip:i=self.skip[i];continue
            unit,nxt=self.unit(i,b,depth+1)
            if unit:units.append(unit)
            i=max(i+1,nxt)
        for unit in reversed(units):follow=self.emit(unit,follow,exit_id,break_to,continue_to,depth+1)
        return follow

    def emit(self,u,follow,exit_id,break_to,continue_to,depth):
        kind,a=u[:2];t=self.ts[a]
        if kind=='empty':return follow
        if kind=='block':return self.sequence(u[2],u[3],follow,exit_id,break_to,continue_to,depth+1)
        if kind in {'if','unless','elseif','while','until','for','foreach','do'}:
            label=self.text(u[2],u[3]) or kind
            if kind in {'unless','until'}:label='not ('+label+')'
            current=self.node('condition' if kind in {'if','unless','elseif'} else 'loop',label,t.line,t.column,
                              self.ts[max(u[2],u[3]-1)].line if u[2]<len(self.ts) else t.line)
            if kind in {'if','unless','elseif'}:
                yes=self.emit(u[4],follow,exit_id,break_to,continue_to,depth+1) if u[4] else follow
                no=self.emit(u[5],follow,exit_id,break_to,continue_to,depth+1) if u[5] else follow
                self.edge(current,yes,'true',label);self.edge(current,no,'false','not ('+label+')');return current
            body=self.emit(u[4],current,exit_id,follow,current,depth+1) if u[4] else current
            self.edge(current,body,'loop-body','next iteration');self.edge(current,follow,'loop-exit','loop finished')
            if kind in {'for','foreach'}:
                self.notes.add('Loop headers summarize iteration; initializer/update expression ordering is not expanded')
            return body if kind=='do' else current
        if kind in {'switch','when','match'}:
            self.notes.add('Switch/match dispatch requires review at line '+str(t.line))
            current=self.node('gap',kind+' '+self.text(u[2],u[3]),t.line,t.column)
            self.edge(current,follow,'unresolved','unresolved dispatch');return current
        end=u[2];word=self.word(t)
        label=self.text(a,end) or t.text
        terminal=word in {'return','throw','raise','break','continue','exit','die','goto'}
        nodekind='gap' if kind=='gap' or word=='goto' else word if terminal else 'statement'
        current=self.node(nodekind,label,t.line,t.column,self.ts[max(a,end-1)].line)
        if word in {'return','throw','raise','exit','die'}:self.edge(current,exit_id,word)
        elif word in {'break','continue'}:
            target=break_to if word=='break' else continue_to
            if not target:self.notes.add('Unresolved '+word+' target at line '+str(t.line))
            self.edge(current,target or exit_id,word if target else 'unresolved')
        elif word=='goto':self.notes.add('Goto target requires review at line '+str(t.line))
        else:self.edge(current,follow,'unresolved' if nodekind=='gap' else 'normal')
        return current

    def build(self):
        scopes=[dict(start=0,body=0,end=len(self.ts),name='<module>',owner='')]+self.scopes[:99]
        if len(self.scopes)>99:self.notes.add('CFG function budget reached')
        for f in scopes:
            line=self.ts[f['start']].line if self.ts else 1
            end=self.ts[min(f['end'],len(self.ts)-1)].line if self.ts else 1
            name=(f.get('owner','')+'.' if f.get('owner') else '')+f['name']
            entry,exit_id=self.begin(name,line,end,self.ts[f['start']].column if self.ts else 1)
            self.edge(entry,self.sequence(f['body'],f['end'],exit_id,exit_id))
        return self.result()


def build_cfg(path,source,language,deadline=None):
    builder=PythonCFG(path,source,deadline=deadline) if language=='python' else TokenCFG(path,source,language,deadline=deadline)
    try:
        return builder.build(ast.parse(source)) if language=='python' else builder.build()
    except (AnalysisBudgetExceeded,RecursionError) as exc:
        builder.notes.add(str(exc));return builder.result()
