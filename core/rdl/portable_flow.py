"""Bounded structural may-flow with callsite-balanced project handoffs.

Local expressions are versioned: overwrites kill old values; branch bodies
merge their environments. Calls resolved to project bodies never receive an
opaque argument-to-return shortcut. Unknown calls retain explicit limitations.
"""
import re
import time
from dataclasses import replace
from pathlib import Path
from utils.source_cache import read_source_text

from .adapters.tokenized import _lex, _Token
from .ast import EntityType
from .cache import AnalysisBudgetExceeded
from .flow import DataFlowGraph, FlowEdge
from .ir import IRBuilder, SourceLocation, EdgeKind
from .plan import Capability
from .portable_profiles import INPUT, PARAMETER_SOURCE, HTML_ENCODERS, is_source, sink_concepts

CONTROL = {'if', 'while', 'for', 'foreach', 'switch', 'catch', 'when', 'with', 'synchronized', 'using', 'match'}
DECLARATIONS = {'function', 'func', 'fun', 'fn', 'def', 'sub', 'Function', 'Sub'}
TYPES = {'const', 'let', 'var', 'val', 'mut', 'ref', 'out', 'in', 'String', 'string', 'int', 'char', 'void', 'auto', 'public', 'private', 'static', 'final', 'async', 'export', 'suspend', 'pub', 'return', 'new', 'await', 'Dim', 'As', 'ByVal', 'ByRef'}
MOBILE_INPUT_TYPES = {'EditText', 'TextInputEditText', 'AutoCompleteTextView', 'MultiAutoCompleteTextView', 'ScanIntentResult'}


def _kotlin_template_parts(text, raw):
    openings = [m for m in re.finditer(r'(\\*)\$\{', text)
                if raw or len(m.group(1)) % 2 == 0]
    expressions = [m.group(2) for m in re.finditer(r'(\\*)\$\{([^{}]*)\}', text)
                   if raw or len(m.group(1)) % 2 == 0]
    return len(openings), expressions


def _normalized(source, language):
    """Normalize block delimiters for line-oriented languages, retaining lines."""
    if language == 'rust':
        return re.sub(r"'([A-Za-z_]\w*)\b(?!')", r' \1', source)
    if language not in {'ruby', 'vb', 'bash', 'powershell'}:
        return source
    result = []
    for line in source.splitlines():
        if language in {'ruby', 'bash', 'powershell'}:
            line = re.sub(r'^([ \t]*)#.*', r'\1', line)
        if language == 'ruby':
            line = re.sub(r'^(\s*)def\s+([\w.]+)(?:\((.*?)\)|\s+([^#]+))?\s*$', lambda m: m[1]+'function '+m[2]+'('+(m[3] or m[4] or '')+') {', line)
            line = re.sub(r'^(\s*)(?:class|module)\s+(\w+).*$', r'\1class \2 {', line)
            line = re.sub(r'^(\s*)end\b', r'\1}', line)
            line = re.sub(r'^(\s*)else\s*$', r'\1} else {', line)
            line = re.sub(r'^(\s*)(if|unless|while)\s+(.+)$', r'\1\2 (\3) {', line)
        if language == 'vb':
            line = re.sub(r"^\s*'.*", '', line)
            line = re.sub(r'(?i)^\s*End\s+(?:Function|Sub|Class|If|While)\b.*', '}', line)
            line = re.sub(r'(?i)\b(Function|Sub)\s+(\w+)\s*\((.*?)\)(?:\s+As\s+\w+)?\s*$', r'function \2(\3) {', line)
            line = re.sub(r'(?i)\bClass\s+(\w+)\s*$', r'class \1 {', line)
            line = re.sub(r'(?i)^(\s*)If\s+(.+)\s+Then\s*$', r'\1if (\2) {', line)
            line = re.sub(r'(?i)^(\s*)Else\s*$', r'\1} else {', line)
            line = re.sub(r'(?i)\bReturn\b', 'return', line)
        result.append(line)
    return '\n'.join(result)


class Walker:
    def __init__(self, path, language, *, source=None, max_tokens=200000):
        self.path, self.language = Path(path), language
        self.source = source if source is not None else read_source_text(self.path, encoding='utf-8')
        self.tokens = _lex(_normalized(self.source, language), php=language == 'php', hash_comments=language in {'ruby','bash','powershell'}, javascript=language == 'javascript', kotlin=language == 'kotlin')
        if len(self.tokens) > max_tokens:
            raise AnalysisBudgetExceeded('portable flow token budget exceeded')
        self.operation_imports={}
        if language in {'java','kotlin'}:
            for index,token in enumerate(self.tokens):
                if token.kind!='identifier' or token.text!='import':continue
                words=[]
                for item in self.tokens[index+1:index+40]:
                    if item.line!=token.line or item.text==';':break
                    if item.kind!='string':words.append(item.text)
                if 'as' in words:
                    alias=words[words.index('as')+1] if words.index('as')+1<len(words) else ''
                    words=words[:words.index('as')]
                else:alias=words[-1] if words else ''
                qualified=''.join(words)
                if qualified in {'org.springframework.beans.BeanUtils','org.apache.commons.beanutils.BeanUtils',
                                 'org.apache.commons.beanutils2.BeanUtils','org.apache.commons.beanutils.BeanUtilsBean',
                                 'org.apache.commons.beanutils2.BeanUtilsBean'}:
                    self.operation_imports[alias]=qualified
        self.builder = IRBuilder(language, language + '-project-flow', '1')
        self.pairs, stack = {}, []
        unmatched = False
        for i, t in enumerate(self.tokens):
            if t.kind != 'symbol':
                continue
            if t.text in {'(', '[', '{'}:
                stack.append(i)
            elif t.text in {')', ']', '}'}:
                if stack and self.tokens[stack[-1]].text == {')': '(', ']': '[', '}': '{'}[t.text]:
                    start = stack.pop(); self.pairs[start] = i
                else:
                    unmatched = True
        self.opening_by_close = {end: start for start, end in self.pairs.items()}
        self.functions = []
        self.scope = '<module>'
        self.default_keys = set()
        self.owner = ''
        self.limits = set()
        for token in self.tokens:
            if self.language == 'kotlin' and token.quote in {'"', '"""'} and '${' in token.text:
                count, expressions = _kotlin_template_parts(token.text, token.quote == '"""')
                if count != len(expressions) or any(
                    not (expression.strip().isidentifier() or expression.strip() == "'$'")
                    for expression in expressions
                ):
                    kind = 'raw-string' if token.quote == '"""' else 'string-template'
                    self.limits.add('Executable or nested '+kind+' interpolation requires review in '+str(self.path))
        if any(t.kind == 'invalid' for t in self.tokens):
            self.limits.add('Unterminated string or template in '+str(self.path))
        if stack or unmatched:
            self.limits.add('Unbalanced or unsupported block syntax in '+str(self.path))
        # Java/Kotlin/C# wildcard generics are not server template delimiters.
        # Template execution applies only to source formats that embed it.
        if self.path.suffix.lower() in {'.jsp', '.jspx', '.erb', '.aspx', '.ascx', '.cshtml'} and any(t.kind == 'symbol' and t.text == '<' and i + 1 < len(self.tokens) and self.tokens[i + 1].text in {'%', '?'} for i, t in enumerate(self.tokens)):
            self.limits.add('Embedded template execution requires manual review in '+str(self.path))
        if self.language in {'bash','powershell'} and re.search(r'\beval\b|\bInvoke-Expression\b',self.source,re.I):
            self.limits.add('Dynamically evaluated code is a sink; its generated call graph is not resolved in '+str(self.path))
        self.types = {}
        self.declared_types = {}
        for match in re.finditer(r'\b([A-Z]\w*)\s+([a-z_]\w*)\b',self.source):
            self.declared_types[match[2]]=match[1]
        for match in re.finditer(r'\b(\w+)\s*:\s*([A-Z]\w*)\b',self.source):
            self.declared_types[match[1]]=match[2]
        self.discover()
        self.mobile_fields = {}
        if language in {'java', 'kotlin'}:
            for index, token in enumerate(self.tokens[:-1]):
                if token.text not in MOBILE_INPUT_TYPES | {'ZipEntry', 'ZipInputStream'} or any(f['start'] <= index <= f['end'] for f in self.functions):
                    continue
                owner = next((name for start,end,name in reversed(self.classes) if start < index < end), '')
                if index > 1 and self.tokens[index-1].text == ':':
                    self.mobile_fields[(owner,self.tokens[index-2].text)] = token.text
                elif self.tokens[index+1].kind == 'identifier':
                    self.mobile_fields[(owner,self.tokens[index+1].text)] = token.text
                    cursor=index+2
                    while cursor+1 < len(self.tokens) and self.tokens[cursor].text == ',' and self.tokens[cursor+1].kind == 'identifier':
                        self.mobile_fields[(owner,self.tokens[cursor+1].text)] = token.text
                        cursor += 2
        self.function_starts = {f['start']: f['end']+1 for f in self.functions}

    def text(self, a, b):
        return ''.join(t.text if t.kind != 'string' else t.quote+t.text+t.quote for t in self.tokens[a:b])

    def node(self, i, name, role, concepts=(), kind=EntityType.VARIABLE, attrs=None):
        t = self.tokens[min(i, len(self.tokens)-1)] if self.tokens else _Token('', 1, 1, '')
        data = dict(role=role, flow_scope=self.scope, owner=self.owner)
        data.update(attrs or {})
        return self.builder.add_entity(kind, name, name,
            SourceLocation(str(self.path), t.line, t.column, t.line, t.column+max(1,len(t.text))),
            role, concepts=concepts, attributes=data)

    def edge(self, source, target, kind, argument=None):
        self.builder.add_edge(source, target, EdgeKind.ASSIGNS, {'flow_kind': kind, 'argument': argument})

    def top(self, a, b, symbols):
        i = a
        while i < b:
            if self.tokens[i].kind == 'symbol' and self.tokens[i].text in symbols:
                yield i
            if i in self.pairs:
                i = self.pairs[i]
            i += 1

    def segments(self, a, b):
        last = a
        for i in self.top(a,b,{','}):
            yield last,i; last=i+1
        if last < b:
            yield last,b

    def discover(self):
        ts = self.tokens
        classes = []
        for i,t in enumerate(ts):
            if t.text in {'class','object','struct','impl','extension','interface'} and i+1<len(ts):
                end = next((j for j in range(i+2,min(i+40,len(ts))) if ts[j].text in {'{',';'}),None)
                if end is not None and end in self.pairs:
                    classes.append((end,self.pairs[end],ts[i+1].text))
        if self.language == 'objc':
            for i,t in enumerate(ts[:-2]):
                if t.text in {'implementation','interface'}:
                    end=next((k for k in range(i+2,len(ts)) if ts[k].text=='end'),len(ts))
                    classes.append((i,end,ts[i+1].text))
            for i,t in enumerate(ts[:-2]):
                if t.text not in {'-','+'} or ts[i+1].text!='(' or i+1 not in self.pairs:continue
                k=self.pairs[i+1]+1
                if k>=len(ts) or ts[k].kind!='identifier':continue
                name=ts[k].text;params=[];j=k+1
                while j<len(ts) and ts[j].text not in {'{',';'}:
                    if ts[j].text==':' and j+1 in self.pairs:
                        variable=self.pairs[j+1]+1
                        if variable<len(ts):params.append((variable,ts[variable].text,False))
                        j=variable
                    j+=1
                if j in self.pairs and ts[j].text=='{':
                    owner=next((c[2] for c in reversed(classes) if c[0]<i<c[1]),'')
                    self.functions.append(dict(start=i,opening=i,body=j+1,end=self.pairs[j],name=name,owner=owner,params=params))
        self.classes = classes
        for i,t in enumerate(ts):
            if t.text != '(' or i not in self.pairs or not i:
                continue
            name = ts[i-1].text
            if ts[i-1].kind != 'identifier' or name in CONTROL:
                continue
            close = self.pairs[i]
            j=close+1
            while j < min(close+40,len(ts)) and ts[j].text not in {'{',';','=','=>','}', '('}:
                if ts[j].line > ts[close].line+2: break
                j+=1
            if j>=len(ts) or ts[j].text!='{' or j not in self.pairs:
                continue
            prev = ts[i-2].text if i>=2 else ''
            if prev in {'.','::','->','new','return','=','@'}:
                continue
            if self.language in {'java', 'kotlin', 'csharp'} and (
                    prev in {'(', '!', '&&', '||', '?'}
                    or any(t.text == ')' for t in ts[close+1:j])):
                # A call inside a control condition is not a declaration.
                continue
            # Braced declarations, including typed methods and named functions.
            start=i-1
            while start>0 and ts[start-1].line==ts[i-1].line and ts[start-1].text not in {';','{','}'}:
                start-=1
            prefix = {x.text for x in ts[start:i-1]}
            if not (prefix & DECLARATIONS or name in {'func','function'} or self.language in {'c','cpp','java','csharp','dart','objc','carbon','groovy','javascript','bash'}):
                continue
            owner = next((c[2] for c in reversed(classes) if c[0]<i<c[1]),'')
            header_start = start
            while header_start > 0 and ts[header_start-1].text not in {';', '{', '}'}:
                header_start -= 1
            spring_route = self.language == 'java' and bool(re.search(
                r'@(?:RequestMapping|GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping)\b',
                self.text(header_start, i-1)))
            action_header = self.text(header_start, i-1)
            csharp_route = self.language == 'csharp' and bool(re.search(r'\[(?:HttpGet|HttpPost|HttpPut|HttpPatch|HttpDelete|HttpHead|HttpOptions)\b', action_header)) and not re.search(r'\[NonAction\b', action_header)
            params=[]
            for a,b in self.segments(i+1,close):
                cutoff=next(iter(self.top(a,b,{'='})),b)
                ids=[k for k in range(a,cutoff) if ts[k].kind=='identifier' and ts[k].text not in TYPES]
                # Decorators / annotations are not parameter identifiers.
                colon=next(iter(self.top(a,cutoff,{':'})),None)
                if colon is not None:
                    ids=[k for k in ids if k<colon]
                if self.language=='vb':
                    aspos=next((k for k in range(a,cutoff) if ts[k].text.lower()=='as'),cutoff)
                    ids=[k for k in ids if k<aspos]
                if ids:
                    k=ids[0] if self.language in {'go','rust','vb'} else ids[-1]
                    if self.language=='rust':
                        destructured=next((j for j in range(a,cutoff) if ts[j].text=='(' and j in self.pairs),None)
                        if destructured is not None and destructured+1<len(ts):k=destructured+1
                    parameter_text = re.sub(r'\s*([@\[\]<:])\s*',r'\1',' '.join(x.text for x in ts[a:b]))
                    source = bool(PARAMETER_SOURCE.search(parameter_text))
                    if spring_route and '@' not in parameter_text:
                        infrastructure = {'HttpServletRequest', 'HttpServletResponse', 'HttpSession',
                                          'ServletRequest', 'ServletResponse', 'Model', 'ModelMap',
                                          'ModelAndView', 'BindingResult', 'Errors', 'Principal',
                                          'Authentication', 'Locale', 'WebRequest', 'SessionStatus',
                                          'RedirectAttributes', 'UriComponentsBuilder'}
                        source = not any(ts[x].text in infrastructure for x in range(a,b))
                    if csharp_route and not any(ts[x].text in {'CancellationToken', 'HttpContext', 'HttpRequest', 'HttpResponse', 'ClaimsPrincipal', 'IServiceProvider'} for x in range(a,b)) and 'FromServices' not in parameter_text:
                        source = True
                    params.append((k,ts[k].text,source))
            if self.language == 'powershell' and not params and j+1 < self.pairs[j] and ts[j+1].text.lower() == 'param':
                popen=j+2
                if popen in self.pairs:
                    params=[(k,ts[k].text,False) for k in range(popen+1,self.pairs[popen]) if ts[k].text.startswith('$')]
            if self.language == 'bash':
                positional = sorted({int(x) for x in re.findall(r'\$([1-9])', self.text(j+1,self.pairs[j]))})
                params = [(j, '$'+str(k), False) for k in range(1, max(positional, default=0)+1)]
            self.functions.append(dict(start=start,opening=i,body=j+1,end=self.pairs[j],name=name,owner=owner,params=params))
        if self.language == 'powershell':
            for i,t in enumerate(ts[:-2]):
                if t.text.lower()=='function' and ts[i+2].text=='{' and i+2 in self.pairs:
                    j=i+2;params=[]
                    if j+2<len(ts) and ts[j+1].text.lower()=='param' and j+2 in self.pairs:
                        params=[(k,ts[k].text,False) for k in range(j+3,self.pairs[j+2]) if ts[k].text.startswith('$')]
                    self.functions.append(dict(start=i,opening=i,body=j+1,end=self.pairs[j],name=ts[i+1].text,owner='',params=params))
        # Named arrow functions; expression bodies become implicit returns.
        if self.language in {'javascript','kotlin','dart','csharp'}:
            for i,t in enumerate(ts):
                if t.text!='=>': continue
                opening = self.opening_by_close.get(i-1)
                if opening is not None and ts[opening].text != '(':
                    opening = None
                a=opening if opening is not None else i-1
                named = a>=2 and ts[a-1].text=='='
                name=ts[a-2].text if named else '<callback:{}>'.format(ts[i].line)
                end=self.pairs.get(i+1)
                expression=end is None
                if expression:
                    end=next((j for j in range(i+1,len(ts)) if ts[j].text==';' or ts[j].line>t.line),len(ts))
                params=[]
                if opening is not None:
                    for left,right in self.segments(a+1,i-1):
                        ids=[k for k in range(left,right) if ts[k].kind=='identifier']
                        k=(ids[-1] if self.language=='csharp' else ids[0]) if ids else None
                        if k is not None:params.append((k,ts[k].text,bool(PARAMETER_SOURCE.search(self.text(left,right)))))
                else:params=[(a,ts[a].text,False)]
                self.functions.append(dict(start=a-2 if named else a,opening=a,body=i+1 if expression else i+2,end=end,name=name,owner='',params=params,expression=expression))

    def parse(self):
        if self.language == 'csharp':
            from .dotnet_security import token_policy_settings
            token_policy_settings(self)
        # Function ranges also keep top-level execution out of function bodies.
        for f in self.functions:
            self.scope='{}:{}'.format(f['name'],self.tokens[f['start']].line);self.owner=f['owner']
            f['scope']=self.scope
            env={}; params=[]
            for k,name,source in f['params']:
                if self.language in {'java', 'csharp'} and k and self.tokens[k-1].kind == 'identifier':
                    self.types[(self.scope,name)] = self.tokens[k-1].text
                elif self.language == 'kotlin' and k+2 < len(self.tokens) and self.tokens[k+1].text == ':':
                    self.types[(self.scope,name)] = self.tokens[k+2].text
                parameter_concepts = set(INPUT if source else {'input.parameter'})
                if source and self.language in {'java', 'csharp'} and self.types.get((self.scope,name)) in {'byte', 'short', 'int', 'long', 'Byte', 'Short', 'Integer', 'Long'}:
                    parameter_concepts.add('sanitizer.sql-numeric')
                n=self.node(k,name,'parameter',parameter_concepts,EntityType.PARAMETER)
                params.append(n);env[name]={n}
            self.node(f['start'],f['name'],'function',{'program.function'},EntityType.FUNCTION,
                      {'parameters':tuple(p.entity_id for p in params),'arity':len(params),'body_scope':self.scope})
            if f.get('expression'):
                values=self.expr(f['body'],f['end'],env)
                n=self.node(f['body'],f['name'],'return',attrs={'return_scope':self.scope})
                for v in values:self.edge(v,n,'return')
            else:
                self.block(f['body'],f['end'],env)
        self.scope='<module>';self.owner=''
        self.block(0,len(self.tokens),{})
        if self.limits:
            self.node(0,'coverage','coverage',attrs={'flow_limits':tuple(sorted(self.limits))})
        return self.builder.build({Capability.ENTITIES, Capability.CONFIGURATION}
                                  if self.language == 'csharp' else {Capability.ENTITIES})

    def block(self,a,b,env,depth=0):
        if depth>64:raise AnalysisBudgetExceeded('portable block depth budget exceeded')
        skip=self.function_starts
        i=a
        while i<b:
            if i in skip:
                i=skip[i];continue
            t=self.tokens[i]
            if t.text in {';', '}'}:i+=1;continue
            if t.text in CONTROL or t.text in {'else','try','finally','unless'}:
                j=i+1
                while j<b and self.tokens[j].text!='{':
                    if j in self.pairs:j=self.pairs[j]
                    j+=1
                if j in self.pairs:
                    end=self.pairs[j]
                    self.expr(i+1,j,env)
                    branch={k:set(v) for k,v in env.items()}
                    before_defaults=self.default_keys
                    condition=[token for token in self.tokens[i+1:j] if token.text not in {'(',')'}]
                    if (t.text == 'if' and len(condition)==3 and condition[0].kind=='identifier'
                            and condition[1].text=='==' and condition[2].kind=='string' and condition[2].text==''):
                        key=condition[0].text
                        lookup=any(value.attribute('environment_lookup') for value in env.get(key,()))
                        if lookup:self.default_keys=before_defaults|{key}
                    try:
                        self.block(j+1,end,branch,depth+1)
                    finally:
                        self.default_keys=before_defaults
                    after=end+1
                    if t.text in {'if','unless'} and after+1<b and self.tokens[after].text=='else' and self.tokens[after+1].text=='{' and after+1 in self.pairs:
                        alternate={k:set(v) for k,v in env.items()}
                        last=self.pairs[after+1]
                        self.block(after+2,last,alternate,depth+1)
                        env.clear()
                        for k in set(branch)|set(alternate):env[k]=branch.get(k,set())|alternate.get(k,set())
                        i=last+1
                    else:
                        for k,v in branch.items():env.setdefault(k,set()).update(v)
                        i=end+1
                    if t.text in {'while','for','foreach','switch','match'}:
                        self.limits.add('Loop-carried or multi-way branch state needs review at {}:{}'.format(self.path,t.line))
                    continue
            if t.text in {'class','object','struct','impl','extension','namespace','interface'}:
                j=next((k for k in range(i+1,b) if self.tokens[k].text in {'{',';'}),b)
                if j in self.pairs:
                    self.block(j+1,self.pairs[j],env,depth+1);i=self.pairs[j]+1;continue
            if t.text in {'import','package','using','use','mod','require','require_relative'} or t.text=='#':
                line=t.line;i+=1
                while i<b and self.tokens[i].line==line:i+=1
                continue
            j=i
            while j<b:
                if self.tokens[j].text in {';','}'}:break
                if j>i and self.tokens[j].line>self.tokens[j-1].line and self.tokens[j-1].text not in {'=',':=',',','+','-','.','(', '=>'} and self.tokens[j].text not in {'.','+',')',','}:
                    break
                if j in self.pairs:j=self.pairs[j]
                j+=1
            if j==i:i+=1;continue
            if self.language in {'ruby','rust','swift'} and self.scope!='<module>' and j==b and not list(self.top(i,j,{'=',':='})) and t.text!='return':
                values=self.expr(i,j,env)
                result=self.node(i,'return','return',attrs={'return_scope':self.scope})
                for value in values:self.edge(value,result,'return')
            else:
                self.statement(i,j,env)
            if t.text=='return':break
            i=j+1 if j<b and self.tokens[j].text==';' else j
        return env

    def statement(self,a,b,env):
        ts=self.tokens
        if self.language=='powershell' and ts[a].text.lower()=='param' and self.scope=='<module>':
            for k in range(a+1,b):
                if ts[k].text.startswith('$'):
                    env[ts[k].text]={self.node(k,ts[k].text,'input',INPUT,EntityType.PARAMETER)}
            return
        if ts[a].text=='return':
            values=self.expr(a+1,b,env)
            n=self.node(a,'return','return',attrs={'return_scope':self.scope})
            for v in values:self.edge(v,n,'return')
            return
        equal=next(iter(self.top(a,b,{'=',':='})),None)
        if equal is not None:
            left=[k for k in range(a,equal) if ts[k].kind=='identifier' and ts[k].text not in TYPES]
            if left:
                colon=next(iter(self.top(a,equal,{':'})),None)
                if colon is not None:left=[k for k in left if k<colon]
                if left:
                    k=left[-1];name=ts[k].text
                    values=self.expr(equal+1,b,env)
                    from .security_operations import token_fallback, token_environment, FALLBACK
                    rhs=ts[equal+1:b]
                    explicit_default = name in self.default_keys and len(rhs)==1 and rhs[0].kind=='string' and bool(rhs[0].text)
                    fallback = {FALLBACK} if token_fallback(rhs) or explicit_default else ()
                    node=self.node(k,name,'assignment',fallback,attrs={'environment_lookup':token_environment(rhs)})
                    for v in values:self.edge(v,node,'assignment')
                    env[name]={node} if values or fallback else set()
                    constructed=re.match(r'(?:new)?([\w:]+)\(',self.text(equal+1,b))
                    if constructed:self.types[(self.scope,name)]=constructed[1]
                    if self.language == 'java' and k and ts[k-1].kind == 'identifier' and ts[k-1].text[:1].isupper():
                        self.types[(self.scope,name)] = ts[k-1].text
                    elif self.language == 'kotlin' and colon is not None and colon+1 < equal:
                        self.types[(self.scope,name)] = ts[colon+1].text
                    archive = re.fullmatch(r'(\w+)\??\.(?:getNextEntry\(\)|nextEntry)', self.text(equal+1,b))
                    if archive and self.types.get((self.scope, archive[1]), self.mobile_fields.get((self.owner, archive[1]), '')) == 'ZipInputStream':
                        self.types[(self.scope,name)] = 'ZipEntry'
                    return
        if self.language in {'bash','powershell','ruby'} and ts[a].kind=='identifier' and (a+1>=b or ts[a+1].text!='(') and (self.language!='ruby' or a+1<b and ts[a+1].text not in {'.','[','+', '-', '*', '/'}):
            # Shell command syntax has whitespace arguments, not C call syntax.
            name=ts[a].text
            k=a+1
            while k+1<b and ts[k].text=='-' and ts[k+1].kind=='identifier':
                name+='-'+ts[k+1].text;k+=2
            arguments=[]
            for x in range(k,b):
                values=self.expr(x,x+1,env)
                arguments.append(values)
            returned=self.call(a,name,arguments,env)
            if self.language=='bash' and name in {'read','readarray'}:
                variable=next((x for x in reversed(range(k,b)) if ts[x].kind=='identifier'),None)
                if variable is not None:env[ts[variable].text]=returned
            return
        self.expr(a,b,env)

    def javascript_regexp_receiver(self, index, name):
        if self.language != 'javascript' or not re.fullmatch(r'\w+\.exec', name):
            return False
        receiver = name.split('.')[0]
        def scopes(position):
            return tuple(f['start'] for f in self.functions if f['start'] <= position < f['end'])
        active = scopes(index)
        for function in self.functions:
            if function['start'] in active and any(parameter[1] == receiver for parameter in function['params']):
                return False
        binding = None
        for position in range(index):
            if self.tokens[position].text != receiver or not set(scopes(position)) <= set(active):
                continue
            if position and self.tokens[position-1].text in {'.', '?.'}:
                continue
            if self.text(position+1, min(position+4,len(self.tokens))) == '.exec=':
                return False
            if position+2 < len(self.tokens) and self.tokens[position+1].text == '=':
                value = self.tokens[position+2]
                binding = value.kind == 'string' and value.quote == '/'
        return bool(binding)

    def call(self,i,name,arguments,env,receiver=(),unsafe_type_resolution=False,argument_spans=(),generic_type=''):
        concepts=sink_concepts(self.language,name)
        if self.language == 'javascript' and name.endswith('.postMessage.send'):
            concepts.discard('output.html')
            concepts.add('data.message-send')
        if self.javascript_regexp_receiver(i, name):
            concepts.discard('command.execution')
            concepts.add('data.regex-matching')
        from .security_operations import operation_arguments, token_arguments, token_labels
        operation_name = name
        first,dot,rest=name.partition('.')
        if first in self.operation_imports:
            operation_name=self.operation_imports[first]+(dot+rest if dot else '')
        operations = operation_arguments(self.language, operation_name, token_arguments(self.tokens, argument_spans),len(arguments),token_labels(self.tokens,argument_spans))
        if (self.language == 'csharp' and name in {'JsonConvert.DeserializeObject','Newtonsoft.Json.JsonConvert.DeserializeObject'}
                and generic_type and generic_type not in {'string','String','int','Int32','long','Int64','double','float','bool','Boolean','byte','object','JObject','JToken'}):
            from .security_operations import MASS
            operations[MASS] = (0,)
        concepts.update(operations)
        if self.language == 'csharp' and name.endswith('DeserializeObject'):
            if unsafe_type_resolution: concepts.add('deserialization.object-construction')
            elif len(arguments) > 1:
                self.limits.add('JSON serializer settings require review at ' + str(self.path) + ':' + str(self.tokens[i].line))
            if name not in {'JsonConvert.DeserializeObject', 'Newtonsoft.Json.JsonConvert.DeserializeObject'}:
                self.limits.add('Custom JSON reader configuration requires review at ' + str(self.path) + ':' + str(self.tokens[i].line))
        if name in HTML_ENCODERS.get(self.language, ()):
            concepts.add('sanitizer.contextual-output-encoding')
        if is_source(self.language,name+'('):concepts = set(INPUT)
        receiver_type = self.types.get((self.scope,name.split('.')[0]),
                                      self.declared_types.get(name.split('.')[-2] if '.' in name else '', ''))
        if self.language == 'csharp' and receiver_type.rsplit('.', 1)[-1] == 'HttpClient' and name.rsplit('.', 1)[-1] in {
            'GetStringAsync', 'GetByteArrayAsync', 'SendAsync', 'PutAsync', 'DeleteAsync', 'PatchAsync'
        }:
            concepts.add('network.outbound-request')
        if self.language == 'csharp' and receiver_type.rsplit('.', 1)[-1] in {
            'IDbConnection', 'DbConnection', 'SqlConnection', 'NpgsqlConnection', 'MySqlConnection', 'SqliteConnection'
        } and name.rsplit('.', 1)[-1] in {
            'ExecuteAsync', 'QueryAsync', 'QueryFirstAsync', 'QueryFirstOrDefaultAsync', 'QuerySingleAsync', 'QuerySingleOrDefaultAsync'
        }:
            concepts.add('sql.execution')
        receiver_name = name.split('.')[-2] if '.' in name else ''
        mobile_type = self.types.get((self.scope,receiver_name), self.mobile_fields.get((self.owner,receiver_name), ''))
        if name in {'if','while','for','switch','when'}:
            concepts.add('language.control')
        if not concepts:
            from .mobile_library import modeled_call
            from .source_review import source_views
            if not hasattr(self,'_mobile_library_views'):
                self._mobile_library_views=source_views(str(self.path),self.source)
            comments,code=self._mobile_library_views
            if modeled_call(self.language,name,receiver_type or mobile_type,comments,code):
                concepts.add('library.mobile-opaque')
        archive_receiver = receiver_name.rstrip('?')
        archive_type = self.types.get((self.scope, archive_receiver), self.mobile_fields.get((self.owner, archive_receiver), ''))
        if self.language in {'java', 'kotlin'} and name.endswith('.getName') and archive_type == 'ZipEntry':
            concepts = set(INPUT)
        # Reading an editable widget is an input boundary. Display-only
        # TextView.getText and arbitrary application getText methods are not.
        if self.language in {'java', 'kotlin'} and (
            name.endswith('.getText') and mobile_type in MOBILE_INPUT_TYPES - {'ScanIntentResult'} or
            name.endswith('.getContents') and mobile_type == 'ScanIntentResult'
        ):
            concepts = set(INPUT)
        n=self.node(i,name,'call',concepts,EntityType.CALL,
                    {'callee':name,'argument_count':len(arguments),'receiver_type':receiver_type})
        sensitive = None
        if concepts - INPUT - {'library.mobile-opaque','language.control'}:
            sensitive = {1} if name.endswith(('QueryContext', 'QueryRowContext', 'ExecContext', 'Select', 'SelectOne')) or name == 'sqlite3_exec' else {0}
        if operations:
            sensitive = {position for positions in operations.values() for position in positions}
        for position,values in enumerate(arguments):
            if sensitive is None or position in sensitive:
                for v in values:self.edge(v,n,'argument',position)
        for v in receiver:self.edge(v,n,'receiver',-1)
        return {n}

    def expr(self,a,b,env,depth=0):
        if depth>64:raise AnalysisBudgetExceeded('portable expression depth budget exceeded')
        values=set();i=a;ts=self.tokens
        if self.language == 'powershell' and a < b and re.match(r'^(?:Read-Host|Get-Content)\b', self.text(a,b)):
            return self.call(a,self.text(a,b),[],env)
        while i<b:
            if i in self.function_starts:
                i=self.function_starts[i];continue
            t=ts[i]
            if t.kind=='string':
                if self.language == 'javascript':
                    if t.quote == '`':
                        for expression in re.findall(r'\$\{([^{}]+)\}', t.text):
                            for key in re.findall(r'[A-Za-z_$][\w$]*', expression):
                                values.update(env.get(key, ()))
                            if is_source(self.language, expression):
                                values.add(self.node(i, expression, 'input', INPUT))
                        if t.text.count('${') != len(re.findall(r'\$\{([^{}]+)\}', t.text)):
                            self.limits.add('Nested template interpolation requires review in '+str(self.path))
                    i += 1
                    continue
                if t.quote in {'"','`','"""'} and self.language not in {'java','c','cpp','go'}:
                    if self.language == 'kotlin':
                        for match in re.finditer(r'(\\*)\$\{?([\w$]+)', t.text):
                            if t.quote == '"""' or len(match.group(1)) % 2 == 0:
                                values.update(env.get(match.group(2), ()))
                    else:
                        for name in re.findall(r'\$\{?([\w$]+)|#\{([\w$]+)',t.text):
                            key=name[0] or name[1]
                            values.update(env.get(key,env.get('$'+key,())))
                    if self.language=='csharp' and i>a and ts[i-1].text=='$':
                        for key in re.findall(r'\{(\w+)\}',t.text):values.update(env.get(key,()))
                    if self.language=='swift':
                        for key in re.findall(r'\\\((\w+)\)',t.text):values.update(env.get(key,()))
                    if self.language=='bash':
                        for key in re.findall(r'\$[1-9]',t.text):values.update(env.get(key,()))
                    if is_source(self.language,t.text) and not (self.language=='bash' and self.scope!='<module>'):
                        values.add(self.node(i,t.text,'input',INPUT))
                i+=1;continue
            if t.kind=='identifier' and t.text not in TYPES:
                j=i+1;name=t.text
                while j+1<b:
                    if j+2<b and ts[j].text=='?' and ts[j+1].text=='.' and ts[j+2].kind=='identifier':
                        name+='.'+ts[j+2].text; j+=3
                    elif ts[j].text in {'.','::','->','?.'} and ts[j+1].kind=='identifier':
                        name+=('.' if ts[j].text=='?.' else ts[j].text)+ts[j+1].text; j+=2
                    else:
                        break
                generic_type = ''
                if self.language == 'csharp' and j < b and ts[j].text == '<':
                    cursor, level = j+1, 1
                    while cursor < min(b, j+128) and level:
                        level += (ts[cursor].text == '<') - (ts[cursor].text == '>')
                        cursor += 1
                    if not level and cursor < b and ts[cursor].text == '(':
                        generic_type = self.text(j+1,cursor-1)
                        j = cursor
                if j<b and ts[j].text=='!' and j+1<b and ts[j+1].text=='(':j+=1
                if j<b and ts[j].text=='(' and j in self.pairs:
                    close=self.pairs[j]
                    argument_spans = list(self.segments(j+1,close))
                    args=[self.expr(x,y,env,depth+1) for x,y in argument_spans]
                    from .security_operations import token_fallback, FALLBACK
                    for position,(first,end) in enumerate(argument_spans):
                        if token_fallback(ts[first:end]):
                            marker=self.node(first,'literal configuration fallback','fallback',{FALLBACK})
                            for value in args[position]:self.edge(value,marker,'configuration-fallback')
                            args[position]={marker}
                    if (self.language == 'csharp' and name == t.text
                            and name in {'if', 'for', 'foreach', 'while', 'switch', 'catch', 'lock', 'using'}
                            and not (i > 0 and ts[i - 1].text == '@')):
                        # A control keyword encountered inside an expression
                        # region is unsupported single-statement/block syntax,
                        # not an unresolved application API. Retain provenance
                        # and uncertainty instead of inventing a call graph node.
                        values.update(set().union(*args) if args else set())
                        self.limits.add('Single-statement control flow needs review at {}:{}'.format(self.path,t.line))
                        i=close+1
                        continue
                    receivers=env.get(t.text,()) if name!=t.text else ()
                    unsafe_types = self.language == 'csharp' and bool(re.search(r'TypeNameHandling\s*=\s*TypeNameHandling\s*\.\s*(?:All|Auto|Objects|Arrays)\b', self.text(j+1,close)))
                    returned=self.call(i,name,args,env,receivers,unsafe_type_resolution=unsafe_types,argument_spans=argument_spans,generic_type=generic_type)
                    values.update(returned)
                    if self.language in {'c','cpp'} and name.split('::')[-1] in {'gets','fgets','getline','read','recv'}:
                        position=1 if name in {'read','recv'} else 0
                        spans=list(self.segments(j+1,close))
                        if position<len(spans):
                            left,right=spans[position]
                            variable=next((k for k in range(left,right) if ts[k].kind=='identifier'),None)
                            if variable is not None:
                                written=self.node(variable,ts[variable].text,'assignment')
                                for value in returned:self.edge(value,written,'assignment')
                                env[ts[variable].text]={written}
                    i=close+1;continue
                end=j
                while end<b and ts[end].text=='[' and end in self.pairs:end=self.pairs[end]+1
                expression=self.text(i,end)
                archive_name = (self.language in {'java','kotlin'} and expression.endswith('.name') and self.types.get((self.scope, expression.split('.')[-2].rstrip('?')), self.mobile_fields.get((self.owner, expression.split('.')[-2].rstrip('?')), '')) == 'ZipEntry')
                if archive_name or is_source(self.language,expression):
                    values.add(self.node(i,expression,'input',INPUT))
                elif t.text in env:
                    n=self.node(i,expression,'read')
                    for v in env[t.text]:self.edge(v,n,'read')
                    values.add(n)
                i=max(j,end);continue
            if i in self.pairs:
                close=self.pairs[i]
                if self.language=='objc' and t.text=='[' and i+2<close:
                    receiver=ts[i+1].text;selector=ts[i+2].text
                    separators=list(self.top(i+3,close,{':'}))
                    args=[]
                    for position,k in enumerate(separators):
                        end=separators[position+1]-1 if position+1<len(separators) else close
                        args.append(self.expr(k+1,end,env,depth+1))
                    values.update(self.call(i,receiver+'.'+selector,args,env,env.get(receiver,())))
                else:
                    values.update(self.expr(i+1,close,env,depth+1))
                i=close+1;continue
            i+=1
        return values


def parse_portable(path, language):
    return Walker(path,language).parse()


def build_project_flow(ir, max_seconds=None):
    """Resolve only unique, visible local definitions; never join by name alone."""
    deadline = time.monotonic() + max_seconds if max_seconds is not None else None
    entities={e.entity_id:e for e in ir.entities}
    edges=[FlowEdge(e.source_id,e.target_id,dict(e.attributes)['flow_kind'],dict(e.attributes).get('argument'))
           for e in ir.edges if 'flow_kind' in dict(e.attributes)]
    functions=[e for e in entities.values() if e.attribute('role')=='function']
    calls=[e for e in entities.values() if e.attribute('role')=='call']
    returns={}
    for e in entities.values():
        if e.attribute('return_scope'):
            returns.setdefault((e.location.path,e.attribute('return_scope')),[]).append(e.entity_id)
    sources={e.location.path for e in entities.values()}
    contents={p:read_source_text(Path(p), encoding='utf-8') for p in sources}
    limits=set()
    for e in entities.values():limits.update(e.attribute('flow_limits',()))
    incoming={}
    for edge in edges:incoming.setdefault(edge.target_id,[]).append(edge)
    from .portable_resolver import imported_target, visible
    paths = {Path(p) for p in sources}
    index = {}
    local_index = {}
    for function in functions:
        index.setdefault((function.name, function.attribute('arity')), []).append(function)
        local_index.setdefault((function.name, function.attribute('arity'), function.location.path), []).append(function)
    resolved = set()
    property_receivers = set()
    import_cache = {}
    declaration_cache = {}
    reference_cache = {}
    candidate_cache = {}
    for call in calls:
        if deadline is not None and time.monotonic() >= deadline:
            limits.add('Project call-resolution time budget reached; remaining calls are unresolved')
            break
        name=call.attribute('callee');parts=re.split(r'\.|::|->',name);short=parts[-1]
        import_key = (call.location.path, name)
        if import_key not in import_cache:
            import_cache[import_key] = imported_target(Path(call.location.path), contents[call.location.path], name, paths, ir.language, declaration_cache)
        explicit = import_cache[import_key]
        if explicit is not None:
            short = explicit[1]
        candidate_key = (call.location.path, name, call.attribute('argument_count'),
                         call.attribute('owner'), call.attribute('receiver_type'))
        if candidate_key not in candidate_cache:
            candidates = []
            if explicit is None:
                # Visible definitions in this file already take precedence over
                # every remote candidate. Do not resolve candidates we discard.
                local = local_index.get((short, call.attribute('argument_count'), call.location.path), ())
                candidates = [f for f in local if visible(f, call, contents, ir.language, explicit, reference_cache)]
            if not candidates:
                pool = index.get((short, call.attribute('argument_count')), ())
                if short=='<default>' and explicit is not None:
                    pool = [f for f in functions if f.attribute('arity')==call.attribute('argument_count') and
                            re.search(r'export\s+default\s+(?:async\s+)?(?:function\s+)?'+re.escape(f.name)+r'\b',contents[f.location.path])]
                candidates = [f for f in pool if visible(f, call, contents, ir.language, explicit, reference_cache)]
            candidate_cache[candidate_key] = candidates
        candidates = candidate_cache[candidate_key]
        if len(candidates)==1:
            f=candidates[0]
            # Remove opaque call edges; bind positional arguments to parameters.
            args=incoming.get(call.entity_id,())
            resolved.add(call.entity_id)
            if ir.language == 'java' and f.attribute('arity') == 0 and re.fullmatch(r'(?:get|is)[A-Z]\w*', f.name):
                from .source_review import source_views
                getter_key = (f.location.path, 'java-getter-code')
                if getter_key not in reference_cache:
                    reference_cache[getter_key] = source_views(f.location.path, contents[f.location.path])[1]
                getter_code = reference_cache[getter_key]
                getter_lines = getter_code.splitlines()[f.location.line-1:]
                body = '\n'.join([getter_lines[0][f.location.column-1:]]+getter_lines[1:]) if getter_lines else ''
                # Only a direct instance-field getter preserves receiver data.
                # Constants and computed getters still use their resolved body.
                getter = re.match(r'[^{};]*\b'+re.escape(f.name)+r'\s*\(\s*\)\s*\{\s*return\s+(?:this\.)?([A-Za-z_]\w*)\s*;\s*\}', body)
                if getter and getter[1] not in {'true', 'false', 'null'} and not getter[1].isupper() and not re.search(r'\bstatic\b[^;{}]*\b'+re.escape(getter[1])+r'\b', getter_code):
                    property_receivers.add(call.entity_id)
                    limits.add('Instance-field getter propagates receiver data without field-sensitive binding at {}:{}'.format(call.location.path, call.location.line))
            params=f.attribute('parameters',())
            for edge in args:
                if isinstance(edge.argument,int) and 0<=edge.argument<len(params):
                    edges.append(FlowEdge(edge.source_id,params[edge.argument],'argument-parameter',edge.argument,call.entity_id))
            for result in returns.get((f.location.path,f.attribute('body_scope')),()):
                edges.append(FlowEdge(result,call.entity_id,'return-call',callsite=call.entity_id))
            from .security_operations import CORS, MASS, KEY
            entities[call.entity_id]=replace(call,concepts=call.concepts-INPUT-set(sink_concepts(ir.language,name))-{CORS, MASS, KEY, 'network.outbound-request', 'sql.execution', 'data.encoding-transform', 'sanitizer.contextual-output-encoding'})
        elif len(candidates)>1:
            limits.add('Ambiguous project call {} at {}:{}'.format(name,call.location.path,call.location.line))
        elif not call.concepts and incoming.get(call.entity_id):
            # Retain may-flow through external transformations, disclose uncertainty.
            limits.add('Unresolved call {} at {}:{}'.format(name,call.location.path,call.location.line))
    edges = [e for e in edges if not(e.target_id in resolved and (e.kind == 'argument' or e.kind == 'receiver' and e.target_id not in property_receivers))]
    if len(edges)>400000:raise AnalysisBudgetExceeded('portable flow edge budget exceeded')
    return DataFlowGraph(entities,tuple(edges)),tuple(sorted(limits))
