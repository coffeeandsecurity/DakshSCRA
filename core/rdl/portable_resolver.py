"""Visibility constraints for local source call resolution."""
import re
from pathlib import Path


_REFERENCE_SPANS = re.compile(r'(?:import|from|require|include|source|use|mod|\.)([^\n;]*)')


def _reference_visible(text, stem, cache=None, origin=None):
    """Match the existing reference heuristic without retrying every dot.

    Only the first prefix in a newline/semicolon-delimited span is needed:
    its suffix contains every suffix of subsequent prefixes in that span.
    Search the original string so word boundaries retain their left context.
    """
    key = (origin, stem)
    if cache is not None and key in cache:
        return cache[key]
    # Unusual filenames can themselves span delimiters; preserve that case.
    if '\n' in stem or ';' in stem:
        result = bool(re.search(r'(?:import|from|require|include|source|use|mod|\.)[^\n;]*\b'+re.escape(stem)+r'\b', text))
    else:
        spans_key = (origin, None)
        spans = cache.get(spans_key) if cache is not None else None
        if spans is None:
            spans = tuple(match.span(1) for match in _REFERENCE_SPANS.finditer(text))
            if cache is not None:
                cache[spans_key] = spans
        pattern = re.compile(r'\b'+re.escape(stem)+r'\b')
        result = any(pattern.search(text, start, end) for start, end in spans)
    if cache is not None:
        cache[key] = result
    return result


def _module_paths(origin, specifier, paths):
    base = (origin.parent / specifier).resolve()
    candidates = {base, base / 'index'}
    return {p for p in paths if p == base or p.with_suffix('') in candidates}


def _import_declarations(origin, text, paths, language):
    declarations = []
    if language == 'javascript':
        for match in re.finditer(r'\bimport\s+(.+?)\s+from\s*[\'"]([^\'"]+)[\'"]', text):
            clause, specifier = match.groups()
            if specifier.startswith('.'):
                declarations.append(('import', clause, _module_paths(origin, specifier, paths)))
        for match in re.finditer(r'(?:const|let|var)\s+(\{[^}]+\}|\w+)\s*=\s*require\s*\(\s*[\'"]([^\'"]+)[\'"]', text):
            clause, specifier = match.groups()
            if specifier.startswith('.'):
                declarations.append(('require', clause, _module_paths(origin, specifier, paths)))
    elif language == 'dart':
        for match in re.finditer(r"import\s+['\"]([^'\"]+)['\"](?:\s+as\s+(\w+))?", text):
            specifier, alias = match.groups()
            if alias:
                declarations.append(('dart', alias, _module_paths(origin, specifier, paths)))
    return declarations


def imported_target(origin, text, name, paths, language, declaration_cache=None):
    """Return explicit module aliases (target paths, exported name), if present."""
    parts = re.split(r'\.|::|->', name)
    head, tail = parts[0], parts[-1]
    if declaration_cache is None:
        declarations = _import_declarations(origin, text, paths, language)
    else:
        if origin not in declaration_cache:
            declaration_cache[origin] = _import_declarations(origin, text, paths, language)
        declarations = declaration_cache[origin]
    for kind, clause, targets in declarations:
        if kind == 'import':
            if clause.strip()==head:
                return targets, tail if len(parts)>1 else '<default>'
            for item in clause.strip('{} ').split(','):
                item = item.strip()
                names = re.split(r'\s+as\s+', item)
                if names[-1].strip()==head:
                    return targets, tail if len(parts)>1 else names[0].strip()
            if re.search(r'\*\s+as\s+'+re.escape(head)+r'\b',clause):
                return targets, tail
        elif kind == 'require':
            if clause==head:return targets,tail
            for item in clause.strip('{} ').split(','):
                names=[n.strip() for n in item.split(':')]
                if names[-1]==head:return targets,names[0]
        elif kind == 'dart' and clause == head:
            return targets, tail
    return None


def visible(function, call, contents, language, explicit=None, reference_cache=None):
    target, origin = Path(function.location.path), Path(call.location.path)
    owner = function.attribute('owner')
    caller_owner = call.attribute('owner')
    name = call.attribute('callee')
    parts = re.split(r'\.|::|->', name)
    typed = call.attribute('receiver_type')
    local_owner = owner == caller_owner and (language != 'java' or len(parts) == 1 or len(parts) == 2 and parts[0] in {'this', 'super'})
    if owner and not (owner in parts[:-1] or owner == typed or local_owner):
        if language != 'java' or not typed:
            return False
        from .source_review import source_views
        cache_key = (str(target), 'java-class-headers')
        headers = reference_cache.get(cache_key) if reference_cache is not None else None
        if headers is None:
            _, code = source_views(target, contents[str(target)])
            headers = dict(re.findall(r'\bclass\s+(\w+)\b([^{}]*)\{', code))
            if reference_cache is not None:
                reference_cache[cache_key] = headers
        implements = re.search(r'\bimplements\s+(.+)', headers.get(owner, ''))
        if not implements or not re.search(r'\b'+re.escape(typed)+r'\b', implements[1]):
            return False
    if target == origin:
        return True
    if explicit is not None:
        return target in explicit[0]
    text, target_text = contents[str(origin)], contents[str(target)]
    if language in {'java','kotlin','csharp','vb','groovy'}:
        pattern = r'\b(?:package|namespace|Namespace)\s+([\w.]+)'
        current = re.search(pattern,text);other = re.search(pattern,target_text)
        if (current.group(1) if current else '') == (other.group(1) if other else ''):
            return True
        return bool(owner and re.search(r'\b(?:import|using|Imports)\s+[^;\n]*(?:\.'+re.escape(owner)+r'|\.\*|'+re.escape(other.group(1) if other else owner)+r')\s*;?',text))
    if language == 'go':
        package = re.search(r'\bpackage\s+(\w+)', target_text)
        if target.parent == origin.parent:
            return True
        if len(parts)>1 and package and parts[0]==package.group(1):
            return bool(re.search(r'["`][^"`]*'+re.escape(target.parent.name)+r'["`]',text))
        return False
    if language in {'c','cpp','objc','swift','carbon'}:
        # C/C++ translation units can link external declarations. Require a
        # local header include or a shared directory, then reject ambiguity.
        return target.parent==origin.parent or bool(re.search(r'#\s*(?:include|import)\s*["<][^">]*'+re.escape(target.stem)+r'\.',text))
    return _reference_visible(text, target.stem, reference_cache, str(origin))
