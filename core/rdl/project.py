"""Resolve explicit local Python imports without importing or executing code."""
import ast
import hashlib
from pathlib import Path
from utils.source_cache import read_source_bytes, read_source_text, source_stat

from utils.scan_scope import walk_source, allows_file
from .cache import AnalysisBudgetExceeded


def local_imports(path, root):
    path, root = Path(path).resolve(), Path(root).resolve()
    tree = ast.parse(read_source_text(path, encoding='utf-8'), filename=str(path))
    bindings = {}

    def module(name, base):
        stem = base.joinpath(*name.split('.')) if name else base
        for candidate in (stem.with_suffix('.py'), stem / '__init__.py'):
            resolved = candidate.resolve()
            if root in resolved.parents and resolved.is_file() and allows_file(resolved):
                return resolved
        return None

    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            base = path.parent if node.level else root
            for _ in range(max(0, node.level - 1)):
                base = base.parent
            parent = module(node.module or '', base)
            for alias in node.names:
                if alias.name == '*':
                    continue
                child = module('.'.join(filter(None, (node.module, alias.name))), base)
                if child or parent:
                    bindings[alias.asname or alias.name] = (child or parent, '' if child else alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                target = module(alias.name, root)
                if target:
                    bindings[alias.asname or alias.name] = (target, '')
    return bindings


def python_dependency_scope(entry, root, max_files=128, max_bytes=16 * 1024 * 1024):
    """A content-keyed, bounded closure of explicit imports within the target."""
    entry, root = Path(entry).resolve(), Path(root).resolve()
    if not root.is_dir() or root not in entry.parents:
        raise AnalysisBudgetExceeded('Python dependency scope requires the absolute source project root')
    pending, seen, fingerprint, total = [entry], set(), [], 0
    while pending:
        path = pending.pop()
        if path in seen or not allows_file(path):
            continue
        if len(seen) >= max_files:
            raise AnalysisBudgetExceeded('Python dependency-file budget exceeded')
        if source_stat(path).st_size > 4 * 1024 * 1024:
            raise AnalysisBudgetExceeded('source-file byte budget exceeded')
        data = read_source_bytes(path)
        total += len(data)
        if total > max_bytes:
            raise AnalysisBudgetExceeded('Python dependency-byte budget exceeded')
        seen.add(path)
        fingerprint.append((str(path), hashlib.sha256(data).hexdigest()))
        pending.extend(target for target, _ in local_imports(path, root).values())
    return tuple(sorted(seen)), tuple(sorted(fingerprint))


def php_dependency_scope(entry, root, max_files=None, max_bytes=None):
    """Resolve literal includes and conventional project class/model references.

    No PHP is executed. Dependencies are constrained to the selected project;
    content hashes invalidate cached results when a helper changes.
    Discovery reads one file at a time; optional caller budgets remain explicit.
    """
    import re
    from .adapters.tokenized import _lex
    entry, root = Path(entry).resolve(), Path(root).resolve()
    if not root.is_dir() or root not in entry.parents:
        raise AnalysisBudgetExceeded('PHP dependency scope requires the absolute source project root')
    pending, seen, fingerprint, total = [entry], set(), [], 0
    # Conventional framework directories are bounded; avoid walking vendor trees per source file.
    directories = [root, entry.parent, root/'application/models', root/'application/libraries', root/'app/Models', root/'app/Services', root/'src', root/'lib', root/'includes']
    psr4 = {}
    composer = root/'composer.json'
    if composer.is_file() and composer.stat().st_size <= 1024*1024:
        import json
        try:
            mappings = json.loads(read_source_text(composer)).get('autoload',{}).get('psr-4',{})
            psr4 = mappings if isinstance(mappings,dict) else {}
            for values in mappings.values():
                for value in values if isinstance(values,list) else [values]:
                    if isinstance(value,str):directories.append(root/value)
        except (ValueError,TypeError,AttributeError):
            pass
    checked_candidates = set()
    while pending:
        path = pending.pop()
        if path in seen or not allows_file(path):continue
        if max_files is not None and len(seen)>=max_files:raise AnalysisBudgetExceeded('PHP dependency-file budget exceeded')
        if source_stat(path).st_size>4*1024*1024:raise AnalysisBudgetExceeded('source-file byte budget exceeded')
        data=read_source_bytes(path);total+=len(data)
        if max_bytes is not None and total>max_bytes:raise AnalysisBudgetExceeded('PHP dependency-byte budget exceeded')
        seen.add(path);fingerprint.append((str(path),hashlib.sha256(data).hexdigest()))
        try:tokens=_lex(data.decode('utf-8'),php=True)
        except UnicodeError:continue
        candidates=[]
        for index,token in enumerate(tokens):
            if token.kind=='identifier' and token.text.lower() in {'include','include_once','require','require_once'}:
                expression=[]
                for item in tokens[index+1:index+30]:
                    if item.text==';':break
                    expression.append(item)
                value='';valid=True
                for item in expression:
                    if item.kind=='string' and not (item.quote=='"' and '$' in item.text):value+=item.text
                    elif item.text=='__DIR__':value+=str(path.parent)
                    elif item.text in {'.','(',')'}:continue
                    else:valid=False;break
                if valid and value:candidates.extend([path.parent/value,root/value])
            if token.kind=='identifier' and token.text.lower() in {'new','extends','use'} and index+1<len(tokens):
                parts=[]
                for item in tokens[index+1:index+20]:
                    if item.kind=='identifier' or item.text=='\\':parts.append(item.text)
                    else:break
                name=''.join(parts).lstrip('\\').replace('\\','/')
                for prefix, locations in psr4.items():
                    prefix = prefix.replace('\\','/')
                    if name.startswith(prefix):
                        for location in locations if isinstance(locations,list) else [locations]:
                            if isinstance(location,str):candidates.append(root/location/(name[len(prefix):]+'.php'))
                for directory in directories:
                    candidates.extend([directory/(name+'.php'), directory/(name.rsplit('/',1)[-1]+'.php')])
            if token.text=='->' and index+2<len(tokens) and tokens[index+2].text=='->':
                name=tokens[index+1].text
                for directory in directories:
                    for variant in {name,name[:1].upper()+name[1:]}:candidates.append(directory/(variant+'.php'))
            if token.text.lower() in {'model','library','helper'} and index+2<len(tokens) and tokens[index+1].text=='(' and tokens[index+2].kind=='string':
                name=tokens[index+2].text
                for directory in directories:candidates.extend([directory/(name+'.php'),directory/(name[:1].upper()+name[1:]+'.php')])
        # Framework calls repeat the same model/property names many times.
        # Probe each candidate only once per closure, including missing files.
        for candidate in dict.fromkeys(candidates):
            if candidate in checked_candidates:
                continue
            checked_candidates.add(candidate)
            if candidate.suffix.lower() != '.php' or not candidate.is_file():
                continue
            candidate=candidate.resolve()
            if root in candidate.parents and candidate.is_file() and candidate.suffix.lower()=='.php' and candidate not in seen:pending.append(candidate)
    return tuple(sorted(seen)),tuple(sorted(fingerprint))


def _portable_source_context(entry, language):
    path = Path(entry)
    if language not in {'java', 'kotlin'}:
        return 'all'
    if language == 'kotlin' and path.name.endswith('.gradle.kts'):
        return 'gradle-build'
    parts = path.parts
    for index, part in enumerate(parts[:-1]):
        if part == 'src':
            source_set = parts[index+1]
            return 'tests' if source_set.startswith(('test', 'androidTest')) else 'production'
    return 'all'


def portable_dependency_scope(entry, root, language, max_files=2048, max_bytes=64 * 1024 * 1024):
    """Freeze a bounded dependency inventory within one immutable source scan.

    Outside a scan snapshot, inventories remain fresh for helper invalidation.
    Failed inventories remain explicit and are reused instead of rewalking a
    large mounted repository for every property and source file.
    """
    from utils.source_cache import current_snapshot
    context = _portable_source_context(entry, language)
    snapshot = current_snapshot()
    if snapshot is None or language == 'javascript' or snapshot.key(root) is None:
        return _portable_dependency_scope(entry, root, language, max_files, max_bytes, context)
    root_path = Path(root).resolve()
    entry_path = Path(entry).resolve()
    try:
        entry_path.relative_to(root_path)
    except ValueError:
        raise AnalysisBudgetExceeded('entry is outside the project root')
    def inventory():
        try:
            files, fingerprint = _portable_dependency_scope(entry, root, language, max_files, max_bytes, context)
            return dict(files=list(map(str, files)), fingerprint=fingerprint)
        except (AnalysisBudgetExceeded, OSError) as exc:
            return dict(error=str(exc))
    result = snapshot.memo(('portable-source-scope', str(root_path), language, context, max_files, max_bytes), inventory)
    if 'error' in result:
        raise AnalysisBudgetExceeded(result['error'])
    if str(entry_path) not in result['files']:
        raise AnalysisBudgetExceeded('entry file excluded from bounded source inventory')
    return tuple(map(Path, result['files'])), tuple(map(tuple, result['fingerprint']))


def _portable_dependency_scope(entry, root, language, max_files=2048, max_bytes=64 * 1024 * 1024, source_context='all'):
    """Bounded source index; visibility is checked again for every call edge.

    Package/class-based languages require a project index, not just literal
    imports. Fingerprint every indexed file so added, removed or edited callees
    invalidate cached verdicts. Never traverse dependency/build trees or symlinks.
    """
    if language == 'javascript':
        return javascript_dependency_scope(entry, root, max_files=max_files, max_bytes=max_bytes)
    import os
    from .portable_profiles import EXTENSIONS
    entry, root = Path(entry).resolve(), Path(root).resolve()
    try:
        entry.relative_to(root)
    except ValueError:
        raise AnalysisBudgetExceeded('entry is outside the project root')
    suffixes = EXTENSIONS[language]
    ignored = {'.git', '.hg', '.svn', 'node_modules', 'vendor', '.venv', 'venv',
               '__pycache__', 'dist', 'build', 'target', 'bin', 'obj', 'Pods', '.dart_tool'}
    files, fingerprint, total = [], [], 0
    visited = 0
    for directory, children, names in walk_source(str(root), followlinks=False):
        children[:] = sorted(name for name in children if name not in ignored and not (Path(directory)/name).is_symlink()
                             and not (source_context == 'production' and Path(directory).name == 'src' and name.startswith(('test', 'androidTest'))))
        visited += 1
        if visited > 20000:
            raise AnalysisBudgetExceeded('project directory budget exceeded')
        for name in sorted(names):
            path = Path(directory)/name
            if path.suffix.lower() not in suffixes or path.is_symlink():
                continue
            if source_context == 'gradle-build' and not (path.name.endswith('.gradle.kts') or 'buildSrc' in path.parts):
                continue
            if source_context == 'production' and path.name.endswith('.gradle.kts'):
                continue
            if source_stat(path).st_size > 4 * 1024 * 1024:
                raise AnalysisBudgetExceeded('source-file byte budget exceeded')
            data = read_source_bytes(path); total += len(data)
            if len(files) >= max_files or total > max_bytes:
                raise AnalysisBudgetExceeded('project flow source scope budget exceeded')
            files.append(path)
            fingerprint.append((str(path), hashlib.sha256(data).hexdigest()))
    if entry not in files:
        raise AnalysisBudgetExceeded('entry file excluded from bounded source inventory')
    return tuple(files), tuple(fingerprint)


def javascript_dependency_scope(entry, root, max_files=2048, max_bytes=64 * 1024 * 1024):
    """Follow literal local JS/TS imports instead of merging unrelated scripts.

    Each entry is still reviewed independently by the scanner. External packages
    and dynamic calls remain unresolved in the flow model, not assumed safe.
    """
    from .adapters.tokenized import _lex
    from .portable_profiles import EXTENSIONS
    entry, root = Path(entry).resolve(), Path(root).resolve()
    if root not in entry.parents:
        raise AnalysisBudgetExceeded('entry is outside the project root')
    pending, seen, fingerprint, total = [entry], set(), [], 0
    while pending:
        path = pending.pop()
        if path in seen or not allows_file(path):
            continue
        if max_files is not None and len(seen) >= max_files:
            raise AnalysisBudgetExceeded('JavaScript dependency-file budget exceeded')
        if source_stat(path).st_size > 4 * 1024 * 1024:
            raise AnalysisBudgetExceeded('source-file byte budget exceeded')
        data = read_source_bytes(path)
        total += len(data)
        if max_bytes is not None and total > max_bytes:
            raise AnalysisBudgetExceeded('JavaScript dependency-byte budget exceeded')
        seen.add(path)
        fingerprint.append((str(path), hashlib.sha256(data).hexdigest()))
        tokens = _lex(data.decode('utf-8'), javascript=True)
        for index, token in enumerate(tokens):
            if token.kind != 'identifier' or token.text not in {'import', 'from', 'require'}:
                continue
            following = tokens[index + 1:index + 3]
            literal = following[0] if following else None
            if literal and literal.text == '(' and len(following) > 1:
                literal = following[1]
            if not literal or literal.kind != 'string' or not literal.text.startswith('.'):
                continue
            base = (path.parent / literal.text).resolve()
            candidates = [base]
            if not base.suffix:
                candidates += [Path(str(base) + suffix) for suffix in EXTENSIONS['javascript']]
                candidates += [base / ('index' + suffix) for suffix in EXTENSIONS['javascript']]
            for candidate in candidates:
                if root in candidate.parents and candidate.is_file() and candidate.suffix.lower() in EXTENSIONS['javascript']:
                    pending.append(candidate)
    return tuple(sorted(seen)), tuple(sorted(fingerprint))
