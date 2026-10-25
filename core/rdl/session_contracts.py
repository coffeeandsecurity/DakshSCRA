"""Bounded Redux persistence and logout-state contracts from local source."""
import re
from pathlib import Path

from core.mobile_model import block_end, enclosing_blocks
from .portable_resolver import imported_target


def _object(code, name):
    match = re.search(r'\b(?:const|let|var)\s+'+re.escape(name)+r'\s*=\s*\{', code)
    if not match:
        return None
    end = block_end(code, match.end()-1)
    return (match.end()-1, end) if end else None


def _action_key(origin, text, name, paths):
    bound = imported_target(origin, text, name, paths, 'javascript')
    return (next(iter(bound[0])), bound[1]) if bound is not None and len(bound[0]) == 1 else None


def _models(project):
    cached = getattr(project, '_logout_models', None)
    if cached is not None:
        return cached
    models, unknown = [], []
    paths = set(project.files)
    for path, (text, comments, code) in project.files.items():
        if path.suffix not in {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs'}:
            continue
        for persisted in re.finditer(r'\bpersistReducer\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)', code):
            config, root_name = persisted.groups()
            span = _object(code, config)
            root = re.search(r'\b'+re.escape(root_name)+r'\s*=\s*combineReducers\s*\(\s*\{', code)
            if not span or not root:
                unknown.append('Persistence configuration or root reducer binding is unresolved in '+project.rel(path))
                continue
            end = block_end(code, root.end()-1)
            if not end:
                continue
            config_text = comments[span[0]:span[1]]
            if not re.search(r'\bstorage\s*:\s*AsyncStorage\b', config_text):
                continue
            if not re.search(r'\bimport\s+AsyncStorage\s+from\s*["\']@react-native(?:-community|\-async-storage)/async-storage["\']', comments):
                continue
            if re.search(r'\b(?:transforms|migrate|serialize|deserialize)\s*:', config_text):
                unknown.append('Persistence transforms or migration need field-level resolution in '+project.rel(path))
                continue
            combined = code[root.end():end-1]
            for member in combined.split(','):
                parts = member.strip().split(':')
                state_key, reducer_name = parts[0].strip(), parts[-1].strip()
                if not re.fullmatch(r'\w+', reducer_name):
                    continue
                bound = imported_target(path, comments, reducer_name, paths, 'javascript')
                if bound is None or len(bound[0]) != 1:
                    continue
                reducer_path = next(iter(bound[0]))
                if reducer_path not in project.files:
                    continue
                for option in ('blacklist', 'whitelist'):
                    selected = re.search(r'\b'+option+r'\s*:\s*\[([^]]*)\]', config_text)
                    if selected:
                        names = re.findall(r'["\']([^"\']+)["\']', selected.group(1))
                        if (option == 'blacklist' and state_key in names) or (option == 'whitelist' and state_key not in names):
                            break
                else:
                    reducer_text = project.files[reducer_path][1]
                    reducer_code = project.files[reducer_path][2]
                    exported = bound[1]
                    start = re.search(r'\b(?:const|let|var)\s+'+re.escape(exported)+r'\s*=\s*\([^)]*\)\s*=>\s*\{', reducer_code)
                    stop = block_end(reducer_code, start.end()-1) if start else None
                    if not stop:
                        continue
                    body = reducer_code[start.end():stop-1]
                    observed = re.findall(r'\bcase\s+([\w.]+)\s*:\s*return\s*\{\s*\.\.\.state\s*,\s*(\w+)\s*:\s*action\.payload\s*\}', body)
                    sensitive = {field for _, field in observed if re.search(r'token|authUserDetails|userDetails|selected_profile|patient|personal', field, re.I)}
                    updates = {_action_key(reducer_path, reducer_text, action, paths): field for action, field in observed}
                    if None in updates:
                        if any('token' in field.lower() for field in sensitive):
                            unknown.append('Reducer action constants require explicit source binding in '+project.rel(reducer_path))
                        continue
                    if any('token' in field.lower() for field in sensitive) and len(sensitive) > 1:
                        models.append(dict(store=project.rel(path), reducer=project.rel(reducer_path), state_key=state_key,
                                           updates=updates, sensitive=sorted(sensitive), reducer_path=reducer_path))
    project._logout_models = (models, unknown)
    return project._logout_models


def logout_contracts(project, path):
    path = Path(path).resolve()
    if path not in project.files:
        return [], []
    text, comments, code = project.files[path]
    logouts = list(re.finditer(r'\b(?:SignOut|signOut|logout)\s*\(', code))
    if not logouts:
        return [], []
    models, unknown = _models(project)
    contracts = []
    for logout in logouts:
        blocks = enclosing_blocks(code, logout.start())
        callback = next((start for start in reversed(blocks) if re.search(r'=>\s*$|\bfunction\s*\([^)]*\)\s*$', code[max(0,start-150):start])), None)
        end = block_end(code, callback) if callback is not None else None
        if end is None:
            continue
        body = comments[callback:end]
        if re.search(r'\b(?:purge|resetRootState|resetStore)\s*\(', code[callback:end]):
            unknown.append('Logout delegates persistence cleanup; resolve its completion and memory-state reset in '+project.rel(path))
            continue
        for model in models:
            cleared = set()
            for call in re.finditer(r'\bdispatch\s*\(\s*(\w+)\s*\(\s*(?:["\']["\']|null|undefined|\{\s*\}|\[\s*\])\s*\)\s*\)', body):
                if not code[callback+call.start():callback+call.start()+8].startswith('dispatch'):
                    continue
                bound = imported_target(path, comments, call.group(1), set(project.files), 'javascript')
                if bound is None or len(bound[0]) != 1:
                    continue
                action_path = next(iter(bound[0]))
                if action_path not in project.files or action_path.parent != model['reducer_path'].parent:
                    continue
                action_code = project.files[action_path][2]
                action = re.search(r'\b(?:const|let|var)\s+'+re.escape(bound[1])+r'\s*=\s*\w+\s*=>\s*dispatch\s*=>\s*\{', action_code)
                stop = block_end(action_code, action.end()-1) if action else None
                kind = re.search(r'\btype\s*:\s*([\w.]+)', action_code[action.end():stop]) if stop else None
                action_key = _action_key(action_path, project.files[action_path][1], kind.group(1), set(project.files)) if kind else None
                if action_key in model['updates']:
                    cleared.add(model['updates'][action_key])
                elif kind:
                    unknown.append('Logout action does not bind to the recorded reducer constants in '+project.rel(action_path))
            remaining = set(model['sensitive'])-cleared
            if any('token' in field.lower() for field in cleared) and remaining:
                contracts.append(dict(kind='logout_persistence_contract', source=project.loc(path,text,logout.start()),
                    store=model['store'], reducer=model['reducer'], state_key=model['state_key'],
                    cleared_fields=sorted(cleared), retained_fields=sorted(remaining), state='local_transition_retains_fields',
                    assumptions=['Imported action and reducer spread update preserve these fields during the recorded token-clear transition.',
                                 'Resolve delegated cleanup, account scoping, subsequent actions and backend session revocation; this is not proof of cross-account disclosure.']))
    return contracts, sorted(set(unknown))
