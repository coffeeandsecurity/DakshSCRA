"""Lossless presentation of ordered evidence with shared source excerpts."""
from copy import deepcopy

TRACE_ROLES = {'SOURCE', 'PROPAGATION', 'SINK', 'EXISTS', 'STATE TRANSITION', 'STATE VIOLATION', 'TEXT_MATCHES', 'TEXT_MISSING', 'FILE_NAME_IS', 'FILE_PATH_GLOB', 'PROJECT_OBSERVATION'}


SINK_OPERATIONS = {
    'CWE-78': 'a shell command',
    'CWE-89': 'SQL query text',
    'CWE-918': 'the destination of a server-side request',
    'CWE-22': 'a filesystem path',
    'CWE-502': 'data to deserialize into objects',
}


def describe_step(item, previous=None, cwe=''):
    role = item.get('predicate', '')
    symbol = item.get('symbol') or item.get('explanation') or 'the recorded value'
    transition = item.get('transition', '')
    prior = (previous or {}).get('symbol') or (previous or {}).get('explanation') or 'the previous value'
    actions = {
        'assignment': 'The value from {prior} is assigned to {symbol}. Input from the source is carried into this variable.',
        'reference': 'The code reads {symbol}, carrying the input forward from {prior}.',
        'argument': 'The value from {prior} is passed to {symbol} as a function argument.',
        'argument-parameter': 'The called function receives the value from {prior} in parameter {symbol}. Follow the next steps inside this function.',
        'return': 'The function returns the value from {prior} through {symbol}, carrying the input back to its caller.',
        'return-call': 'The call to {symbol} receives the returned value from {prior}. The trace continues in the calling function.',
        'receiver': 'The operation {symbol} uses {prior} and produces a result that still depends on the input.',
    }
    if role in {'TEXT_MATCHES', 'TEXT_MISSING', 'FILE_NAME_IS', 'FILE_PATH_GLOB', 'PROJECT_OBSERVATION'}:
        return 'Text/path predicate evidence: ' + symbol + '. This does not establish data flow or exploitability.'
    if role == 'SOURCE':
        return 'Input is received through {0} and treated as untrusted. The following steps show where this value goes.'.format(symbol)
    if role == 'SINK':
        operation = SINK_OPERATIONS.get(cwe, 'input to a security-sensitive operation')
        return 'The value from {0} reaches {1}, where it is used as {2}.'.format(prior, symbol, operation)
    if transition in actions:
        return actions[transition].format(prior=prior, symbol=symbol)
    if role == 'PROPAGATION':
        if symbol == prior:
            return 'The code uses {0} again, carrying the input toward the sink. The recorded evidence does not specify a separate assignment or function handoff here.'.format(symbol)
        return 'The input is carried from {0} to {1}. The recorded evidence does not specify the exact transfer operation.'.format(prior, symbol)
    if role == 'EXISTS':
        return 'The code contains {0} at this location. Review the highlighted expression and its surrounding configuration.'.format(symbol)
    return item.get('explanation', '')


def build_trace(items, cwe=''):
    """Keep every step while merging overlapping excerpts only within a file."""
    steps, windows = [], []
    for item in items:
        if item.get('predicate') not in TRACE_ROLES:
            continue
        step = {key: deepcopy(value) for key, value in item.items() if key != 'snippet'}
        step['number'] = len(steps) + 1
        step['description'] = describe_step(item, steps[-1] if steps else None, cwe)
        steps.append(step)
        location = item.get('location') or {}
        lines = item.get('snippet') or []
        if location.get('path') and lines:
            windows.append(dict(path=location['path'], start=min(x['line'] for x in lines),
                                end=max(x['line'] for x in lines), lines=deepcopy(lines), steps=[step['number']]))
    merged = []
    for window in sorted(windows, key=lambda x: (x['path'], x['start'])):
        if merged and merged[-1]['path'] == window['path'] and window['start'] <= merged[-1]['end'] + 1:
            block = merged[-1]
            block['end'] = max(block['end'], window['end'])
            block['lines'].extend(window['lines'])
            block['steps'].extend(window['steps'])
        else:
            merged.append(window)
    blocks = []
    for index, block in enumerate(sorted(merged, key=lambda x: min(x['steps'])), 1):
        block['id'] = 'code-{}'.format(index)
        unique = {}
        for line in block['lines']:
            existing = unique.setdefault(line['line'], line)
            existing['highlight'] = bool(existing.get('highlight') or line.get('highlight'))
        for line in unique.values():
            line['steps'] = [number for number in block['steps'] if (steps[number - 1].get('location') or {}).get('line') == line['line']]
        block['lines'] = sorted(unique.values(), key=lambda x: x['line'])
        for number in block['steps']:
            steps[number - 1]['code_block'] = block['id']
        blocks.append(block)
    flow = any(step['predicate'] == 'SOURCE' for step in steps) and any(step['predicate'] == 'SINK' for step in steps)
    controls = {
        'SANITIZER.COMMAND-APPROVED': 'command-input validation',
        'SANITIZER.SQL-PARAMETERIZATION': 'SQL parameter binding',
        'SANITIZER.PATH-CONTAINMENT': 'a path-containment check',
        'SANITIZER.CONTEXTUAL-OUTPUT-ENCODING': 'context-appropriate output encoding',
        'POLICY.DESTINATION-ALLOWLIST': 'a destination allowlist',
        'POLICY.TYPE-ALLOWLIST': 'a deserialization type allowlist',
    }
    missing = list(dict.fromkeys(controls[item['predicate'].upper()] for item in items
        if item.get('predicate', '').upper() in controls and item.get('matched') is False))
    protection_note = ''
    if flow:
        protection_note = ('The rule did not identify ' + ', '.join(missing) + ' on this path. Check controls outside the traced code before confirming the issue.'
                           if missing else 'The recorded evidence does not establish whether a suitable protection is present. Review validation and controls before confirming the issue.')
    return dict(steps=steps, blocks=blocks,
                review_note=('This trace follows source code; it does not show an observed execution. Confirm that the source can receive external input.' if flow else ''),
                protection_note=protection_note, file_count=len({b['path'] for b in blocks}),
                original_excerpt_count=len(windows), shared_excerpt_count=len(blocks))
