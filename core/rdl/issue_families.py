"""Issue families and located occurrences, separate from immutable rule evidence."""
import hashlib
import json
import re

from core.issue_titles import issue_title


def family_title(finding):
    return issue_title(finding.get('title') or 'Untitled review')


def family_key(finding):
    return family_title(finding).casefold()


def _retained_source(finding):
    lines = {}
    for step in [*(finding.get('evidence') or []), *((finding.get('trace') or {}).get('steps') or [])]:
        for line in step.get('snippet') or []:
            number = line.get('line')
            if not isinstance(number,int): continue
            value = line.get('text','')
            if number in lines and lines[number] != value: return None
            lines[number] = value
    if not lines: return None
    first, last = min(lines), max(lines)
    return '\n'.join(lines.get(n,'') for n in range(first,last+1)), first


def _configuration_anchor(finding, text, first=1):
    title = family_key(finding)
    loc = finding.get('location') or {}
    path = str(loc.get('path') or '').lower()
    if title not in {'exported component access review','cross-application overlay capability','ats http exception review'} and not path.endswith(('.xml','.plist','.entitlements','.xib','.storyboard')):
        return None
    line, column = loc.get('line'), loc.get('column') or 1
    if not isinstance(line,int): return None
    rows = text.splitlines(keepends=True)
    relative = line-first
    if relative < 0 or relative >= len(rows): return None
    offset = sum(map(len,rows[:relative]))+column-1
    def position(index):
        return [first+text.count('\n',0,index),index-text.rfind('\n',0,index)]
    # Mask comments at their offsets; comments cannot supply an owner.
    code = re.sub(r'<!--[\s\S]*?-->',lambda m: re.sub(r'[^\n]',' ',m[0]),text)
    if title == 'exported component access review':
        for tag in re.finditer(r'<(?:activity(?:-alias)?|service|receiver|provider)\b[^>]*>',code):
            name = re.search(r'\b[\w.-]+:name\s*=\s*["\x27]([^"\x27]+)["\x27]',tag[0])
            if not name: continue
            closing = re.search(r'</(?:activity(?:-alias)?|service|receiver|provider)\s*>',code[tag.end():])
            end = tag.end() if tag[0].rstrip().endswith('/>') else tag.end()+closing.end() if closing else len(code)
            if tag.start() <= offset < end and '<evidence-gap/>' not in code[tag.start():offset]:
                return ['component',name[1],*position(tag.start()+name.start())]
        # A legacy excerpt may start in a multi-line opening tag. Only use a
        # preceding class-like name without intervening closing/component tags.
        names = list(re.finditer(r'\b[\w.-]+:name\s*=\s*["\x27]((?:\.|[A-Za-z_]\w*\.)[^"\x27]+)["\x27]',code[:offset]))
        if names:
            name = names[-1]
            between = code[name.end():offset]
            if '<evidence-gap/>' not in between and not name[1].startswith(('android.intent.','android.permission.')) and not re.search(r'/\s*>|</|<(?:activity|service|receiver|provider)\b',between):
                return ['component',name[1],*position(name.start())]
    if title == 'cross-application overlay capability':
        for tag in re.finditer(r'<uses-permission(?:-sdk-23)?\b[^>]*>',code):
            if tag.start() <= offset < tag.end() and 'android.permission.SYSTEM_ALERT_WINDOW' in tag[0]:
                return ['permission',*position(tag.start())]
    if title == 'ats http exception review':
        for key in re.finditer(r'<key>\s*NSExceptionAllowsInsecureHTTPLoads\s*</key>',code):
            if key.start() <= offset < key.end():
                return ['plist-key',*position(key.start())]
    path = str(loc.get('path') or '').lower()
    if path.endswith(('.xml','.plist','.entitlements','.xib','.storyboard')):
        # Equivalent predicates can select a tag prefix, attribute or scalar.
        # Locate the same XML node rather than conflating every item on a line.
        if path.endswith(('.plist','.entitlements')):
            for pair in re.finditer(r'<key>[^<]*</key>\s*<(?:true|false|string|integer|real|data|date)\b[^>]*>(?:[^<]*</(?:string|integer|real|data|date)>)?',code):
                if pair.start() <= offset < pair.end():
                    return ['plist-property',*position(pair.start())]
        for tag in re.finditer(r'<[A-Za-z_][\w:.-]*\b[^>]*>',code):
            if tag.start() <= offset < tag.end() and '<evidence-gap/>' not in tag[0]:
                attrs = [a for a in re.finditer(r'''([\w:.-]+)\s*=\s*(?:"[^"]*"|'[^']*')''',tag[0]) if not a[1].startswith('xmlns')]
                selected = next((a[1] for a in attrs if tag.start()+a.start() <= offset < tag.start()+a.end()), None)
                if selected is None and len(attrs) == 1: selected = attrs[0][1]
                return ['xml-element',*position(tag.start()),selected]
    return None


def occurrence_identity(record, finding, text=None):
    loc = finding.get('location') or {}
    path = str(loc.get('path') or finding.get('path') or (record.get('context') or {}).get('file_path') or '').replace('\\','/')
    path_only = bool(finding.get('path_only'))
    steps = (finding.get('trace') or {}).get('steps') or finding.get('evidence') or []
    flows = [s for s in steps if s.get('matched') is not False and s.get('predicate') in {'SOURCE','PROPAGATION','SINK'}]
    if flows:
        # Different sources, sinks and handoffs remain different paths even at
        # the same destination. Narrative wording and rule IDs are not identity.
        anchor = ['flow', [[s.get('predicate'),s.get('location'),s.get('symbol'),s.get('transition')] for s in flows]]
    elif path_only:
        anchor = ['path']
    else:
        anchor = finding.get('occurrence_anchor')
        if anchor is None:
            source = (text,1) if text is not None else _retained_source(finding)
            anchor = _configuration_anchor(finding,*source) if source else None
        anchor = anchor or ['location',loc.get('line'),loc.get('column')]
        if not loc.get('line') and not finding.get('occurrence_anchor'):
            # No located evidence: do not collapse unrelated opaque rules.
            anchor = ['unlocated',record.get('v2_rule_id') or record.get('v2_rule'),finding.get('evidence')]
    return json.dumps([family_key(finding),path,anchor],sort_keys=True,separators=(',',':'))


def decorate(record, finding, text=None):
    finding['issue_family'] = family_key(finding)
    if text is not None:
        anchor = _configuration_anchor(finding,text)
        if anchor: finding['occurrence_anchor'] = anchor
    finding['occurrence_id'] = hashlib.sha256(occurrence_identity(record,finding,text).encode()).hexdigest()
    return finding
