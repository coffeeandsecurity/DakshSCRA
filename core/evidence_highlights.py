"""Record bounded source highlights using the same Python regex as the scanner."""
import re
import html

COLORS = {'red': '#f85149', 'green': '#3fb950', 'blue': '#58a6ff', 'cyan': '#39c5cf',
          'yellow': '#d29922', 'orange': '#e3842a', 'purple': '#a371f7', 'magenta': '#db61a2'}


def highlighted_html(code, spans):
    """Escape source text before adding marks from validated recorded offsets."""
    code = str(code or '')
    spans = [s for s in spans[:256] if isinstance(s, dict) and type(s.get('start')) is int and
             type(s.get('end')) is int and 0 <= s['start'] < s['end'] <= len(code)] if isinstance(spans, list) else []
    cuts = sorted({0, len(code), *(s['start'] for s in spans), *(s['end'] for s in spans)})
    parts = []
    for start, end in zip(cuts, cuts[1:]):
        text = html.escape(code[start:end])
        span = next((s for s in spans if s['start'] <= start and s['end'] >= end), None)
        if span:
            color = str(span.get('color', 'red'))
            value = COLORS.get(color, color if re.fullmatch(r'#[0-9a-fA-F]{6}', color) else COLORS['red'])
            parts.append(f'<mark class="pattern-source-mark" style="--pattern-mark-color:{value}">{text}</mark>')
        else:
            parts.append(text)
    return ''.join(parts)


def source_highlights(code, pattern, config):
    if not config.get('highlight_enabled', True):
        return []
    marks = config.get('marks') or [{'color': config.get('highlight_color', 'red'),
                                   'spec': config.get('highlight_target', 'match')}]
    spans = []
    for mark in marks:
        spec, color = mark.get('spec', 'match'), mark.get('color', 'red')
        if spec == 'line':
            matches = [(0, len(code))]
        else:
            regex = pattern
            groups = None
            if spec.startswith('pattern:'):
                try:
                    regex = re.compile(spec[len('pattern:'):])
                except re.error:
                    continue
            elif spec == 'pattern':
                try:
                    regex = re.compile(config.get('highlight_pattern', '')) if config.get('highlight_pattern') else None
                except re.error:
                    continue
            elif spec == 'groups' or spec.startswith(('group:', 'groups:')):
                selected = spec.partition(':')[2] or config.get('highlight_groups', '')
                groups = [g.strip() for g in str(selected).split(',') if g.strip()]
                if not groups and regex is not None:
                    groups = list(regex.groupindex) or list(range(1, regex.groups + 1))
            elif spec != 'match':
                continue
            if regex is None:
                continue
            matches = []
            for match in regex.finditer(code):
                for group in groups if groups is not None else [0]:
                    try:
                        matches.append(match.span(int(group) if str(group).isdigit() else group))
                    except (IndexError, ValueError):
                        continue
                if len(matches) >= 256:
                    break
        for start, end in matches:
            if 0 <= start < end <= len(code):
                span = {'start': start, 'end': end, 'color': color}
                if span not in spans:
                    spans.append(span)
            if len(spans) >= 256:
                return spans
    return spans
