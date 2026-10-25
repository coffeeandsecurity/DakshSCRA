"""Presentation-only audience selection; retained scan evidence stays complete."""
AUDIENCES = ('developer', 'code_review', 'both')
LABELS = {'developer': 'Developer Mode', 'code_review': 'Code Review Mode', 'both': 'Both'}
_audience = 'both'


def normalize_audience(value=None):
    value = value or 'both'
    if value not in AUDIENCES:
        raise ValueError('Report audience must be developer, code_review, or both')
    return value


def configure_audience(value):
    global _audience
    _audience = normalize_audience(value)


def current_audience():
    return _audience


def filter_guidance(value, audience='both'):
    """Return a decoded presentation copy without the unselected guidance."""
    audience = normalize_audience(audience)
    omitted = ({'reviewer_note', 'reviewer', 'review_steps', 'rev_note'} if audience == 'developer'
               else {'developer_note', 'developer', 'remediation', 'recommendation', 'recommendations', 'dev_note'}
               if audience == 'code_review' else set())
    if isinstance(value, dict):
        review = ('reviewer_note', 'reviewer', 'rev_note', 'review_steps')
        developer = ('developer_note', 'remediation', 'recommendation', 'developer', 'dev_note', 'recommendations')
        notes = {key: filter_guidance(value[key], audience) for key in (*review, *developer)
                 if key in value and key not in omitted}
        result = {}
        placed = False
        for key, child in value.items():
            if key in omitted or key in (*review, *developer):
                continue
            result[key] = filter_guidance(child, audience)
            if key in {'security_impact', 'impact', 'attack_desc'}:
                result.update(notes)
                placed = True
        if not placed:
            result.update(notes)
        return result
    if isinstance(value, list):
        return [filter_guidance(child, audience) for child in value]
    return value
