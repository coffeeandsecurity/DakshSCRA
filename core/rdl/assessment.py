"""Conservative classifications derived exclusively from recorded RDL results."""

CATEGORIES = ('confirmed', 'suppressed', 'manual', 'mitigated')


def manual_review_direction(record):
    """Require located security evidence, not merely an analyzer failure."""
    evidence = list(record.get('v2_evidence') or [])
    for finding in record.get('v2_findings') or []:
        if not finding.get('path_only'):
            evidence.extend(finding.get('evidence') or (finding.get('trace') or {}).get('steps') or [])
    located = [step for step in evidence if step.get('matched') is True
               and (step.get('location') or {}).get('path')
               and (step.get('location') or {}).get('line')]
    sources = [step for step in located if step.get('predicate') == 'SOURCE'
               or (step.get('predicate', '').startswith('LET ') and step.get('explanation', '').startswith('input.'))]
    sinks = [step for step in located if step.get('predicate') == 'SINK'
             or (step.get('predicate', '').startswith('LET ') and step.get('explanation', '') in {'command.execution', 'sql.execution', 'network.outbound-request', 'filesystem.access', 'deserialization.object-construction', 'output.html', 'redirect.destination', 'model.mass-assignment', 'xml.external-entities', 'variable.extraction', 'regex.execution', 'code.inclusion', 'dynamic.evaluation'})]
    violations = [step for step in located if step.get('predicate') == 'STATE VIOLATION']
    flow_recorded = any(step.get('predicate') == 'FLOWS TO' and step.get('matched') is True for step in evidence)
    if sources and sinks and flow_recorded:
        source, sink = sources[0], sinks[0]
        def describe(step):
            loc = step['location']
            return '{} at {}:{}'.format(step.get('symbol') or step.get('explanation') or step['predicate'], loc['path'], loc['line'])
        return dict(observed='Input {} and sensitive operation {} were identified.'.format(describe(source), describe(sink)),
                    uncertainty='A source-to-operation flow was recorded, but the analysis did not establish its runtime reachability or whether an effective security control protects it.',
                    investigate='Verify the recorded flow into the operation’s arguments. Verify attacker control, reachable callers and branches, and validation or authorization on that specific path. Confirm an unsafe path or dismiss the lead with the protecting control.',
                    evidence=[source, sink])
    if violations:
        step = violations[0]; loc = step['location']
        return dict(observed='A security state violation was recorded at {}:{}: {}.'.format(loc['path'], loc['line'], step.get('explanation') or step.get('symbol') or 'invalid state transition'),
                    uncertainty='Reachability and the relevant runtime security controls remain unresolved.',
                    investigate='Inspect the recorded state transition and its callers. Check whether an attacker can reach it and whether authorization or state validation prevents the violation.', evidence=[step])
    return None


def classify_record(record):
    outcome = record.get('v2_outcome')
    findings = record.get('v2_findings') or []
    if findings and all(finding.get('path_only') is True for finding in findings):
        # Filename observations belong to Areas of Interest. A path match
        # remains recorded RDL coverage, but cannot establish a code finding.
        return 'not_applicable'
    review = record.get('security_review') or {}
    # Human review can suppress a match. Engine-confirmed findings mean that
    # the RDL property matched, not that exploitation was demonstrated.
    if isinstance(review, dict) and review.get('reviewer') and review.get('reason'):
        status = review.get('status')
        if status == 'false_positive':
            return 'suppressed'
        if status == 'confirmed' and outcome == 'MATCH':
            return 'confirmed'
    if outcome == 'MATCH':
        return 'confirmed'
    if outcome in {'INDETERMINATE', 'RULE_ERROR', 'SHADOW_ERROR'} or record.get('v2_errors') or record.get('v2_unavailable_capabilities'):
        return 'manual' if manual_review_direction(record) else 'coverage_limit'
    if outcome == 'NO_MATCH':
        evidence = record.get('v2_evidence') or []
        if any(step.get('matched') is True and step.get('predicate') in {'SANITIZED', 'MITIGATION', 'SAFE STATE'} for step in evidence):
            return 'mitigated'
        flow_recorded = any(step.get('predicate') == 'FLOWS TO' and step.get('matched') is True for step in evidence)
        if flow_recorded and any(step.get('matched') is True and
                                 str(step.get('predicate', '')).lower().startswith(('sanitizer.', 'policy.'))
                                 for step in evidence):
            return 'mitigated'
    return 'not_applicable'


def combined_category(categories):
    """Do not hide a review lead when duplicate evaluations disagree."""
    return next((kind for kind in ('manual', 'confirmed', 'suppressed', 'mitigated', 'coverage_limit') if kind in categories), 'not_applicable')
