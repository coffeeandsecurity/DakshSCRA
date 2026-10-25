"""Presentation of saved suppression decisions; never change scanner verdicts."""
from pathlib import Path
import json
import sqlite3


def _read(path, default):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return default


def _path(value, root):
    value = str(value or '').replace('\\', '/').rstrip('/')
    root = str(root or '').replace('\\', '/').rstrip('/')
    if root and value.startswith(root + '/'):
        return value[len(root) + 1:]
    if root and value.startswith(root.rsplit('/', 1)[-1] + '/'):
        return value[len(root.rsplit('/', 1)[-1]) + 1:]
    return value


def explain_suppressions(items, runtime=None, target=None, active=False, records=None, xref=None):
    """Annotate copies using related, same-file semantic decisions only.

    Pattern predicates are not taint traces. An absence of semantic matches is
    not proof of protection. Original reasons, traces and statuses stay intact.
    """
    if not items:
        return []
    from core.rdl.review_views import flow_traits
    runtime = Path(runtime) if runtime else None
    if runtime:
        summary = _read(runtime / 'scan_summary.json', {})
        target = target or (summary.get('inputs_received') or {}).get('target_directory')
    unavailable = False
    if active:
        records, xref = [], {}
    else:
        if xref is None:
            xref = {}
            if runtime and (runtime / 'rdl_xref.json').is_file():
                try:
                    from core.rdl.xref import read_index
                    xref = read_index(runtime / 'rdl_xref.json') or {}
                except (OSError, ValueError, sqlite3.DatabaseError):
                    unavailable = True
        if records is None:
            records = []
            if runtime:
                from core.rdl.result_store import ResultStore
                try:
                    wanted = {_path(item.get('file'), target) for item in items}
                    records = [r for r in ResultStore(runtime / 'rdl_shadow_comparisons.jsonl').iter_records_readonly()
                               if r.get('comparison_kind') == 'semantic'
                               and _path((r.get('context') or {}).get('file_path'), target) in wanted
                               and r.get('v2_rule_id') == 'injection.sql']
                except (OSError, ValueError, sqlite3.DatabaseError):
                    unavailable = True
    grouped = {}
    for record in records or []:
        if record.get('comparison_kind') != 'semantic':
            continue
        path = _path((record.get('context') or {}).get('file_path'), target)
        grouped.setdefault(path, []).append(record)
    inventory = (xref or {}).get('input_inventory') or {}
    no_inputs = isinstance(inventory.get('records'), list) and not inventory['records']
    result = []
    for item in items:
        reason = str(item.get('suppression_reason') or '')
        engine = str(item.get('suppression_engine') or item.get('logic_engine') or '').lower()
        pattern = engine == 'pattern' or str(item.get('rdl_condition') or '').startswith('Pattern:')
        failed = reason.startswith('Expression did not pass:')
        sql = 'sql' in str(item.get('rule_title') or '').lower()
        family = 'injection.sql' if sql else None
        related = [r for r in grouped.get(_path(item.get('file'), target), [])
                   if family and r.get('v2_rule_id') == family]
        limits = []
        for record in related:
            for error in record.get('v2_errors') or []:
                text = error if isinstance(error, str) else json.dumps(error, ensure_ascii=True)
                if text not in limits:
                    limits.append(text)
        outcomes = sorted({str(r.get('v2_outcome')) for r in related if r.get('v2_outcome')})
        # A flow in the same file may belong to another operation. Never use it
        # to certify this suppressed line or infer a missing frontend.
        linked_flow = False
        for record in related:
            if record.get('v2_outcome') != 'MATCH':
                continue
            for finding in record.get('v2_findings') or []:
                traits = flow_traits(finding)
                steps = (finding.get('trace') or {}).get('steps') or finding.get('evidence') or []
                if traits['complete'] and any(step.get('predicate') == 'SINK'
                        and step.get('matched') is not False
                        and _path((step.get('location') or {}).get('path'), target) == _path(item.get('file'), target)
                        and (step.get('location') or {}).get('line') == item.get('line') for step in steps):
                    linked_flow = True
        if active:
            trace_status, trace_summary = 'pending', 'Trace coverage is pending while this scan is running.'
        elif limits or 'INDETERMINATE' in outcomes:
            trace_status, trace_summary = 'incomplete', 'Complete input-to-SQL tracing could not be established: related same-file semantic checks were indeterminate or recorded analysis limitations.'
        elif linked_flow:
            trace_status, trace_summary = 'recorded_bounded', 'A modeled source-to-sink path was recorded at this operation. Review its evidence separately; it does not establish full application coverage or a verified mitigation.'
        else:
            trace_status, trace_summary = 'not_recorded', ('No complete input-to-SQL trace is linked to this suppressed operation in the saved review evidence.' if sql else 'Trace completeness was not established by this suppression record.')
        if no_inputs and not active:
            limits.append('The saved input inventory contains no modeled entry points. This does not establish that UI, request or other external inputs are absent.')
        if unavailable:
            limits.append('Some saved analysis evidence could not be read; trace coverage is unknown.')
        if 'MATCH' in outcomes:
            limits.append('A related semantic rule matched in this file. Its evidence must be reviewed separately; this Pattern suppression does not dismiss that result.')
        if pattern and failed:
            summary = 'The Pattern rule matched this operation, but its additional condition did not pass. This is a rule-filter decision, not a verified mitigation.'
            scope = 'Pattern condition; this decision does not establish a complete taint flow.'
            if sql and 'PRESENT:(\\+|String\\.Format|Request\\.|QueryString|Form)' in reason and 'MISSING:(SqlParameter|AddWithValue|Parameters\\.Add|Parameters\\.AddWithValue)' in reason:
                scope = 'File-level pattern condition; no per-command input or parameter binding was established by this decision.'
                summary = 'The SQL rule required both an input/query-construction marker and the absence of a parameter-binding marker. That combined condition did not pass; the saved decision does not say which operand failed.'
                limits.insert(0, 'These markers are checked across the file. A parameter used by another command can suppress this match; its presence does not prove this command is safely bound.')
        else:
            summary = reason or 'A suppression was recorded without a decision reason. Inspect the retained rule and evidence.'
            scope = 'Recorded rule evaluation; suppression alone does not verify exploitability or protection.'
        explanation = dict(summary=summary, decision_scope=scope, trace_status=trace_status,
                           trace_summary=trace_summary, limitations=limits, related_outcomes=outcomes,
                           technical_reason=reason, basis='Saved rule decision and related same-file semantic records')
        result.append(dict(item, suppression_explanation=explanation))
    return result
