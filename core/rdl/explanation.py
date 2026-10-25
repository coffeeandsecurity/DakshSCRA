"""Evidence-backed explanations for reviewers of semantic rule outcomes."""
from dataclasses import asdict
from pathlib import Path
from utils.source_cache import read_source_text, source_stat
import re
from .trace import build_trace
from .plan import Capability

# Compatibility view for callers that consume the original three-field tuples.
from .narratives import catalogs
GUIDANCE = {key: (entry.get('cwe', ''), entry['impact'], entry['remediation'])
            for key, entry in catalogs()[1].items() if entry.get('cwe')}



def format_issue_title(title):
    """Use the same issue names in pattern, semantic and exported results."""
    from core.issue_titles import issue_title
    return issue_title(title)


def evidence_payload(evidence, sources=None):
    item = dict(predicate=evidence.predicate, matched=evidence.matched, entity_id=evidence.entity_id,
                explanation=evidence.explanation, symbol=evidence.explanation, transition=evidence.transition)
    if evidence.location:
        item['location'] = asdict(evidence.location)
        try:
            path = Path(evidence.location.path)
            # Report only bounded, local evidence already inspected by the adapter.
            if source_stat(path).st_size <= 4 * 1024 * 1024:
                from utils.file_utils import detect_encoding_type, readfile_FallbackEncoding
                sources = sources if sources is not None else {}
                if str(path) not in sources:
                    try:
                        sources[str(path)] = read_source_text(path, encoding=detect_encoding_type(path) or 'utf-8').splitlines()
                    except UnicodeError:
                        with readfile_FallbackEncoding(path) as source:
                            sources[str(path)] = source.read().splitlines()
                lines = sources[str(path)]
                first = max(1, evidence.location.line - 2)
                last = min(len(lines), max(evidence.location.line + 3, evidence.location.end_line + 2), first + 79)
                snippet = []
                for line in range(first, last + 1):
                    text = lines[line - 1]
                    snippet.append(dict(line=line, text=text, highlight=evidence.location.line <= line <= evidence.location.end_line))
                item['snippet'] = snippet
        except (OSError, UnicodeError):
            item['snippet'] = []
    return item


def explain_result(document, result):
    plan = document.execution_plan
    text_rule = not (plan.capabilities - {Capability.TEXT, Capability.PATH, Capability.PROJECT})
    from .narratives import narrative_for
    narrative = narrative_for(result.rule_id)
    cwe = narrative.get('cwe', '')
    description = narrative.get('description', 'The recorded evidence matches the named rule property; its application context requires review.')
    impact = narrative.get('impact', 'No rule-specific security consequence has been established for this unregistered property.')
    remediation = narrative.get('remediation', 'Resolve the property’s required trust boundary and controls before recommending a code change.')
    groups = result.witnesses or ((result.evidence,) if result.outcome.value == 'MATCH' else ())
    findings = []
    sources = {}
    for evidence in groups:
        anchors = [e for e in evidence if e.matched and e.predicate in {'SINK', 'EXISTS', 'STATE VIOLATION', 'TEXT_MATCHES', 'PRESENT', 'MATCHES'} and e.location]
        anchor = (anchors[0] if text_rule else anchors[-1]) if anchors else None
        payload = [evidence_payload(e, sources) for e in evidence]
        findings.append(dict(title=format_issue_title(plan.report_title), severity=plan.severity.value, confidence='LOW' if text_rule else 'MEDIUM',
            confidence_reason=('Text/path rule evidence; no data-flow or exploitability claim.' if text_rule else 'Static structural and data-flow evidence; exploitability and deployment context require review.'),
            cwe=cwe, description=description, impact=impact, remediation=remediation,
            location=asdict(anchor.location) if anchor else None,
            evidence=payload, trace=build_trace(payload, cwe)))
    outcome = result.outcome.value
    if outcome == 'MATCH':
        explanation = '{} evidence-backed review lead(s); each source location is shown below.'.format(len(groups))
        if result.errors:
            explanation += ' Coverage is incomplete: ' + '; '.join(result.errors)
    elif outcome == 'NO_MATCH':
        explanation = 'No matching issue was found for this rule in the checked code. Other issues may still be present.'
        failed = next((e for e in reversed(result.evidence) if not e.matched), None)
        if failed:
            explanation += ' Decisive check: {} ({}).'.format(failed.predicate, failed.explanation or 'condition not satisfied')
    else:
        explanation = 'No security verdict: ' + '; '.join(result.errors or result.unavailable_capabilities or ('analysis incomplete',))
    return dict(v2_title=format_issue_title(plan.report_title), v2_severity=plan.severity.value, v2_explanation=explanation,
        v2_findings=findings, v2_finding_count=len(groups), v2_findings_truncated=len(groups) > len(findings),
        v2_evidence=[evidence_payload(e, sources) for e in result.evidence],
        v2_limitations=['Only the named property and selected source scope were evaluated.',
            'Unresolved libraries, runtime configuration, dynamic dispatch, and infeasible branch combinations can require manual review.',
            'Parameter-name source inference is heuristic; a flow is a review lead, not proof of exploitation.'] if any(e.predicate == 'FLOWS TO' for e in result.evidence) else
            (['Text/path predicates identify review surfaces, not data flow or confirmed vulnerabilities.'] if text_rule else ['Entity checks do not establish runtime exploitability or whole-application safety.']))
