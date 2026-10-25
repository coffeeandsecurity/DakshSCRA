"""Portable, escaped HTML report for semantic review evidence."""
from html import escape
from pathlib import Path
import hashlib
import json
import os
import sqlite3
import tempfile
import shutil

from .shadow import read_shadow_results, iter_shadow_results
from .explanation import format_issue_title
from .trace import build_trace
from utils.guidance_format import guidance_html


def finding_anchor(record, finding):
    location = finding.get('location') or {}
    origin = next((item.get('location') or {} for item in finding.get('evidence') or []
                   if item.get('predicate') == 'SOURCE'), {})
    identity = [record.get('v2_rule_id'), location, finding.get('path') or (record.get('context') or {}).get('file_path'), origin]
    return 'trace-' + hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:16]


def render_trace(finding, prefix):
    trace = finding.get('trace') or build_trace(finding.get('evidence') or [], finding.get('cwe', ''))
    steps, blocks = [], []
    for step in trace['steps']:
        where = step.get('location') or {}
        reference = ''
        if step.get('code_block'):
            reference = '<a href="#{0}-{1}-L{2}">Code {3}, line {2}</a>'.format(
                prefix, escape(step['code_block']), int(where['line']), step['code_block'].split('-')[-1])
        steps.append('<li id="{0}-step-{1}"><strong>{2}</strong>: <code>{3}</code><p>{4}</p><p><code>{5}:{6}:{7}</code> {8}</p></li>'.format(
            prefix, step['number'], escape(step['predicate']), escape(step.get('symbol') or step.get('explanation', '')),
            escape(step['description']), escape(str(where.get('path', ''))), where.get('line', ''), where.get('column', ''), reference))
    for block in trace['blocks']:
        lines = []
        for line in block['lines']:
            labels = ' '.join('<a href="#{0}-step-{1}" title="Trace step {1}">[{1}]</a>'.format(prefix, number) for number in line['steps'])
            lines.append('<span id="{0}-{1}-L{2}" class="code-line {3}"><span class="line-number">{2}</span><span>{4}</span><span class="step-tags">{5}</span></span>'.format(
                prefix, block['id'], line['line'], 'highlight' if line.get('highlight') else '', escape(line['text']), labels))
        blocks.append('<section class="source-block"><h3>Code {0} · lines {1}-{2}</h3><code>{3}</code><pre>{4}</pre></section>'.format(
            block['id'].split('-')[-1], block['start'], block['end'], escape(block['path']), ''.join(lines)))
    handoffs = []
    for step in trace['steps']:
        path = (step.get('location') or {}).get('path')
        if path and (not handoffs or handoffs[-1] != path):
            handoffs.append(path)
    route = ''
    if len(set(handoffs)) > 1:
        route = '<aside class="file-handoffs"><strong>Cross-File Source-To-Sink Trace · {} Files</strong><p>{}</p><small>File order follows the trace, including returns to callers.</small></aside>'.format(
            len(set(handoffs)), ' → '.join('<code title="{}">{}</code>'.format(escape(path), escape('/'.join(Path(path).parts[-2:]))) for path in handoffs))
    notes = ''.join('<p><strong>{}</strong> {}</p>'.format(label, escape(trace[key])) for key, label in [('protection_note', 'Protection check:'), ('review_note', 'Evidence scope:')] if trace.get(key))
    return route + ('<aside class="trace-review-notes">' + notes + '</aside>' if notes else '') + '<p class="trace-summary">{0} steps · {1} source file(s) · {2} shared code block(s). Numbered markers link each line to its trace steps.</p><div class="trace-layout"><ol class="trace-steps">{3}</ol><div>{4}</div></div>'.format(
        len(trace['steps']), trace['file_count'], len(trace['blocks']), ''.join(steps), ''.join(blocks))


def write_shadow_report(telemetry_path, destination):
    """Stream all findings and decisions without retaining the report in memory."""
    summary = read_shadow_results(telemetry_path, limit=0)['summary']
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent) as directory:
        root = Path(directory)
        seen = sqlite3.connect(str(root/'index.db'))
        seen.execute('CREATE TABLE findings (id TEXT PRIMARY KEY, issue TEXT, title TEXT, rule TEXT, body TEXT)')
        seen.execute('CREATE TABLE occurrences (id TEXT PRIMARY KEY, family TEXT, title TEXT)')
        seen.execute('CREATE INDEX contributions_issue ON findings(issue)')
        seen.execute('CREATE INDEX occurrences_family ON occurrences(family)')
        seen.execute('CREATE TABLE navigation (files INTEGER, body TEXT)')
        count = 0
        try:
            with (root/'findings.html').open('w',encoding='utf-8') as findings, (root/'decisions.html').open('w',encoding='utf-8') as decisions:
                for record in iter_shadow_results(telemetry_path):
                    for finding in record.get('v2_findings') or []:
                        from .review_views import finding_identity
                        from .issue_families import occurrence_identity, family_title, family_key
                        occurrence = hashlib.sha256(occurrence_identity(record,finding).encode()).hexdigest()
                        identity = hashlib.sha256(finding_identity(record,finding).encode()).hexdigest()
                        if not seen.execute('INSERT OR IGNORE INTO findings(id) VALUES (?)',(identity,)).rowcount:
                            continue
                        count += seen.execute('INSERT OR IGNORE INTO occurrences VALUES (?,?,?)',(occurrence,family_key(finding),family_title(finding))).rowcount
                        anchor = 'trace-' + identity[:24]
                        location = finding.get('location') or {}
                        origin = next((item.get('location') or {} for item in finding.get('evidence') or [] if item.get('predicate') == 'SOURCE'), {})
                        trace = finding.get('trace') or build_trace(finding.get('evidence') or [],finding.get('cwe',''))
                        if trace['file_count'] > 1:
                            seen.execute('INSERT INTO navigation VALUES (?,?)',(trace['file_count'],'<li><a href="#{}">{} · {} files · source {}</a></li>'.format(anchor,escape(format_issue_title(finding['title'])),trace['file_count'],escape('/'.join(Path(origin.get('path','')).parts[-2:])))))
                        body = (('<article id="'+anchor+'"><h2>{}</h2><p class="badge">{} · {} · Confidence {}</p><p><code>{}:{}</code></p><h3>Issue description</h3><p>{}</p><h3>Security impact</h3><p>{}</p>{}<aside><strong>Review guidance</strong>{}</aside><aside><strong>Recommendations</strong>{}</aside><p>{}</p></article>').format(
                            escape(format_issue_title(finding['title'])),escape(finding.get('severity','')),escape(finding.get('cwe','')),escape(finding.get('confidence','')),
                            escape(str(location.get('path') or finding.get('path') or (record.get('context') or {}).get('file_path',''))),location.get('line','path only' if finding.get('path_only') else ''),escape(finding.get('description','')),escape(finding.get('impact','')),render_trace(finding,anchor),guidance_html(finding.get('reviewer_note','')),guidance_html(finding.get('remediation','')),escape(finding.get('confidence_reason',''))))
                        seen.execute('UPDATE findings SET issue=?,title=?,rule=?,body=? WHERE id=?',(occurrence,family_title(finding),record.get('v2_rule_id') or record.get('v2_rule') or '',body,identity))
                    context = record.get('context') or {}
                    decisions.write('<details><summary>{} · {} · v1 {} / v2 {}</summary><p>{}</p><p>{}</p></details>'.format(
                        escape(str(record.get('comparison_kind','semantic'))+' · '+str(record.get('status','UNKNOWN'))),escape(str(context.get('file_path',''))),escape(str(record.get('v1_outcome',''))),escape(str(record.get('v2_outcome',''))),escape(str(record.get('v2_explanation',''))),escape(str(record.get('v1_reason','')))))
            with (root/'findings.html').open('w',encoding='utf-8') as findings:
                for family, title in seen.execute('SELECT family,MIN(title) FROM occurrences GROUP BY family ORDER BY MIN(rowid)'):
                    findings.write('<section class="issue-family"><h2>'+escape(title)+'</h2>')
                    for occurrence, in seen.execute('SELECT id FROM occurrences WHERE family=? ORDER BY rowid',(family,)):
                        findings.write('<details class="issue-occurrence" open><summary>Recorded source occurrence</summary>')
                        first = True
                        for title, rule, body in seen.execute('SELECT title,rule,body FROM findings WHERE issue=? ORDER BY rowid',(occurrence,)):
                            body = body.replace('<h2>'+escape(format_issue_title(title))+'</h2>','',1)
                            findings.write('<details class="rule-contribution"'+(' open' if first else '')+'><summary>Contributing rule: '+escape(rule)+'</summary>'+body+'</details>')
                            first = False
                        findings.write('</details>')
                    findings.write('</section>')
            header = '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">\n<title>RDL v2 review</title><style>body{font:15px/1.6 system-ui,sans-serif;color:#183042;background:#edf2f6;margin:0}main{max-width:1060px;margin:auto;padding:36px 20px}h1{font-size:34px}article,header,details{background:white;border:1px solid #d2dfe8;border-radius:12px;padding:24px;margin:18px 0}code,pre{font:12px/1.7 monospace;overflow-wrap:anywhere}pre{overflow:auto;background:#f2f5f8;padding:12px}aside{background:#e8f3fa;border-left:4px solid #2375a5;padding:14px}summary{cursor:pointer;overflow-wrap:anywhere}.badge{font-weight:bold;color:#974717}li{margin:18px 0}@media print{body{background:white}article{break-inside:avoid}details{display:none}.rule-contribution,.issue-occurrence{display:block}.rule-contribution>summary{display:none}}</style><main>\n<header><h1>RDL v2 review</h1><p>Evidence, security impact, and corrective guidance for human review.</p>\n<p><strong>%(leads)s unique review leads · %(properties)s properties · %(files)s files evaluated</strong></p>\n<p>RDL v2 is experimental. V1 results remain separate when both engines are selected; NOT_RUN means v1 was not selected. The v1 column below describes its RDL logic gate, not every regex or suppression in the full scanner. V2 disagreements require review and are not automatically confirmed defects.</p>\n<p>Baseline text/path checks, semantic analysis and supplemental checks are separate coverage layers. Text matches do not establish data flow. Only selected rule packs and configured mappings were evaluated. A no-match is not proof of application safety. Unsupported control flow and dynamic behavior remain explicit limitations.</p></header>\n' % dict(leads=count,properties=summary.get('evaluated_properties',0),files=summary.get('evaluated_files',0))
            header = header.replace('</style>', '\n.trace-layout{display:grid;grid-template-columns:minmax(240px, .85fr) minmax(0,1.15fr);gap:28px}.trace-steps{padding-left:25px;margin:0}.trace-steps p{margin:6px 0}.source-block{min-width:0;margin:16px 0 24px}.source-block h3{margin:0 0 6px;font-size:15px}.source-block pre{padding:10px 0}.code-line{display:flex;gap:12px;min-width:max-content;padding:2px 12px}.line-number{display:inline-block;min-width:3ch;color:#607286;user-select:none}.highlight{background:#fff3cb}.step-tags{margin-left:auto;padding-left:12px}a{color:#155bab}.code-line:target,.trace-steps li:target{outline:2px solid #2375a5;scroll-margin-top:24px}.trace-summary{color:#52687a;font-size:13px}@media(max-width:850px){.trace-layout{grid-template-columns:minmax(0,1fr)}}@media print{.trace-layout{display:block}.source-block pre{white-space:pre-wrap}.code-line{min-width:0}}\n.cross-file-index{padding:20px;background:#fff;border:2px solid #2375a5;border-radius:12px;margin:18px 0}.file-handoffs p{overflow-wrap:anywhere;margin:8px 0}article:target{outline:3px solid #2375a5;scroll-margin-top:12px}\n</style>')
            output = root/'report.html'
            with output.open('w',encoding='utf-8') as handle:
                handle.write(header)
                if summary.get('telemetry_truncated') or summary.get('malformed') or summary.get('storage_error'):
                    handle.write('<aside>Recorded coverage is incomplete. Review diagnostics; missing results do not establish safety.</aside>')
                if seen.execute('SELECT COUNT(*) FROM navigation').fetchone()[0]:
                    handle.write('<section class="cross-file-index"><h2>Cross-File Traces</h2><ul>')
                    for row in seen.execute('SELECT body FROM navigation ORDER BY files'): handle.write(row[0])
                    handle.write('</ul></section>')
                if not count: handle.write('<p>No supported review leads were recorded. Inspect unresolved decisions below.</p>')
                with (root/'findings.html').open(encoding='utf-8') as source: shutil.copyfileobj(source,handle)
                handle.write('<h2>Decision ledger</h2><p>{} mapped evaluations. All recorded property/file decisions are included; the compressed JSONL download preserves every original evaluation.</p>'.format(summary['total']))
                with (root/'decisions.html').open(encoding='utf-8') as source: shutil.copyfileobj(source,handle)
                handle.write('</main></html>')
            os.replace(output,destination)
        finally:
            seen.close()
    return destination
