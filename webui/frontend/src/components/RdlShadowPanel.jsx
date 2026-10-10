import RetainedTab from './RetainedTab'
import { useId, useMemo, useState } from 'react'
import RdlTrace from './RdlTrace'

function Metric({ label, value }) {
  return <div className="rdl-shadow-metric"><div className="rdl-shadow-metric-value">{Number(value || 0).toLocaleString()}</div><div className="rdl-shadow-metric-label">{label}</div></div>
}

function Evidence({ items = [], showSnippets = true }) {
  return <ol className="rdl-evidence-steps">{items.map((item, index) => <li key={index}>
    <div><strong>{item.predicate}</strong> <span>{item.matched ? 'Observed' : 'Not established'}</span></div>
    <p>{item.explanation || 'See the recorded predicate outcome.'}</p>
    {item.location ? <code className="rdl-source-location">{item.location.path}:{item.location.line}:{item.location.column}</code> : null}
    {showSnippets && item.snippet?.length ? <pre className="rdl-source-snippet">{item.snippet.map(line => <span className={line.highlight ? 'highlight' : ''} key={line.line}><span className="rdl-line-number">{line.line}</span>{line.text}{'\n'}</span>)}</pre> : null}
  </li>)}</ol>
}

function Finding({ finding, index, item, onNavigate }) {
  return <section className="rdl-review-lead">
    <div className="rdl-lead-heading"><strong>Finding {index + 1}: {finding.title}</strong><span className="rdl-shadow-badge warning">{finding.severity} · {finding.cwe || 'Security review'}</span></div>
    <div className="rdl-assessment-grid"><div><span className="aa-simple-stage-title">Affected location</span><code className="rdl-source-location">{finding.location?.path || finding.path || item?.record.context?.file_path || 'Not recorded'}{finding.location?.line ? ':' + finding.location.line : ''}</code></div><div><span className="aa-simple-stage-title">Confidence · {finding.confidence || 'Unspecified'}</span><p>{finding.confidence_reason || 'Review the available evidence before confirming this issue.'}</p></div></div>
    <h4>Issue description</h4><p>{finding.description || 'This saved result does not contain an issue description. Review the recorded rule evidence.'}</p>
    <h4>Security impact</h4><p>{finding.impact || 'No rule-specific security consequence was recorded.'}</p>
    <div className="rdl-remediation"><strong>Recommended correction</strong><p>{finding.remediation || 'No correction guidance was recorded.'}</p></div>
    <RdlTrace finding={finding} />
  </section>
}

function Comparison({ item, showFindings = true }) {
  const context = item.context || {}
  const comparisonRetained = item.comparison_retained !== false
  const positive = item.v2_outcome === 'MATCH'
  const unresolved = ['INDETERMINATE', 'RULE_ERROR', 'SHADOW_ERROR'].includes(item.v2_outcome)
  const label = item.assessment === 'suppressed' ? 'Suppressed false positive' : item.assessment === 'mitigated' ? 'Mitigated implementation' : item.assessment === 'confirmed' ? 'Confirmed rule match' : positive ? (item.v1_outcome === 'NO_MATCH' ? 'Additional v2 evidence' : 'Review lead') : unresolved ? 'Needs manual review' : item.v1_outcome === 'MATCH' ? 'V1-only match' : 'No match for this property'
  return <details className="rdl-shadow-record" open={positive || item.status === 'DISAGREEMENT'}>
    <summary><span className={'rdl-shadow-badge ' + (positive ? 'warning' : unresolved ? 'danger' : 'neutral')}>{label}</span><span className="rdl-shadow-rule">{item.v2_title || context.rule_title || item.v2_rule_id || item.v2_rule}<code className="rdl-record-path">{context.file_path || 'No file recorded'}</code></span><span className="rdl-shadow-outcomes">{comparisonRetained ? `v1 ${item.v1_outcome} / v2 ${item.v2_outcome}` : item.v2_outcome}</span></summary>
    <div className="rdl-shadow-record-body">
      <code className="rdl-source-location">{context.file_path || 'No file recorded'}</code>
      {item.security_review ? <p><strong>Recorded review:</strong> {item.security_review.status} · {item.security_review.reviewer} · {item.security_review.reason}</p> : null}
      <p><strong>{item.comparison_kind === 'custom' ? 'App-specific custom RDL check' : item.comparison_kind === 'baseline' ? 'Baseline source review' : item.comparison_kind === 'supplemental' ? 'Additional v2 check (no v1 counterpart)' : 'Semantic analysis'}</strong></p>
      {item.manual_review ? <section><h4>Observed evidence</h4><p>{item.manual_review.observed}</p><h4>What remains uncertain</h4><p>{item.manual_review.uncertainty}</p><h4>What to investigate</h4><p>{item.manual_review.investigate}</p><Evidence items={item.manual_review.evidence} /></section> : null}
      {!item.manual_review ? <p>{item.v2_explanation || 'This older scan contains predicate evidence only. Run a new scan for source excerpts and remediation.'}</p> : null}
      {showFindings ? (item.v2_findings || []).map((finding, index) => <Finding finding={finding} index={index} key={index} />) : null}
      {item.v2_findings_truncated ? <p>Additional locations were found. This record displays the first {item.v2_findings.length} leads.</p> : null}
      {item.v2_errors?.length ? <details><summary>Technical analysis limits ({item.v2_errors.length})</summary><ul>{item.v2_errors.map((error, index) => <li key={index}>{error}</li>)}</ul></details> : null}
      {item.v2_unavailable_capabilities?.length ? <div><strong>Missing capabilities:</strong> {item.v2_unavailable_capabilities.join(', ')}</div> : null}
      <details className="rdl-decision-details"><summary>Analysis explanation</summary>
        {comparisonRetained ? <>
        <p><strong>V1 logic gates:</strong> {['NOT_RUN', 'NOT_APPLICABLE'].includes(item.v1_outcome) ? 'V1 was not run or has no counterpart for this check.' : `${item.v1_outcome} if any mapped gate matched. This does not include every regex and suppression in the main scanner.`}</p>
        {(item.v1_decisions || [{ logic_ref: context.logic_ref, outcome: item.v1_outcome, reason: item.v1_reason }]).map((decision, index) => <p key={index}><code>{decision.logic_ref}</code>: <strong>{decision.outcome}</strong>. {decision.reason}</p>)}
        <p><strong>Comparison:</strong> {item.status}. Disagreement alone does not establish a false positive or a missed vulnerability.</p>
        </> : null}
        <p><strong>Rule mapping:</strong> <code>{context.logic_ref || '-'}</code> to <code>{item.v2_rule}</code></p>
        <Evidence items={item.v2_evidence} showSnippets={!item.v2_findings?.length} />
        {(item.v2_limitations || []).map((limitation, index) => <p key={index}>{limitation}</p>)}
      </details>
    </div>
  </details>
}


function FindingFamily({ family, focusId, onNavigate, open, onToggle }) {
  const [selectedId, setSelectedId] = useState(null)
  const selected = family.items.find(item => item.id === selectedId) || family.items.find(item => item.id === focusId) || family.items[0]
  const detailId = useId()
  return <section className={`vg-family${open ? ' open' : ''}`}>
    <button className="vg-family-head" aria-expanded={open} aria-controls={detailId} onClick={onToggle}>
      <div className="vg-family-head-main">
        <div className="vg-family-title-row"><span className={`aa-pill severity ${String(family.severity || 'unknown').toLowerCase()}`}>{family.severity || 'Review'}</span><span className="vg-family-title">{family.title}</span><span className="vg-family-count">{family.items.length} instance{family.items.length === 1 ? '' : 's'}</span></div>
        <div className="vg-family-meta"><span>{family.cwe || 'Security review'}</span><span>{new Set(family.items.map(item => item.finding.location?.path || item.finding.path || item.record.context?.file_path)).size} file(s) on this page</span><span>RDL v2 evidence</span></div>
      </div><span className="vg-caret">{open ? '▲' : '▼'}</span>
    </button>
    {open ? <div className="vg-family-body" id={detailId}>
      <div className="vg-instance-list" aria-label={`${family.title} instances`}>
        {family.items.map(item => <button key={item.id} className={`vg-instance-row${selected.id === item.id ? ' active' : ''}`} aria-pressed={selected.id === item.id} onClick={() => setSelectedId(item.id)}>
          <div className="vg-instance-row-top"><strong>{(item.finding.location?.path || item.finding.path || item.record.context?.file_path || 'Unknown location').split(/[\\/]/).slice(-2).join('/')}{item.finding.path_only ? ' · path only' : ':' + (item.finding.location?.line || '?')}</strong></div>
          <div className="vg-instance-row-sub"><span>{item.finding.confidence || 'Unspecified'} confidence</span><span>{item.finding.trace?.steps?.length || 0} trace steps</span></div>
        </button>)}
      </div>
      <div className="vg-detail" key={selected.id}>
        <Finding finding={selected.finding} index={family.items.indexOf(selected)} item={selected} onNavigate={onNavigate} />
        <details className="rdl-decision-details"><summary>Analysis decision and evidence</summary><Comparison item={selected.record} showFindings={false} /></details>
      </div>
    </div> : null}
  </section>
}

function FindingGroups({ families, focusId, onNavigate, navigation }) {
  const [expanded, setExpanded] = useState({})
  const listId = useId()
  const isOpen = family => expanded[family.key] ?? Boolean(focusId && family.items.some(item => item.id === focusId))
  const allExpanded = families.length > 0 && families.every(isOpen)
  return <>
    <div className="rdl-findings-actions">
      {navigation}
      {families.length > 0 ? <button type="button" className="btn btn-secondary" aria-controls={listId} onClick={() => setExpanded(Object.fromEntries(families.map(family => [family.key, !allExpanded])))}>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={allExpanded ? 'm7 8 5 5 5-5M7 16l5-5 5 5' : 'm7 8 5-5 5 5M7 16l5 5 5-5'} /></svg>
        {allExpanded ? 'Collapse all' : 'Expand all'}
      </button> : null}
    </div>
    <div className="vg-family-list" id={listId}>{families.map(family => <FindingFamily family={family} key={family.key} focusId={focusId} onNavigate={onNavigate} open={isOpen(family)} onToggle={() => setExpanded(current => ({ ...current, [family.key]: !isOpen(family) }))} />)}</div>
  </>
}

function severityRank(value) {
  return ({ CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4, INFORMATIONAL: 4, INFORMATION: 4 })[String(value || '').trim().toUpperCase()] ?? 5
}

function groupFindings(records) {
  const families = new Map()
  const seen = new Set()
  for (const record of records || []) {
    if (record.v2_outcome !== 'MATCH') continue
    for (const finding of record.v2_findings || []) {
      const id = JSON.stringify([record.v2_rule_id || record.v2_rule, finding.location, finding.path || record.context?.file_path, finding.evidence?.length ? finding.evidence : finding.trace?.steps])
      if (seen.has(id)) continue
      seen.add(id)
      const key = `${finding.cwe || ''}:${finding.title}`
      if (!families.has(key)) families.set(key, { key, title: finding.title, cwe: finding.cwe, severity: finding.severity, items: [] })
      const family = families.get(key)
      if (severityRank(finding.severity) < severityRank(family.severity)) family.severity = finding.severity
      family.items.push({ id, finding, record })
    }
  }
  for (const family of families.values()) family.items.sort((a, b) => severityRank(a.finding.severity) - severityRank(b.finding.severity) || a.id.localeCompare(b.id))
  return [...families.values()].sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.title.localeCompare(b.title) || a.key.localeCompare(b.key))
}

const SECTIONS = [
  { key: 'summary', label: 'Summary', note: 'RDL v2 analysis outcome overview', tone: 'summary', icon: 'summary' },
  { key: 'confirmed', label: 'Confirmed Findings', note: 'Recorded RDL rule matches', tone: 'taint', icon: 'review' },
  { key: 'suppressed', label: 'Suppressed False Positives', note: 'Recorded false-positive reviews', tone: 'xref', icon: 'check' },
  { key: 'manual', label: 'Manual Inspection Recommended', note: 'Partial security evidence requiring a specific investigation', tone: 'vectors', icon: 'review' },
  { key: 'mitigated', label: 'Mitigated Implementations', note: 'Controls supported by rule evidence', tone: 'report', icon: 'check' },
]
function SectionIcon({ name }) {
  const paths = {
    summary: 'M4 4h16v16H4z M8 16v-4m4 4V8m4 8v-6',
    check: 'M9 12l2 2 4-4 M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20',
    review: 'M8 4H5v17h14V4h-3 M8 2h8v5H8z M8 13l2 2 5-5',
  }
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={paths[name]} /></svg>
}

export default function VulnerabilityAnalysis({ data, loading, onQuery, onRefresh, initialSection = 'summary', focusItem }) {
  const [section, setSection] = useState(initialSection)
  const [search, setSearch] = useState(focusItem?.record.context?.file_path || '')
  const [appliedSearch, setAppliedSearch] = useState(focusItem?.record.context?.file_path || '')
  const [kind, setKind] = useState(focusItem?.record.comparison_kind || 'all')
  const prefix = useId()
  const families = useMemo(() => groupFindings(data?.comparisons), [data?.comparisons])
  function query(nextSection = section, nextSearch = appliedSearch, nextKind = kind, offset = 0, after = null) {
    onQuery?.({ view: 'all', search: nextSearch, kind: nextKind, section: nextSection === 'summary' ? 'all' : nextSection, offset, ...(after ? { after } : {}) })
  }
  function selectSection(next) {
    if (next === section) return
    setSection(next)
    query(next)
  }
  function tabKeys(event, index) {
    const direction = event.key === 'ArrowRight' ? 1 : event.key === 'ArrowLeft' ? -1 : 0
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? SECTIONS.length - 1 : direction ? (index + direction + SECTIONS.length) % SECTIONS.length : null
    if (next === null) return
    event.preventDefault()
    document.getElementById(`${prefix}-tab-${SECTIONS[next].key}`)?.focus()
    selectSection(SECTIONS[next].key)
  }
  if (loading && !data) return <div className="fr-loading"><div className="fr-spinner" /><span>Loading vulnerability analysis...</span></div>
  if (data?.error) return <div className="rdl-shadow-callout warning" role="alert">{data.error} <button onClick={() => query()}>Retry</button></div>
  if (!data?.enabled) return <div className="empty-state"><div className="empty-title">RDL v2 was not enabled for this scan</div><p>Run a scan with RDL v2 to populate Vulnerability Analysis. Legacy analyzer verdicts are retired; historical artifacts remain available under Reports.</p></div>
  const counts = data.assessment_counts || {}
  const summary = data.summary || {}
  const ordered = data.comparisons || [], offset = data.offset || 0, limit = data.limit || 50
  const info = SECTIONS.find(item => item.key === section)
  // A response for the previous category may be visible while a request loads.
  const responseSection = data.query?.section || 'all'
  const ready = !loading && responseSection === (section === 'summary' ? 'all' : section)
  return <div className="rdl-shadow-panel" aria-busy={loading}>
    <header className="rdl-panel-heading"><div><h3>Vulnerability Analysis</h3><p>RDL v2 findings, recorded reviews and mitigation evidence</p></div></header>
    <div className="rdl-shadow-callout">Confirmed Findings are recorded RDL rule matches, not proof of exploitation. Manual Inspection lists partial security evidence with a specific investigation step. Analyzer failures alone are coverage limits. Negative checks are listed as mitigated only when control evidence was recorded.</div>
    <div className="aa-subtabs rdl-subtabs vulnerability-subtabs" role="tablist" aria-label="Vulnerability Analysis sections">{SECTIONS.map((item, index) => <button type="button" role="tab" id={`${prefix}-tab-${item.key}`} aria-controls={`${prefix}-panel-${item.key}`} aria-selected={section === item.key} tabIndex={section === item.key ? 0 : -1} className={`aa-subtab tone-${item.tone}${section === item.key ? ' active' : ''}`} key={item.key} onClick={() => selectSection(item.key)} onKeyDown={event => tabKeys(event, index)}>
      <span className="aa-subtab-icon"><SectionIcon name={item.icon} /></span><span className="aa-subtab-copy"><span className="aa-subtab-title">{item.label}</span><span className="aa-subtab-meta">{item.note}</span></span><span className="aa-subtab-count">{item.key === 'summary' ? data.confirmed_finding_count ?? data.section_counts?.findings ?? '—' : counts[item.key] ?? '—'}</span><span aria-hidden="true">›</span>
    </button>)}</div>
    <form className="rdl-review-filters" onSubmit={event => { event.preventDefault(); setAppliedSearch(search); query(section, search) }}>
      <label>Analysis type<select aria-label="Analysis type" value={kind} disabled={loading} onChange={event => { setKind(event.target.value); query(section, appliedSearch, event.target.value) }}><option value="all">All types</option><option value="baseline">Baseline source review</option><option value="semantic">Semantic analysis</option><option value="supplemental">Additional v2 checks</option><option value="custom">App-specific custom RDL</option></select></label>
      <label>Find file or rule<input value={search} maxLength={200} onChange={event => setSearch(event.target.value)} placeholder="Path, property, or rule title" /></label><button type="submit" disabled={loading}>Search</button>
    </form>
    <p className="rdl-coverage-note">Counts represent distinct rule/file evaluations across the filtered scan, before pagination. Duplicate evaluations are grouped; affected locations are retained within each issue family.</p>
    {summary.storage_error ? <div className="rdl-shadow-callout warning">Some results could not be saved. This scan is incomplete; inspect the scan log.</div> : null}
    {summary.malformed || summary.telemetry_truncated ? <div className="rdl-shadow-callout warning">Some saved evidence is missing or unreadable; totals may be incomplete.</div> : null}
    <RetainedTab active role="tabpanel" id={`${prefix}-panel-${section}`} aria-labelledby={`${prefix}-tab-${section}`} tabIndex={0} className="rdl-section-panel">
      <div className="rdl-results-heading"><div className="vg-section-head"><h3>{info.label}</h3><p>{info.note}</p></div><button type="button" className="btn btn-ghost" disabled={loading} onClick={onRefresh}>Refresh analysis results</button></div>
      {!ready ? <div className="fr-loading" role="status"><div className="fr-spinner" /><span>Loading {info.label.toLowerCase()}...</span></div> : section === 'summary' ? <>
        <p className="rdl-coverage-note">{data.confirmed_finding_count ?? data.section_counts?.findings ?? 0} distinct matched findings in {counts.confirmed || 0} rule/file evaluations. Unresolved checks are counted separately below.</p>
        <div className="rdl-shadow-metrics"><Metric label="Checks with coverage limits (not findings)" value={summary.coverage_limit_groups} /><Metric label="Matched rule/file evaluations" value={counts.confirmed} /><Metric label="Suppressed false-positive evaluations" value={counts.suppressed} /><Metric label="Actionable manual review evaluations" value={counts.manual} /><Metric label="Mitigated evaluations" value={counts.mitigated} /></div>
        <div className="rdl-summary-actions">{SECTIONS.slice(1).map(item => <button key={item.key} onClick={() => selectSection(item.key)}><SectionIcon name={item.icon} /><strong>{counts[item.key] || 0} {item.label}</strong><span>{item.note} →</span></button>)}</div>
        <p className="rdl-coverage-note">{summary.evaluated_properties || 0} properties evaluated across {summary.evaluated_files || 0} files. Checks without an applicable issue or recorded control are excluded from the four outcome categories.</p>
        <p className="rdl-coverage-note">Baseline: {data.evaluation_kinds?.baseline || 0} · Semantic: {data.evaluation_kinds?.semantic || 0} · Supplemental: {data.evaluation_kinds?.supplemental || 0} · Custom: {data.evaluation_kinds?.custom || 0}. These counts describe evaluated properties, not whole-application security coverage.</p>
      </> : <>

        {ordered.some(item => item.v2_findings_truncated) ? <div className="rdl-shadow-callout warning">Some evaluations contain more locations than were retained. Counts reflect recorded evidence only.</div> : null}
        <FindingGroups key={`${section}:${offset}:${data.query?.search}:${data.query?.kind}`} families={families} navigation={<div className="rdl-page-navigation"><span role="status">{data.filtered_total || 0} rule/file evaluations · showing {ordered.length ? offset + 1 : 0}–{offset + ordered.length}</span><button disabled={offset === 0} onClick={() => query(section, appliedSearch, kind, Math.max(0, offset - limit))}>Previous</button><button disabled={!data.truncated} onClick={() => query(section, appliedSearch, kind, offset + limit, data.next_cursor)}>Next</button></div>} focusId={section === 'confirmed' ? focusItem?.id : null} />
        {ordered.filter(item => !item.v2_findings?.length).map((item, index) => <Comparison item={item} key={index} />)}
        {!ordered.length ? <div className="empty-state">No recorded RDL outcomes in this category match the filters.</div> : null}
      </>}
    </RetainedTab>
  </div>
}
