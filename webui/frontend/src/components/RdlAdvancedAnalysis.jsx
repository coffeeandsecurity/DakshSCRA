import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { getRdlShadowResults } from '../api'
import { createQueryCache, queryKey } from '../lib/queryCache'
import RetainedTab from './RetainedTab'
import { TaintFlows } from './RdlFlowViews'
import RdlCrossReferences from './RdlCrossReferences'
import RdlAttackVectors from './RdlAttackVectors'

const SECTIONS = [
  { key: 'summary', label: 'Summary', tone: 'summary' },
  { key: 'taint', label: 'Taint Flows', tone: 'taint' },
  { key: 'xref', label: 'Cross-References', tone: 'xref' },
  { key: 'vectors', label: 'Attack Vectors', tone: 'vectors' },
]

export default function RdlAdvancedAnalysis({ runUuid, onCount, onFinding }) {
  const [section, setSection] = useState('summary')
  const [search, setSearch] = useState('')
  const [filters, setFilters] = useState({ search: '', kind: 'all', offset: 0 })
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [focusId, setFocusId] = useState(null)
  const [focusItem, setFocusItem] = useState(null)
  const [xrefCount, setXrefCount] = useState(null)
  const [reload, setReload] = useState(0)
  const cache = useRef(createQueryCache())
  const requestId = useRef(0)
  const prefix = useId()
  const buttons = useRef([])
  const evidenceSection = section === 'vectors' ? 'vectors' : 'taint'
  const options = useMemo(() => Object.fromEntries(Object.entries({ view: 'all', section: evidenceSection, ...filters }).filter(([, value]) => value != null)), [evidenceSection, filters])
  useEffect(() => {
    const generation = ++requestId.current
    setLoading(true); setError('')
    cache.current.get(queryKey({ runUuid, ...options }), () => getRdlShadowResults(runUuid, 50, options))
      .then(result => {
        if (generation !== requestId.current) return
        setData(result)
        if (!options.search && options.kind === 'all') onCount?.(result.section_counts?.taint || 0)
      })
      .catch(reason => { if (generation === requestId.current) setError(reason.message || 'Unable to load recorded RDL analysis.') })
      .finally(() => { if (generation === requestId.current) setLoading(false) })
    return () => { requestId.current += 1 }
  }, [runUuid, options, reload, onCount])
  const items = useMemo(() => {
    const seen = new Set(), result = []
    for (const record of data?.comparisons || []) {
      if (record.v2_outcome !== 'MATCH') continue
      for (const finding of record.v2_findings || []) {
        const id = JSON.stringify([record.v2_rule_id || record.v2_rule, finding.location, finding.path || record.context?.file_path, finding.evidence?.length ? finding.evidence : finding.trace?.steps])
        if (!seen.has(id)) { seen.add(id); result.push({ id, finding, record }) }
      }
    }
    if (section === 'taint' && focusItem && !seen.has(focusItem.id)) result.unshift(focusItem)
    return result
  }, [data, section, focusItem])
  const counts = data?.section_counts || {}
  const badges = { summary: counts.taint || 0, taint: counts.taint || 0, xref: xrefCount ?? 'Explore', vectors: counts.vectors || 0 }
  function select(next) {
    setSection(next); setFocusId(null); setFocusItem(null)
    setFilters(value => ({ ...value, offset: 0, after: undefined }))
  }
  function navigate(next, item) {
    if (next === 'findings') { onFinding?.(item); return }
    setSection(next); setFocusId(item?.id || null); setFocusItem(item || null)
  }
  function keyDown(event, index) {
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? 3 : event.key === 'ArrowRight' ? (index + 1) % 4 : event.key === 'ArrowLeft' ? (index + 3) % 4 : null
    if (next === null) return
    event.preventDefault(); buttons.current[next]?.focus(); select(SECTIONS[next].key)
  }
  function refresh() { cache.current.clear(); setReload(value => value + 1) }
  const offset = data?.offset || 0, limit = data?.limit || 50
  const ready = !loading && data?.query?.section === evidenceSection
  return <div className="rdl-shadow-panel aa-root" aria-busy={loading}>
    <div className="rdl-panel-heading"><div><h2>Advanced Analysis</h2><p>Recorded RDL v2 source paths, symbol relationships and input entry points</p></div></div>
    <div className="rdl-shadow-callout">These views use recorded RDL evidence. A complete path means a source and sink were recorded; it does not prove exploitation. Vulnerability outcomes are listed under Vulnerability Analysis.</div>
    <div className="aa-subtabs rdl-subtabs" role="tablist" aria-label="Advanced Analysis sections">{SECTIONS.map((item, index) => <button type="button" role="tab" id={`${prefix}-tab-${item.key}`} aria-controls={`${prefix}-panel-${item.key}`} aria-selected={section === item.key} tabIndex={section === item.key ? 0 : -1} ref={button => { buttons.current[index] = button }} onKeyDown={event => keyDown(event, index)} onClick={() => select(item.key)} className={`aa-subtab tone-${item.tone}${section === item.key ? ' active' : ''}`} key={item.key}><span className="aa-subtab-copy"><span className="aa-subtab-title">{item.label}</span><span className="aa-subtab-meta">{item.key === 'taint' ? `${counts.complete || 0} complete · ${counts.partial || 0} partial` : item.key === 'xref' ? 'Symbols, callers and callees' : item.key === 'vectors' ? 'Recorded input entry points' : 'RDL evidence coverage'}</span></span><span className="aa-subtab-count">{badges[item.key]}</span><span aria-hidden="true">›</span></button>)}</div>
    {section !== 'xref' ? <>
      <form className="rdl-filter-row rdl-review-filters" onSubmit={event => { event.preventDefault(); setFilters(value => ({ ...value, search, offset: 0, after: undefined })) }}><label>Analysis type<select value={filters.kind} onChange={event => setFilters(value => ({ ...value, kind: event.target.value, offset: 0, after: undefined }))}><option value="all">All types</option><option value="semantic">Semantic analysis</option><option value="baseline">Baseline source review</option><option value="supplemental">Additional v2 checks</option></select></label><label>Find file or rule<input value={search} maxLength={200} onChange={event => setSearch(event.target.value)} placeholder="Path, property, or rule title" /></label><button type="submit" className="btn btn-primary" disabled={loading}>Search</button></form>
      <button type="button" className="btn btn-ghost" disabled={loading} onClick={refresh}>Refresh advanced analysis</button>
      {error ? <div role="alert" className="rdl-shadow-callout warning">{error} <button onClick={refresh}>Retry</button></div> : null}
      {data?.summary?.storage_error || data?.summary?.malformed || data?.summary?.telemetry_truncated ? <div className="rdl-shadow-callout warning">Some saved evidence is unavailable; coverage and totals may be incomplete.</div> : null}
    </> : null}
    {SECTIONS.map(item => <RetainedTab key={item.key} active={section === item.key} role="tabpanel" id={`${prefix}-panel-${item.key}`} aria-labelledby={`${prefix}-tab-${item.key}`}>
      {item.key === 'xref' ? <RdlCrossReferences runUuid={runUuid} onCount={setXrefCount} /> : !ready ? <div className="fr-loading" role="status">{error ? 'Recorded analysis could not be loaded.' : 'Loading recorded RDL analysis…'}</div> : item.key === 'summary' ? <>
        <div className="rdl-shadow-metrics">{[['Distinct recorded paths', counts.taint], ['Complete paths', counts.complete], ['Partial paths', counts.partial], ['Recorded handoffs', counts.xref], ['Input entry points', counts.vectors]].map(([label, value]) => <div className="rdl-shadow-metric" key={label}><div className="rdl-shadow-metric-value">{value || 0}</div><div className="rdl-shadow-metric-label">{label}</div></div>)}</div>
        <p>Counts cover the filtered scan before pagination. Text and filename matches do not establish a flow. Missing recorded paths do not establish that the application is safe.</p>
        <p>{data.summary?.coverage_limit_groups || 0} rule/file evaluations have analysis coverage limits.</p>
      </> : <>
        <div className="rdl-page-navigation"><span>{data.filtered_total} rule/file evaluations · showing {data.filtered_total ? offset + 1 : 0}–{Math.min(offset + limit, data.filtered_total || 0)}</span><button disabled={!offset || loading} onClick={() => setFilters(value => ({ ...value, offset: Math.max(0, offset - limit), after: undefined }))}>Previous</button><button disabled={!data.truncated || loading} onClick={() => setFilters(value => ({ ...value, offset: offset + limit, after: data.next_cursor }))}>Next</button></div>
        {item.key === 'taint' ? <TaintFlows items={items} focusId={focusId} onNavigate={navigate} /> : <RdlAttackVectors items={items} onNavigate={navigate} />}
      </>}
    </RetainedTab>)}
  </div>
}
