import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { getRdlAdvancedResults, buildRdlXref } from '../api'
import { createQueryCache, queryKey } from '../lib/queryCache'
import RetainedTab from './RetainedTab'
import { TaintFlows } from './RdlFlowViews'
import RdlCrossReferences from './RdlCrossReferences'
import RdlAttackVectors from './RdlAttackVectors'

const SECTIONS = [
  { key: 'taint', label: 'Taint Flows', tone: 'taint' },
  { key: 'xref', label: 'Cross-References', tone: 'xref' },
  { key: 'vectors', label: 'Attack Vectors', tone: 'vectors' },
]

export default function RdlAdvancedAnalysis({ runUuid, onCount, onFinding }) {
  const [section, setSection] = useState('taint')
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
    cache.current.get(queryKey({ runUuid, ...options }), () => getRdlAdvancedResults(runUuid, 50, options))
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
      for (const finding of record.v2_findings || []) {
        const id = JSON.stringify([record.v2_rule_id || record.v2_rule, finding.location, finding.path || record.context?.file_path, finding.evidence?.length ? finding.evidence : finding.trace?.steps])
        if (!seen.has(id)) { seen.add(id); result.push({ id, finding, record }) }
      }
    }
    if (section === 'taint' && focusItem && !seen.has(focusItem.id)) result.unshift(focusItem)
    return result
  }, [data, section, focusItem])
  const counts = data?.section_counts || {}
  const badges = { taint: counts.taint || 0, xref: xrefCount ?? 'Explore', vectors: counts.vectors || 0 }
  function select(next) {
    setSection(next); setFocusId(null); setFocusItem(null)
    setFilters(value => ({ ...value, offset: 0, after: undefined }))
  }
  function navigate(next, item) {
    if (next === 'findings') { onFinding?.(item); return }
    setSection(next); setFocusId(item?.id || null); setFocusItem(item || null)
  }
  function keyDown(event, index) {
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? SECTIONS.length - 1 : event.key === 'ArrowRight' ? (index + 1) % SECTIONS.length : event.key === 'ArrowLeft' ? (index + SECTIONS.length - 1) % SECTIONS.length : null
    if (next === null) return
    event.preventDefault(); buttons.current[next]?.focus(); select(SECTIONS[next].key)
  }
  function refresh() { cache.current.clear(); setReload(value => value + 1) }
  async function rebuild() { setLoading(true); setError(''); try { await buildRdlXref(runUuid); refresh() } catch (reason) { setError(reason.message); setLoading(false) } }
  const offset = data?.offset || 0, limit = data?.limit || 50
  const ready = !loading && data?.query?.section === evidenceSection
  return <div className="rdl-shadow-panel aa-root" aria-busy={loading}>
    <div className="rdl-panel-heading"><div><h2>Advanced Analysis</h2><p>Recorded RDL v2 source paths, symbol relationships and input entry points</p></div></div>
    <div className="rdl-shadow-callout">Explore recorded inputs and data paths. Complete paths connect an input to a modeled destination; partial paths have unresolved steps. Vulnerability decisions are listed under Vulnerability Analysis.</div>
    <div className="aa-subtabs rdl-subtabs" role="tablist" aria-label="Advanced Analysis sections">{SECTIONS.map((item, index) => <button type="button" role="tab" id={`${prefix}-tab-${item.key}`} aria-controls={`${prefix}-panel-${item.key}`} aria-selected={section === item.key} tabIndex={section === item.key ? 0 : -1} ref={button => { buttons.current[index] = button }} onKeyDown={event => keyDown(event, index)} onClick={() => select(item.key)} className={`aa-subtab tone-${item.tone}${section === item.key ? ' active' : ''}`} key={item.key}><span className="aa-subtab-copy"><span className="aa-subtab-title">{item.label}</span><span className="aa-subtab-meta">{item.key === 'taint' ? `${counts.complete || 0} complete · ${counts.partial || 0} partial` : item.key === 'xref' ? 'Symbols, callers and callees' : item.key === 'vectors' ? 'Recorded input entry points' : 'RDL evidence coverage'}</span></span><span className="aa-subtab-count">{badges[item.key]}</span><span aria-hidden="true">›</span></button>)}</div>
    {section !== 'xref' ? <>
      <form className="rdl-filter-row rdl-review-filters" onSubmit={event => { event.preventDefault(); setFilters(value => ({ ...value, search, offset: 0, after: undefined })) }}><label>Find input or file<input value={search} maxLength={200} onChange={event => setSearch(event.target.value)} placeholder="Input name or file path" /></label><button type="submit" className="btn btn-primary" disabled={loading}>Search</button></form>
      <button type="button" className="btn btn-ghost" disabled={loading} onClick={refresh}>Refresh advanced analysis</button>
      {error ? <div role="alert" className="rdl-shadow-callout warning">{error} <button onClick={refresh}>Retry</button></div> : null}
      {data?.needs_rebuild ? <div className="rdl-shadow-callout warning">This scan has no saved input and flow inventory. <button disabled={loading} onClick={rebuild}>Build from current source</button></div> : null}
      {data?.provenance === 'current-source' ? <p className="rdl-coverage-note">Rebuilt from current source; original scan verdicts are unchanged.</p> : null}
      {data?.diagnostics?.length ? <details><summary>Analysis coverage ({data.diagnostic_count || data.diagnostics.length} limits)</summary>{data.diagnostics.map((note, i) => <p key={i}>{note}</p>)}</details> : null}
      {data?.summary?.storage_error || data?.summary?.malformed || data?.summary?.telemetry_truncated ? <div className="rdl-shadow-callout warning">Some saved evidence is unavailable; coverage and totals may be incomplete.</div> : null}
    </> : null}
    {SECTIONS.map(item => <RetainedTab key={item.key} active={section === item.key} role="tabpanel" id={`${prefix}-panel-${item.key}`} aria-labelledby={`${prefix}-tab-${item.key}`}>
      {item.key === 'xref' ? <RdlCrossReferences runUuid={runUuid} onCount={setXrefCount} /> : !ready ? <div className="fr-loading" role="status">{error ? 'Recorded analysis could not be loaded.' : 'Loading recorded RDL analysis…'}</div> : <>
        <div className="rdl-page-navigation"><span>{data.filtered_total} path records · showing {data.filtered_total ? offset + 1 : 0}–{Math.min(offset + limit, data.filtered_total || 0)}</span><button disabled={!offset || loading} onClick={() => setFilters(value => ({ ...value, offset: Math.max(0, offset - limit), after: undefined }))}>Previous</button><button disabled={!data.truncated || loading} onClick={() => setFilters(value => ({ ...value, offset: offset + limit, after: data.next_cursor }))}>Next</button></div>
        {item.key === 'taint' ? <TaintFlows items={items} focusId={focusId} onNavigate={navigate} /> : <RdlAttackVectors items={items} onNavigate={navigate} />}
      </>}
    </RetainedTab>)}
  </div>
}
