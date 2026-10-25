import { useEffect, useMemo, useRef, useState } from 'react'
import { buildProgramGraphs, getProgramGraphs } from '../api'
import { createQueryCache, queryKey } from '../lib/queryCache'
import { querySavedProgramGraphs } from '../lib/programGraphModel'
import ProgramGraph from './ProgramGraph'
import { formatDateTime } from '../lib/datetime'

export default function ProgramGraphsPanel({ runUuid, catalog }) {
  const [query, setQuery] = useState({ kind: 'cfg', language: 'all', search: '', offset: 0, file_id: '', function_id: '' })
  const [draft, setDraft] = useState(''), [data, setData] = useState(null), [loading, setLoading] = useState(true), [error, setError] = useState(''), [building, setBuilding] = useState(false), [revision, setRevision] = useState(0)
  const cache = useRef(createQueryCache())
  useEffect(() => {
    let current = true
    setLoading(true); setError('')
    const request = catalog ? Promise.resolve(querySavedProgramGraphs(catalog, query)) : cache.current.get(queryKey({ runUuid, ...query }), () => getProgramGraphs(runUuid, query))
    request.then(result => {
      if (!current) return
      setData(result)
      if (!query.file_id && result.files?.length) {
        const first = result.files[0], scope = first.functions?.find(item => item.name !== '<module>')
        setQuery(value => ({ ...value, file_id: first.id, function_id: scope?.id || '' }))
      }
    }).catch(reason => { if (current) setError(reason.message || 'Unable to load saved program graphs.') })
      .finally(() => { if (current) setLoading(false) })
    return () => { current = false }
  }, [runUuid, catalog, query, revision])
  const selected = data?.selected, graph = data?.graph
  const notes = useMemo(() => [...new Set([...(data?.diagnostics || []), ...(selected?.diagnostics || []), ...(graph?.diagnostics || []), ...(graph?.limitations || [])])], [data, selected, graph])
  async function rebuild() {
    setBuilding(true); setError('')
    try {
      await buildProgramGraphs(runUuid); cache.current.clear()
      setQuery(value => ({ ...value, file_id: '', function_id: '', offset: 0 })); setRevision(value => value + 1)
    } catch (reason) { setError(reason.message || 'Unable to build program graphs.') }
    finally { setBuilding(false) }
  }
  function downloadJson() {
    const payload = { provenance: data.provenance, created_at: data.created_at, file: selected.path, sha256: selected.sha256, function_id: query.function_id, graph }
    const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }))
    const link = document.createElement('a'); link.href = url; link.download = `${query.kind}-evidence.json`; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000)
  }
  return <section className="program-graphs-panel" aria-label="Control and data flow graphs" aria-busy={loading || building}>
    <header className="rdl-panel-heading"><div><h2>Control &amp; Data Flow</h2><p>CFG follows possible execution; DFG follows modeled value dependencies. Taint paths remain a separate security-focused view.</p></div></header>
    <p className="rdl-shadow-callout">Graphs use saved source snapshots across executable-language profiles. Frameworks and mobile platforms use their implementation language. Configuration-only formats have no executable CFG/DFG model. A displayed relationship does not establish a feasible attack.</p>
    <div className="flow-view-modes program-graph-kind" role="group" aria-label="Program graph kind"><button type="button" aria-pressed={query.kind === 'cfg'} onClick={() => setQuery(value => ({ ...value, kind: 'cfg' }))}>CFG · Control flow</button><button type="button" aria-pressed={query.kind === 'dfg'} onClick={() => setQuery(value => ({ ...value, kind: 'dfg' }))}>DFG · Data flow</button></div>
    <form className="program-graph-filters" onSubmit={event => { event.preventDefault(); setQuery(value => ({ ...value, search: draft, offset: 0, file_id: '', function_id: '' })) }}>
      <label>Find source file<input value={draft} maxLength={200} onChange={event => setDraft(event.target.value)} placeholder="Project-relative source path" /></label>
      <label>Language<select aria-label="Language" value={query.language} onChange={event => setQuery(value => ({ ...value, language: event.target.value, offset: 0, file_id: '', function_id: '' }))}><option value="all">All executable languages</option>{(data?.coverage || []).map(item => <option key={item.language} value={item.language}>{item.language}{item.cfg === 'not-applicable' ? ' · not executable' : ''}</option>)}</select></label>
      <button type="submit" className="btn btn-primary" disabled={loading || building}>Search files</button>
    </form>
    {!catalog ? <div className="program-graph-actions"><button type="button" className="btn btn-secondary" disabled={loading || building} onClick={rebuild}>{building ? 'Building source snapshot…' : data?.needs_rebuild ? 'Build from current source' : 'Rebuild from current source'}</button><button type="button" className="btn btn-ghost" disabled={loading || building} onClick={() => { cache.current.clear(); setRevision(value => value + 1) }}>Refresh saved graphs</button></div> : null}
    {error ? <p role="alert" className="rdl-shadow-callout warning">{error}</p> : null}
    {loading ? <p role="status">Loading saved program graph…</p> : null}
    {data?.needs_rebuild ? <p className="rdl-coverage-note">This scan has no saved CFG/DFG snapshot. Build from the allowed current source, or run a new scan with semantic or inter-file analysis enabled. A current-source build does not reconstruct historical source or change scan verdicts.</p> : null}
    {data?.available ? <>
      <p className="rdl-coverage-note"><strong>Snapshot:</strong> {data.provenance === 'current-source' ? 'Rebuilt from current source; original verdicts unchanged' : 'Recorded during scan'}{data.created_at ? ` · ${formatDateTime(data.created_at)}` : ''}. {data.summary?.files || 0} files recorded.{data.truncated ? ' Coverage is truncated by the recorded analysis budget.' : ''}</p>
      <div className="program-graph-filters"><label>Source file<select aria-label="Source file" value={query.file_id} disabled={loading || !data.files?.length} onChange={event => { const file = data.files.find(item => item.id === event.target.value); setQuery(value => ({ ...value, file_id: event.target.value, function_id: file?.functions?.find(item => item.name !== '<module>')?.id || '' })) }}><option value="">Select a source file</option>{(data.files || []).map(file => <option key={file.id} value={file.id}>{file.path} · {file.language}{file.status !== 'available' ? ` · ${file.status}` : ''}</option>)}</select></label>
        <label>Function / scope<select aria-label="Function / scope" value={query.function_id} disabled={loading || !selected} onChange={event => setQuery(value => ({ ...value, function_id: event.target.value }))}><option value="">Whole file</option>{(selected?.functions || []).map(scope => <option key={scope.id} value={scope.id}>{scope.name} · lines {scope.line}–{scope.end_line}</option>)}</select></label>
      </div>
      <div className="rdl-page-navigation"><span>{data.total || 0} matching files · page {Math.floor((data.offset || 0) / 40) + 1}</span><button type="button" disabled={loading || !query.offset} onClick={() => setQuery(value => ({ ...value, offset: Math.max(0, value.offset - 40), file_id: '', function_id: '' }))}>Previous files</button><button type="button" disabled={loading || !data.has_more} onClick={() => setQuery(value => ({ ...value, offset: value.offset + 40, file_id: '', function_id: '' }))}>Next files</button></div>
      {!data.files?.length && !loading ? <p className="rdl-coverage-note">No executable source files were recorded for this selection. Declarative configuration and unsupported or excluded files do not acquire invented execution paths.</p> : null}
      {notes.length ? <details className="program-graph-limits" open><summary>Model scope and limitations ({notes.length})</summary><ul>{notes.map(note => <li key={note}>{note}</li>)}</ul></details> : null}
      {selected && !graph && !loading ? <p className="rdl-coverage-note">The {query.kind.toUpperCase()} is unavailable for this source. Read the recorded limitations above.</p> : null}
      {graph && !loading ? <><div className="program-graph-actions"><span className="aa-pill plain">{graph.status} · {graph.model}</span><button type="button" className="btn btn-ghost" onClick={downloadJson}>Download graph JSON</button></div><ProgramGraph key={`${selected.id}:${query.function_id}:${query.kind}`} graph={graph} title={`${query.kind.toUpperCase()} · ${selected.path}`} /></> : null}
    </> : null}
    <details className="program-graph-coverage"><summary>Platform and language applicability</summary><p>Each executable profile uses the same graph contract and controls. These are bounded models, not complete compiler frontends. Embedded templates, macros, dynamic behavior and unresolved constructs retain explicit limits.</p><div className="program-table-wrap"><table><thead><tr><th>Scan platform</th><th>Executable profiles</th><th>CFG / DFG</th></tr></thead><tbody>{(data?.platforms || []).map(item => <tr key={item.platform}><td>{item.platform}</td><td>{item.languages.join(', ') || 'Configuration / paths only'}</td><td>{item.cfg} / {item.dfg}</td></tr>)}</tbody></table><table><thead><tr><th>Language / format</th><th>CFG</th><th>DFG</th><th>Scope</th></tr></thead><tbody>{(data?.coverage || []).map(item => <tr key={item.language}><td>{item.language}</td><td>{item.cfg}</td><td>{item.dfg}</td><td>{item.note}</td></tr>)}</tbody></table></div></details>
  </section>
}
