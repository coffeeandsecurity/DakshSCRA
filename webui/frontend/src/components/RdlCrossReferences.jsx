import { formatDateTime } from '../lib/datetime'
import FlowView from './FlowView'
import { createQueryCache, queryKey } from '../lib/queryCache'
import { useEffect, useId, useRef, useState } from 'react'
import { buildRdlXref, getRdlXref } from '../api'

const location = item => `${item.path}:${item.line}`
function CodeText({ text }) {
  const pieces = text.split(/(\/\/.*$|#[^\n]*$|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\b(?:class|function|def|return|public|private|static|new|const|let|var|if|else|import|from|namespace|use|void|int|String|async|await)\b|\b\d+\b)/g)
  return pieces.map((piece, index) => {
    const tone = /^(?:\/\/|#)/.test(piece) ? 'comment' : /^["']/.test(piece) ? 'string' : /^\d+$/.test(piece) ? 'number' : /^(?:class|function|def|return|public|private|static|new|const|let|var|if|else|import|from|namespace|use|void|int|String|async|await)$/.test(piece) ? 'keyword' : ''
    return tone ? <span className={`xref-code-${tone}`} key={index}>{piece}</span> : piece
  })
}

const kindLabel = { module: 'File', class: 'Class', method: 'Method', function: 'Function' }

function Source({ item, title }) {
  const id = useId()
  if (!item) return null
  return <section className="xref-source" aria-label={title}>
    <h5>{title} <span>{location(item)}</span></h5>
    <pre className="rdl-source-snippet" tabIndex={0} aria-label={`${title} source code`} id={id}>{(item.snippet || []).map(line => <span className={`rdl-code-line${line.highlight ? ' highlight' : ''}`} key={line.line}><span className="rdl-line-number">{line.line}</span><code><CodeText text={line.text} /></code></span>)}</pre>
  </section>
}

function Reference({ reference, direction, onOpen }) {
  const [expanded, setExpanded] = useState(false)
  const detailsId = useId()
  const other = direction === 'callers' ? reference.caller : reference.target
  return <div className={`xref-reference${expanded ? ' expanded' : ''}`}>
    <div className="xref-reference-head">
      <button className="xref-reference-toggle" aria-expanded={expanded} aria-controls={detailsId} onClick={() => setExpanded(value => !value)}>
        <span aria-hidden="true">{expanded ? '⌄' : '›'}</span>
        <span><strong>{other?.qualified_name || reference.callee}</strong><small>{location(reference)} · {reference.arguments.length} argument{reference.arguments.length === 1 ? '' : 's'}</small></span>
        {reference.resolution !== 'resolved' ? <span className="xref-resolution">{reference.resolution === 'ambiguous' ? 'Ambiguous' : 'Unresolved'}</span> : null}
      </button>
      {other ? <button className="xref-open" aria-label={`Open ${other.qualified_name}`} onClick={() => onOpen(other)}>Open →</button> : null}
    </div>
    {expanded ? <div id={detailsId} className="xref-reference-detail">
      <FlowView title="Call-site relationship" steps={[
        { role:'caller', file:reference.caller.path, line:reference.caller.line, symbol:reference.caller.qualified_name, snippet:reference.caller.snippet, description:'Indexed caller declaration' },
        { role:'call site', file:reference.path, line:reference.line, symbol:reference.callee, snippet:reference.snippet, description:reference.reason, transition:'call' },
        ...(reference.target ? [{ role:'callee', file:reference.target.path, line:reference.target.line, symbol:reference.target.qualified_name, snippet:reference.target.snippet, description:'Resolved callee declaration', transition:'resolved call relationship' }] : [])
      ]}>{() => <p className="xref-muted">Indexed declaration → call site{reference.target ? ' → resolved declaration' : ' → unresolved target'}. This relationship alone does not establish taint.</p>}</FlowView>
      <div className="xref-route"><button onClick={() => onOpen(reference.caller)}>{reference.caller.qualified_name}</button><span aria-hidden="true">→</span>{reference.target ? <button onClick={() => onOpen(reference.target)}>{reference.target.qualified_name}</button> : <code>{reference.callee}</code>}</div>
      <div className="xref-evidence-grid">
        <section><h5>Argument mapping</h5>{reference.arguments.length ? <div className="xref-table-scroll"><table><thead><tr><th>Argument at call site</th><th>Parameter</th></tr></thead><tbody>{reference.arguments.map((argument, index) => <tr key={index}><td><small>{index + 1}{argument.name ? ` · ${argument.name}` : ''}</small><code>{argument.expression}</code></td><td><code>{argument.parameter || 'Not resolved'}</code></td></tr>)}</tbody></table></div> : <p className="xref-muted">No explicit arguments at this call site.</p>}</section>
        <Source item={reference} title="Call site" />
      </div>
      {reference.target ? <details className="xref-definition"><summary>Definition and return details</summary><Source item={reference.target} title="Callee definition" />{reference.target.returns?.length ? <ul>{reference.target.returns.map((value, index) => <li key={index}><span>Line {value.line}</span> <code>{value.expression}</code></li>)}</ul> : <p className="xref-muted">No return statement was indexed for this declaration.</p>}</details> : null}
      <p className="xref-resolution-note">{reference.reason}</p>
      {reference.candidates?.length > 1 ? <div className="xref-candidates"><span>Possible definitions · showing {reference.candidates.length} of {reference.candidate_count || reference.candidates.length}</span>{reference.candidates.map(candidate => <button key={candidate.id} onClick={() => onOpen(candidate)}>{candidate.qualified_name} <small>{location(candidate)}</small></button>)}</div> : null}
    </div> : null}
  </div>
}

export default function RdlCrossReferences({ runUuid, onCount }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [building, setBuilding] = useState(false)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [filters, setFilters] = useState({ search: '', kind: 'all', offset: 0 })
  const [history, setHistory] = useState({ entries: [], cursor: -1 })
  const [direction, setDirection] = useState('callees')
  const [referenceOffset, setReferenceOffset] = useState(0)
  const [reload, setReload] = useState(0)
  const requestId = useRef(0)
  const cache = useRef(createQueryCache())
  const mounted = useRef(true)
  useEffect(() => { mounted.current = true; return () => { mounted.current = false } }, [])
  const inspector = useRef(null)
  const selection = history.entries[history.cursor] || ''

  useEffect(() => {
    const timer = setTimeout(() => setFilters(value => value.search === search ? value : { ...value, search, offset: 0 }), 250)
    return () => clearTimeout(timer)
  }, [search])

  useEffect(() => {
    const generation = ++requestId.current
    if (!runUuid) { setLoading(false); setError('This scan identifier is unavailable. Reopen the scan to load cross-references.'); return }
    setLoading(true); setError('')
    const options = { ...filters, symbol_id: selection, direction, reference_offset: referenceOffset }
    cache.current.get(queryKey({ runUuid, ...options }), () => getRdlXref(runUuid, options))
      .then(result => { if (generation === requestId.current) { setData(result); onCount?.(result.available ? result.summary.calls : null) } })
      .catch(reason => { if (generation === requestId.current) setError(reason.message || 'Unable to load cross-references.') })
      .finally(() => { if (generation === requestId.current) setLoading(false) })
    return () => { requestId.current += 1 }
  }, [runUuid, filters, selection, direction, referenceOffset, reload, onCount])

  function refresh() { cache.current.clear(); setReload(value => value + 1) }

  function open(item) {
    if (item.id === data?.selected?.id) return
    setHistory(value => {
      const entries = value.cursor < 0 && data?.selected ? [data.selected.id] : value.entries.slice(0, value.cursor + 1)
      return { entries: [...entries, item.id], cursor: entries.length }
    })
    setReferenceOffset(0)
    inspector.current?.focus({ preventScroll: true })
    if (window.matchMedia('(max-width: 700px)').matches) inspector.current?.scrollIntoView({ block: 'start' })
  }
  function move(delta) {
    setHistory(value => ({ ...value, cursor: value.cursor + delta }))
    setReferenceOffset(0)
  }
  async function build() {
    const generation = ++requestId.current
    setBuilding(true); setError('')
    try {
      const result = await buildRdlXref(runUuid)
      if (generation === requestId.current) { setData(result); onCount?.(result.summary.calls); refresh() }
    } catch (reason) { if (generation === requestId.current) setError(reason.message || 'Unable to build the source index.') }
    finally { if (mounted.current) { setBuilding(false); if (generation !== requestId.current) refresh() } }
  }
  const selected = data?.selected
  const groups = new Map()
  for (const item of data?.symbols || []) {
    if (!groups.has(item.path)) groups.set(item.path, [])
    groups.get(item.path).push(item)
  }
  if (loading && !data) return <div className="fr-loading" role="status">Loading source references…</div>
  return <section className="xref-browser" aria-label="Symbol cross-reference browser" aria-busy={loading || building} onKeyDown={event => {
    if (!event.altKey || loading || building) return
    const delta = event.key === 'ArrowLeft' ? -1 : event.key === 'ArrowRight' ? 1 : 0
    if (delta && history.cursor + delta >= 0 && history.cursor + delta < history.entries.length) { event.preventDefault(); move(delta) }
  }}>
    <button type="button" className="btn btn-ghost" disabled={loading || building} onClick={refresh}>Refresh cross-references</button>
    {error ? <div role="alert" className="rdl-shadow-callout warning">{error} <button disabled={building} onClick={() => refresh()}>Retry</button></div> : null}
    {!data?.available ? <div className="xref-not-indexed"><h4>This scan has no symbol index yet</h4><p>Earlier scans saved taint handoffs only. Build a separate function, method and class index to explore incoming and outgoing calls.</p><p className="xref-muted">Uses the currently available project source. Saved findings stay unchanged; this index will be dated separately from the scan.</p><button disabled={building || loading || !runUuid} onClick={build}>{building ? 'Indexing project source…' : 'Build symbol index'}</button></div> : <>
      <div className="xref-status"><span><strong>{data.summary.symbols.toLocaleString()} symbols</strong> · {data.summary.calls.toLocaleString()} calls · {data.summary.files.toLocaleString()} files</span><span>{data.provenance === 'scan' ? 'Captured during scan' : 'Current-source snapshot'} · {formatDateTime(data.created_at)}</span></div>
      {data.provenance !== 'scan' ? <p className="xref-snapshot-note">This index describes source available when it was built, which may differ from the original scan.</p> : null}
      <div className="xref-workspace">
        <aside className="xref-symbols" aria-label="Symbols">
          <h4>Symbols</h4>
          <label className="xref-search">Search symbols<input aria-label="Search symbols" placeholder="Name or file path" value={search} maxLength={200} onChange={event => setSearch(event.target.value)} /></label>
          <label className="xref-kind">Symbol kind<select aria-label="Symbol kind" value={filters.kind} onChange={event => setFilters(value => ({ ...value, kind: event.target.value, offset: 0 }))}><option value="all">All kinds</option><option value="function">Functions</option><option value="method">Methods</option><option value="class">Classes</option><option value="module">Files</option></select></label>
          <div className="xref-symbol-list" aria-busy={loading}>{[...groups].map(([path, items]) => <section key={path}><h5 title={path}>{path}</h5>{items.map(item => <button key={item.id} className={`xref-symbol${selected?.id === item.id ? ' active' : ''}`} aria-pressed={selected?.id === item.id} onClick={() => open(item)}><span className="xref-kind-icon" title={kindLabel[item.kind]}>{item.kind === 'module' ? '#' : kindLabel[item.kind]?.[0]}</span><span><strong>{item.qualified_name}</strong><small>{kindLabel[item.kind]} · line {item.line}</small></span></button>)}</section>)}{!groups.size ? <p className="xref-muted">No symbols match your search.</p> : null}</div>
          <div className="xref-list-pages"><span>{data.total} symbols</span><button aria-label="Previous symbols" disabled={!filters.offset || loading} onClick={() => setFilters(value => ({ ...value, offset: Math.max(0, value.offset - data.limit) }))}>‹</button><button aria-label="Next symbols" disabled={filters.offset + data.limit >= data.total || loading} onClick={() => setFilters(value => ({ ...value, offset: value.offset + data.limit }))}>›</button></div>
        </aside>
        <div className="xref-inspector" tabIndex={-1} ref={inspector}>
          <div className="xref-history"><button title="Back (Alt + Left)" disabled={history.cursor <= 0 || loading} onClick={() => move(-1)}>← Back</button><button title="Forward (Alt + Right)" disabled={history.cursor >= history.entries.length - 1 || loading} onClick={() => move(1)}>Forward →</button>{loading ? <span role="status">Loading…</span> : null}</div>
          {selected && !loading && !error ? <div key={selected.id}>
            <header className="xref-symbol-heading"><h4>{selected.qualified_name}</h4><p>{kindLabel[selected.kind]} · {selected.language} · <code>{location(selected)}</code></p><pre className="xref-signature">{selected.signature}</pre></header>
            {data.members?.length ? <details className="xref-members" open={selected.kind === 'class'}><summary>{data.member_total || data.members.length} member{data.members.length === 1 ? '' : 's'}</summary><div>{data.member_total > data.members.length ? <p className="xref-muted">First {data.members.length} members shown. Search symbols to find more.</p> : null}{data.members.map(member => <button key={member.id} onClick={() => open(member)}>{member.qualified_name}<small>line {member.line} →</small></button>)}</div></details> : null}
            <div className="xref-direction" role="group" aria-label="Reference direction">{['callers', 'callees'].map(value => <button key={value} aria-pressed={direction === value} className={direction === value ? 'active' : ''} onClick={() => { setDirection(value); setReferenceOffset(0) }}>{value === 'callers' ? 'Callers' : 'Callees'} <span>{selected[value]}</span></button>)}</div>
            <h5 className="xref-reference-title">{direction === 'callers' ? 'Calls into this symbol' : 'Calls made by this symbol'}</h5>
            <p className="xref-muted">{direction === 'callers' ? 'Incoming call sites with a resolved source definition.' : 'Outgoing call sites, including external and unresolved targets.'} Expand a row for arguments and source.</p>
            <div className="xref-references">{data.references?.map(reference => <Reference key={`${direction}:${reference.id}`} reference={reference} direction={direction} onOpen={open} />)}</div>
            {!data.reference_total ? <div className="xref-no-references">{selected.kind === 'class' ? 'Select a method above to inspect its callers and callees.' : direction === 'callers' ? 'No direct callers were resolved in this scan. This symbol may still be invoked through routes, framework dispatch, callbacks or dynamic calls.' : 'No outgoing calls were indexed for this symbol. It may contain no calls, or its calls may use unsupported or dynamic syntax.'}</div> : null}
            {data.reference_total > 40 ? <div className="xref-reference-pages"><span>{referenceOffset + 1}–{Math.min(referenceOffset + 40, data.reference_total)} of {data.reference_total} call sites</span><button disabled={!referenceOffset} onClick={() => setReferenceOffset(value => Math.max(0,value - 40))}>Previous</button><button disabled={referenceOffset + 40 >= data.reference_total} onClick={() => setReferenceOffset(value => value + 40)}>Next</button></div> : null}
            <details className="xref-definition"><summary>Selected declaration and source</summary><Source item={selected} title="Declaration" /></details>
          </div> : !loading && !error ? <p className="xref-muted">Select a symbol to inspect its references.</p> : null}
        </div>
      </div>
      <details className="xref-coverage"><summary>Index scope and resolution details{data.truncated || data.diagnostics.length ? ' · partial coverage' : ''}</summary><p>Static source relationships, independent of security findings. {data.summary.resolved} resolved · {data.summary.unresolved} unresolved · {data.summary.ambiguous} ambiguous calls. Parenthesized calls and supported declarations are indexed; reflection, runtime dispatch and unsupported syntax may be absent. Dependency/build folders, minified bundles and oversized files are skipped.</p>{data.truncated ? <p>The source, time or index-size limit was reached. This is a partial index.</p> : null}{data.diagnostics.length ? <ul>{data.diagnostics.map((note,index) => <li key={index}>{note}</li>)}</ul> : null}<p>Rebuilding reads current source and replaces only this reference index.</p><button disabled={building} onClick={build}>{building ? 'Indexing project source…' : 'Rebuild from current source'}</button></details>
    </>}
  </section>
}
