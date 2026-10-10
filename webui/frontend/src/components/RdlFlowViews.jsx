import FlowView from './FlowView'
import { useMemo, useState } from 'react'
import RdlTrace, { RdlSourceEvidence, locationLabel } from './RdlTrace'
import { collectPaths, collectReferences, handoffLabel } from '../lib/rdlReviewModels'

function RelatedFindings({ items, onNavigate }) {
  return <section className="rdl-related-findings"><h4>Linked review findings</h4><p className="rdl-coverage-note">Open a finding for its impact, confidence and recommended correction.</p>{items.map(item => <button key={item.id} className="rdl-context-link" onClick={() => onNavigate('findings', item)}><span className={`aa-pill severity ${String(item.finding.severity || '').toLowerCase()}`}>{item.finding.severity || 'Review'}</span><span>{item.finding.title}</span><span aria-hidden="true">→</span></button>)}</section>
}

export function TaintFlows({ items, focusId, onNavigate }) {
  const paths = useMemo(() => collectPaths(items), [items])
  const [selectedKey, setSelectedKey] = useState(null)
  const selected = paths.find(path => path.key === selectedKey) || paths.find(path => path.items.some(item => item.id === focusId)) || paths[0]
  if (!selected) return <div className="empty-state"><div className="empty-title">No taint flow recorded</div><p>A flow needs recorded source evidence. Text and path checks are available under Review Findings / Vulnerabilities.</p></div>
  const item = selected.items.find(entry => entry.id === focusId) || selected.items[0]
  return <section className="rdl-taint-view" aria-label="Source-to-sink paths">
    <p className="rdl-view-count">{paths.length} distinct {paths.length === 1 ? 'path' : 'paths'} on this page · {paths.filter(path => !path.sink).length} partial</p>
    <div className="rdl-flow-workspace">
      <div className="rdl-flow-list" aria-label="Recorded taint paths">{paths.map(path => <button className={`vg-instance-row${selected.key === path.key ? ' active' : ''}`} key={path.key} aria-pressed={selected.key === path.key} onClick={() => setSelectedKey(path.key)}>
        <strong>{path.source.symbol || path.source.explanation || 'Recorded source'}</strong><span>{locationLabel(path.source.location)}</span><span>→ {path.sink ? locationLabel(path.sink.location) : 'Unresolved destination'}</span><small>{path.sink ? 'Complete path' : 'Partial path'} · {path.flow.length} recorded actions · {path.items.length} linked finding(s)</small>
      </button>)}</div>
      <div className="rdl-flow-detail" key={selected.key}>
        <header className="rdl-purpose-heading"><h4>Source → sink path</h4><span className="aa-pill plain">{selected.sink ? 'Source and sink recorded' : 'Partial propagation'}</span></header>
        <RdlTrace finding={item.finding} />
        <RelatedFindings items={selected.items} onNavigate={onNavigate} />
      </div>
    </div>
  </section>
}

export function CrossReferences({ items, onNavigate }) {
  const references = useMemo(() => collectReferences(items), [items])
  const [selection, setSelection] = useState(null)
  const [type, setType] = useState('all')
  const visible = references.filter(edge => type === 'all' || (type === 'cross-file' ? edge.crossFile : edge.transition === type))
  const selected = visible.find(edge => edge.key === selection) || visible[0]
  if (!references.length) return <div className="empty-state"><div className="empty-title">No call or file handoff recorded</div><p>Cross-references require adjacent flow steps that change files, pass an argument into a parameter, or return to a caller.</p></div>
  const paths = selected ? collectPaths(selected.items) : []
  return <section className="rdl-xref-view" aria-label="Call and file handoffs">
    <div className="rdl-reference-tools"><p className="rdl-view-count">{visible.length} of {references.length} unique handoffs on this page</p><label>Reference type<select value={type} onChange={event => { setType(event.target.value); setSelection(null) }}><option value="all">All handoffs</option><option value="cross-file">Between files</option><option value="argument-parameter">Arguments to parameters</option><option value="return-call">Returns to callers</option></select></label></div>
    {selected ? <div className="rdl-flow-workspace">
      <div className="rdl-flow-list" aria-label="Recorded cross-references">{visible.map(edge => <button className={`vg-instance-row${selected.key === edge.key ? ' active' : ''}`} key={edge.key} aria-pressed={selected.key === edge.key} onClick={() => setSelection(edge.key)}>
        <strong>{handoffLabel(edge)}</strong><span>{locationLabel(edge.from.location)}</span><span>→ {locationLabel(edge.to.location)}</span><small>{edge.crossFile ? 'Between files' : 'Within one file'} · {edge.items.length} linked finding(s)</small>
      </button>)}</div>
      <div className="rdl-flow-detail" key={selected.key}>
        <header className="rdl-purpose-heading"><h4>{handoffLabel(selected)}</h4><span className="aa-pill plain">{selected.crossFile ? 'Cross-file' : 'Interprocedural'}</span></header>
        <p className="rdl-coverage-note">This connection is shared by {paths.length} recorded path(s). It is a code relationship, not a separate vulnerability.</p>
        <div className="rdl-reference-endpoints">{[['from', 'From · calling or returning code'], ['to', 'To · receiving code']].map(([key, label]) => <section className="rdl-reference-endpoint" key={key}>
          <span className="aa-simple-stage-title">{label}</span><strong>{locationLabel(selected[key].location)}</strong><code>{selected[key].symbol || selected[key].explanation || 'Recorded value'}</code>
          <RdlSourceEvidence finding={selected.items[0].finding} step={selected[key]} title="Code at this endpoint" />
        </section>)}</div>
        <FlowView steps={[selected.from, selected.to].filter(Boolean)} title="Recorded handoff"><p>Inspect the recorded connection and its linked paths below.</p></FlowView><section className="rdl-reference-paths"><h4>Paths using this connection</h4>{paths.map(path => <button className="rdl-context-link" key={path.key} onClick={() => onNavigate('taint', path.items[0])}><span>{locationLabel(path.source.location)} → {path.sink ? locationLabel(path.sink.location) : 'Unresolved destination'}</span><span>Open taint flow →</span></button>)}</section>
        <RelatedFindings items={selected.items} onNavigate={onNavigate} />
      </div>
    </div> : <div className="empty-state">No handoffs of this type on this page.</div>}
  </section>
}
