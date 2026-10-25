import FlowView from './FlowView'
import { useId, useMemo, useState } from 'react'
import { collectVectors, VECTOR_CATEGORIES } from '../lib/rdlVectors'
import { RdlSourceEvidence, locationLabel, shortPath } from './RdlTrace'
import { collectPaths, locationKey } from '../lib/rdlReviewModels'

export default function RdlAttackVectors({ items, onNavigate }) {
  const vectors = useMemo(() => collectVectors(items), [items])
  const [category, setCategory] = useState('all')
  const [search, setSearch] = useState('')
  const [file, setFile] = useState('all')
  const [selectedKey, setSelectedKey] = useState(null)
  const detailId = useId()
  const counts = useMemo(() => {
    const result = new Map()
    for (const vector of vectors) result.set(vector.category, (result.get(vector.category) || 0) + 1)
    return result
  }, [vectors])
  const categories = VECTOR_CATEGORIES.filter(item => counts.has(item.key))
  const categoryVectors = vectors.filter(item => category === 'all' || item.category === category)
  const files = [...new Set(categoryVectors.map(item => item.source.location?.path || ''))]
  const visible = useMemo(() => {
    const needle = search.trim().toLocaleLowerCase()
    return vectors.filter(vector => (category === 'all' || vector.category === category) && (file === 'all' || (vector.source.location?.path || '') === file) && (!needle || [vector.source.symbol, vector.source.explanation, vector.source.location?.path, vector.source.location?.line, vector.label, ...vector.items.map(item => item.finding.title)].join(' ').toLocaleLowerCase().includes(needle)))
  }, [vectors, category, file, search])
  const groupedFiles = useMemo(() => {
    const groups = new Map()
    for (const vector of visible) {
      const path = vector.source.location?.path || ''
      if (!groups.has(path)) groups.set(path, [])
      groups.get(path).push(vector)
    }
    return [...groups.entries()]
  }, [visible])
  const selected = visible.find(item => item.key === selectedKey) || visible[0]
  const review = selected?.items[0]
  const paths = selected ? collectPaths(selected.items) : []
  const destinationCount = new Set(paths.filter(path => path.sink).map(path => JSON.stringify([locationKey(path.sink.location), path.sink.symbol || path.sink.explanation]))).size
  const selectedCategory = VECTOR_CATEGORIES.find(item => item.key === selected?.category)
  function changeCategory(next) {
    setCategory(next); setFile('all'); setSelectedKey(null)
  }
  function clearFilters() {
    changeCategory('all'); setSearch('')
  }
  if (!vectors.length) return <div className="empty-state"><div className="empty-title">No input entry point recorded</div><p>These filters contain no RDL v2 source evidence. Text and path checks remain available under Review Findings / Vulnerabilities.</p></div>
  return <div className="rdl-vector-browser">
    <div className="rdl-vector-categories" role="group" aria-label="Input categories">
      <button className={`rdl-vector-category${category === 'all' ? ' active' : ''}`} aria-pressed={category === 'all'} onClick={() => changeCategory('all')}><span>All inputs</span><strong>{vectors.length}</strong></button>
      {categories.map(item => <button className={`rdl-vector-category${category === item.key ? ' active' : ''}`} aria-pressed={category === item.key} onClick={() => changeCategory(item.key)} title={item.description} key={item.key}><span>{item.label}</span><strong>{counts.get(item.key)}</strong></button>)}
    </div>
    <p className="rdl-vector-scope">Categories describe recorded input APIs on this page. Unresolved origins remain separate; external reachability still requires review.</p>
    <div className="rdl-vector-workspace">
      <aside className="rdl-vector-sidebar" aria-label="Input browser">
        <div className="rdl-vector-tools">
          <label>Search inputs<input type="search" maxLength={200} value={search} onChange={event => { setSearch(event.target.value); setSelectedKey(null) }} placeholder="Symbol, file, line or finding" /></label>
          <label>Source file<select aria-label="Source file" value={file} onChange={event => { setFile(event.target.value); setSelectedKey(null) }}><option value="all">All files ({files.length})</option>{files.map(path => <option value={path} key={path}>{path || 'Location not recorded'}</option>)}</select></label>
          <div className="rdl-vector-list-status"><span role="status">{visible.length} of {vectors.length} inputs on this page</span>{category !== 'all' || file !== 'all' || search ? <button onClick={clearFilters}>Clear filters</button> : null}</div>
        </div>
        <div className="rdl-vector-input-list" key={JSON.stringify([category, file, search])} aria-label="Recorded input entry points">{groupedFiles.map(([path, entries]) => <section className="rdl-vector-file-group" key={path}>
          <h4 title={path}><span>{shortPath(path)}</span><span>{entries.length}</span></h4>
          {entries.map(vector => <button type="button" key={vector.key} className={`rdl-vector-row${selected?.key === vector.key ? ' active' : ''}`} aria-pressed={selected?.key === vector.key} aria-controls={detailId} onClick={() => { setSelectedKey(vector.key) }}>
            <span className="rdl-vector-row-title">{vector.source.symbol || vector.source.explanation || 'Recorded input'}</span>
            <span className="rdl-vector-row-meta"><span>{vector.label}</span><span>{vector.source.location?.line ? `Line ${vector.source.location.line}` : 'No line recorded'}</span></span>
            <span className="rdl-vector-row-count">{collectPaths(vector.items).length} linked path(s)<span aria-hidden="true">→</span></span>
          </button>)}
        </section>)}</div>
      </aside>
      <div className="rdl-vector-detail" id={detailId}>
        {selected && review ? <>
          <header className="rdl-selected-vector">
            <div className="rdl-selected-vector-kind"><span className="aa-pill plain">{selectedCategory?.mark}</span><span>{selectedCategory?.label} / {selected.label}</span></div>
            <h4>{selected.source.symbol || selected.source.explanation || 'Recorded input'}</h4>
            <code className="rdl-source-location">{selected.source.location?.path || 'Location not recorded'}{selected.source.location?.line ? ':' + selected.source.location.line : ''}</code>
            <p>{selectedCategory?.description}. {paths.length} linked propagation path(s) on this page.</p>
            {selected.category === 'other' ? <p className="rdl-vector-origin-note">The recorded symbol does not establish whether this input comes from an HTTP request or another source.</p> : null}
          </header>
          <div className="rdl-input-facts"><div><strong>{paths.length}</strong><span>Recorded paths</span></div><div><strong>{destinationCount}</strong><span>Distinct destinations</span></div><div><strong>{selected.items.length}</strong><span>Evidence records</span></div></div>
          <p className="rdl-coverage-note">External reachability and request routing are not established by this input record. Inputs without a resolved origin are kept under Other inputs.</p>
          <RdlSourceEvidence finding={review.finding} step={selected.source} title="Input source evidence" />
          <section className="rdl-vector-destinations"><h4>Reachable destinations</h4><p className="rdl-coverage-note">Only destinations connected by recorded propagation are listed. Open a path to inspect every handoff.</p>
            {paths.map(path => <div className="rdl-destination-row" key={path.key}>
              <div><strong>{path.sink?.symbol || path.sink?.explanation || 'Unresolved destination'}</strong><code className="rdl-source-location">{path.sink ? locationLabel(path.sink.location) : 'Partial trace · no final sink recorded'}</code><span>{[...new Set(path.items.map(item => item.finding.title))].join(' · ')}</span></div>
              <FlowView steps={path.flow} blocks={path.items[0]?.finding.trace?.blocks || []} title="Input-to-sink path">{() => <button className="rdl-context-link" onClick={() => onNavigate('taint', path.items[0])}>Inspect full text taint flow →</button>}</FlowView>
            </div>)}
          </section>
          {selected.items.some(item => !item.record.analysis_only) ? <section className="rdl-related-findings"><h4>Review findings linked to this input</h4>{selected.items.filter(item => !item.record.analysis_only).map(item => <button className="rdl-context-link" key={item.id} onClick={() => onNavigate('findings', item)}><span className="aa-pill plain">{item.finding.severity || 'Review'}</span><span>{item.finding.title}</span><span>Review →</span></button>)}</section> : <p className="rdl-coverage-note">Recorded input evidence. Rule outcomes are available under Vulnerability Analysis.</p>}
        </> : <div className="empty-state"><div className="empty-title">No inputs match these filters</div><p>Try another symbol, source file or category.</p><button className="rdl-vector-reset" onClick={clearFilters}>Clear input filters</button></div>}
      </div>
    </div>
  </div>
}
