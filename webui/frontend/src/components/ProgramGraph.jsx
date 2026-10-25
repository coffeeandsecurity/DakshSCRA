import { useId, useMemo, useRef, useState } from 'react'
import { programGraphModel, programEdgePath } from '../lib/programGraphModel'

export default function ProgramGraph({ graph, title = 'Program graph' }) {
  const model = useMemo(() => programGraphModel(graph), [graph])
  const [selection, setSelection] = useState(''), [zoom, setZoom] = useState(1)
  const selected = model.nodes.find(node => node.id === selection) || model.nodes[0]
  const viewport = useRef(null), svg = useRef(null), drag = useRef(null)
  const marker = useId().replaceAll(':', '')
  function exportSvg() {
    if (!svg.current) return
    const copy = svg.current.cloneNode(true)
    copy.setAttribute('width', model.width); copy.setAttribute('height', model.height)
    const url = URL.createObjectURL(new Blob([new XMLSerializer().serializeToString(copy)], { type: 'image/svg+xml' }))
    const link = document.createElement('a'); link.href = url; link.download = `${graph.kind || 'program'}-graph.svg`; link.click()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  }
  function focusNode(id) {
    setSelection(id)
    const node = model.nodes.find(item => item.id === id), el = viewport.current
    if (node && el) { el.scrollLeft = Math.max(0, (node.x + node.width / 2) * zoom - el.clientWidth / 2); el.scrollTop = Math.max(0, node.y * zoom - 50) }
  }
  if (!model.nodes.length) return <p className="rdl-coverage-note">No modeled {graph.kind === 'cfg' ? 'control-flow statements' : 'data dependencies'} were recorded in this selection. This is not a security verdict.</p>
  return <section className="program-graph" aria-label={`${title} visualization`}>
    <div className="program-graph-tools"><strong>{title}</strong><span>{model.totalNodes} nodes · {model.totalEdges} recorded edges</span>
      <button type="button" onClick={() => setZoom(value => Math.max(.002, value / 1.25))} aria-label="Zoom out program graph">−</button><span>{Math.round(zoom * 100)}%</span><button type="button" onClick={() => setZoom(value => Math.min(2.5, value * 1.25))} aria-label="Zoom in program graph">+</button>
      <button type="button" onClick={() => setZoom(Math.max(.002, Math.min(1, (viewport.current?.clientWidth || 800) / model.width)))}>Fit graph</button>
      <button type="button" onClick={exportSvg}>Export graph SVG</button>
    </div>
    {model.truncated ? <p className="program-graph-notice" role="status">Showing {model.nodes.length} of {model.totalNodes} nodes and {model.edges.length} of {model.totalEdges} edges. Select a smaller function to inspect remaining evidence. The saved JSON retains the recorded graph.</p> : null}
    <div className="program-graph-viewport" ref={viewport} tabIndex={0} aria-label="Scrollable program graph; drag background to pan" onPointerDown={event => { if (event.target.closest('[data-program-node]')) return; const el = event.currentTarget; el.setPointerCapture(event.pointerId); drag.current = { x: event.clientX, y: event.clientY, left: el.scrollLeft, top: el.scrollTop } }} onPointerMove={event => { if (!drag.current) return; event.currentTarget.scrollLeft = drag.current.left - event.clientX + drag.current.x; event.currentTarget.scrollTop = drag.current.top - event.clientY + drag.current.y }} onPointerUp={() => { drag.current = null }} onPointerCancel={() => { drag.current = null }}>
      <svg ref={svg} xmlns="http://www.w3.org/2000/svg" width={model.width * zoom} height={model.height * zoom} viewBox={`0 0 ${model.width} ${model.height}`} role="img" aria-label={`${title}, ${model.nodes.length} nodes and ${model.edges.length} edges`}>
        <title>{title}</title><rect width="100%" height="100%" fill="#0b1422" />
        <defs><marker id={marker} markerWidth="9" markerHeight="9" refX="8" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8" fill="none" stroke="#91b4dd" strokeWidth="1.5" /></marker></defs>
        {model.edges.map(edge => <g key={edge.id}><path d={programEdgePath(edge)} fill="none" stroke={edge.kind === 'unresolved' ? '#f4c86a' : '#7396be'} strokeWidth="1.5" strokeDasharray={edge.cyclic || edge.kind === 'unresolved' ? '5 4' : undefined} markerEnd={`url(#${marker})`} /><text x={(edge.from.x + edge.from.width + edge.to.x) / 2} y={(edge.from.y + edge.to.y) / 2 + 30} fill="#c6d7eb" fontSize="10" fontFamily="monospace">{String(edge.label || edge.kind).slice(0, 34)}<title>{edge.label || edge.kind}</title></text></g>)}
        {model.nodes.map(node => <g data-program-node={node.id} key={node.id} role="button" tabIndex={0} aria-label={`${node.kind}: ${node.label}, line ${node.location?.line || 'unknown'}`} aria-pressed={node.id === selected?.id} onClick={() => setSelection(node.id)} onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); setSelection(node.id) } }}>
          <rect x={node.x} y={node.y} width={node.width} height={node.height} rx="8" fill={node.id === selected?.id ? '#24415f' : '#15263b'} stroke={node.kind === 'gap' ? '#f4c86a' : node.id === selected?.id ? '#eef6ff' : '#79a3d2'} strokeWidth={node.id === selected?.id ? 2.5 : 1} strokeDasharray={node.boundary ? '5 4' : undefined} />
          <text x={node.x + 12} y={node.y + 19} fill="#80c4fc" fontSize="10" fontFamily="monospace">{node.kind}{node.boundary ? ' · BOUNDARY' : ''}</text>
          <text x={node.x + 12} y={node.y + 42} fill="#f0f5fb" fontSize="12" fontFamily="monospace">{String(node.label).slice(0, 27)}</text>
          <text x={node.x + 12} y={node.y + 65} fill="#b2c6dc" fontSize="10" fontFamily="monospace">{String(node.location?.path || '').split('/').slice(-1)}:{node.location?.line || '—'}</text><title>{node.label}</title>
        </g>)}
      </svg>
    </div>
    <label className="program-node-select">Inspect node<select aria-label="Inspect node" value={selected?.id || ''} onChange={event => focusNode(event.target.value)}>{model.nodes.map(node => <option key={node.id} value={node.id}>{node.kind} · {node.label.slice(0, 90)} · line {node.location?.line}</option>)}</select></label>
    {selected ? <section className="program-node-evidence"><h4>{selected.kind}: {selected.label}</h4><code>{selected.location?.path}:{selected.location?.line}{selected.boundary ? ' · Cross-function boundary' : ''}</code><pre>{selected.code || 'No source excerpt was recorded for this node.'}</pre><p>These are recorded program relationships. They do not establish attacker control, feasible execution or exploitability.</p></section> : null}
    <details className="program-edge-list"><summary>Recorded edges ({model.edges.length})</summary><ol>{model.edges.map(edge => <li key={edge.id}><button type="button" onClick={() => focusNode(edge.source)}>{edge.from.label}</button> → <strong>{edge.label || edge.kind}</strong> → <button type="button" onClick={() => focusNode(edge.target)}>{edge.to.label}</button></li>)}</ol></details>
  </section>
}
