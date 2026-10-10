import { Component, lazy, Suspense, useId, useState } from 'react'
const FlowGraph = lazy(() => import('./FlowGraph'))
export class GraphBoundary extends Component {
  state = { failed: false }
  static getDerivedStateFromError() { return { failed: true } }
  render() { return this.state.failed ? <p role="alert">Graph could not be displayed. Switch to Text to inspect the recorded evidence.</p> : this.props.children }
}
export default function FlowView({ steps = [], blocks = [], title = 'Recorded flow', note, graphSteps, children }) {
  const [mode, setMode] = useState('text')
  const [textStep, setTextStep] = useState(0)
  const rawSteps = Array.isArray(steps) ? steps : []
  const graphicalSteps = graphSteps === undefined ? rawSteps : graphSteps
  const canGraph = Array.isArray(graphicalSteps) && graphicalSteps.length > 0
  const activeMode = canGraph ? mode : 'text'
  const total = rawSteps.length
  const start = Math.min(Math.floor(textStep / 120) * 120, Math.max(0, Math.floor((total-1)/120)*120))
  const visible = rawSteps.slice(start, start+120)
  const id = useId()
  return <section className="flow-view" aria-label={`${title} views`}>
    <div className="flow-view-heading"><div><span className="flow-view-eyebrow">FLOW EXPLORER</span><strong>{title}</strong></div><div className="flow-view-modes" role="group" aria-label="Evidence display mode"><button aria-pressed={activeMode === 'text'} aria-controls={id} onClick={() => setMode('text')}>Text</button>{canGraph && <button aria-pressed={activeMode === 'graph'} aria-controls={id} onClick={() => setMode('graph')}>Graph</button>}</div></div>
    {note && <p className="rdl-coverage-note">{note}</p>}
    <div id={id}>{activeMode === 'text' ? <>{total>120 && <div className="flow-text-pages"><span>Steps {start+1}–{Math.min(start+120,total)} of {total.toLocaleString()}</span><button disabled={start===0} onClick={()=>setTextStep(Math.max(0,start-120))}>Previous segment</button><button disabled={start+120>=total} onClick={()=>setTextStep(start+120)}>Next segment</button></div>}{typeof children === 'function' ? children({ steps:visible, start, end:Math.min(start+120,total) }) : children || <p>No text story recorded.</p>}</> : <GraphBoundary><Suspense fallback={<p role="status">Loading flow graph…</p>}><FlowGraph steps={graphicalSteps} blocks={Array.isArray(blocks) ? blocks : []} title={title} initialStep={textStep} onSelection={setTextStep}/></Suspense></GraphBoundary>}</div>
  </section>
}
