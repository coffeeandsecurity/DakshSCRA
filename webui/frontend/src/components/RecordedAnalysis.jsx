import { lazy, Suspense, useEffect, useId, useState } from 'react'
import { getScanAnalysis } from '../api'
import RetainedTab from './RetainedTab'
import RdlAdvancedAnalysis from './RdlAdvancedAnalysis'

const AdvancedAnalysis = lazy(() => import('./AdvancedAnalysis'))
const ProgramGraphsPanel = lazy(() => import('./ProgramGraphsPanel'))

const EVIDENCE_SOURCES = [
  { key: 'rules', label: 'Semantic rule paths', description: 'Follow recorded rule evidence', icon: 'M5 4h14v16H5z M8 8h8 M8 12h5 M8 16h3' },
  { key: 'analyzer', label: 'Inter-file analyzer', description: 'Trace flows across source files', icon: 'M3 5h6v6H3z M15 13h6v6h-6z M9 8h6v8 M12 13l3 3 3-3' },
  { key: 'program', label: 'CFG & DFG', description: 'Explore control and data graphs', icon: 'M9 3h6v5H9z M3 16h6v5H3z M15 16h6v5h-6z M12 8v4 M6 16v-4h12v4' },
]

function AnalyzerEvidence({ runUuid, artifactIndex }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [revision, setRevision] = useState(0)
  useEffect(() => {
    let current = true
    setLoading(true); setError('')
    getScanAnalysis(runUuid).then(result => { if (current) setData(result.analysis) })
      .catch(reason => { if (current) setError(reason.message || 'Unable to load saved analyzer evidence.') })
      .finally(() => { if (current) setLoading(false) })
    return () => { current = false }
  }, [runUuid, revision])
  if (loading) return <p role="status">Loading saved inter-file analyzer evidence…</p>
  if (error) return <div role="alert">{error} <button type="button" onClick={() => setRevision(value => value + 1)}>Retry analyzer evidence</button></div>
  if (!data) return <p className="rdl-coverage-note">No saved inter-file analyzer results are available for this scan. Enable the optional inter-file analyzer in New Scan → Analysis &amp; Output and run a new scan. This view does not rerun analysis or reconstruct deleted evidence.</p>
  return <Suspense fallback={<p role="status">Loading analyzer view…</p>}><AdvancedAnalysis analysis={data} artifactIndex={artifactIndex} initialSection="taint" /></Suspense>
}

export default function RecordedAnalysis(props) {
  const [source, setSource] = useState('rules')
  const prefix = useId()
  return <div className="recorded-analysis">
    <div className="analysis-evidence-source" role="group" aria-label="Analysis evidence source">
      {EVIDENCE_SOURCES.map(item => <button key={item.key} type="button" aria-label={item.label} aria-pressed={source === item.key} aria-controls={`${prefix}-${item.key}`} onClick={() => setSource(item.key)}>
        <span className="analysis-source-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round"><path d={item.icon} /></svg></span>
        <span className="analysis-source-copy"><strong>{item.label}</strong><span>{item.description}</span></span>
        <span className="analysis-source-state" aria-hidden="true">{source === item.key ? <><svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2"><path d="m3 8 3 3 7-7" /></svg><span>Selected</span></> : <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="m6 3 5 5-5 5" /></svg>}</span>
      </button>)}
    </div>
    <p className="rdl-coverage-note">Choose the evidence source. Semantic rules and the optional inter-file analyzer record separate results; either may have paths the other does not. A graph follows recorded evidence and does not prove runtime exploitability.</p>
    <RetainedTab active={source === 'rules'} id={`${prefix}-rules`}><RdlAdvancedAnalysis {...props} /></RetainedTab>
    <RetainedTab active={source === 'analyzer'} id={`${prefix}-analyzer`}><AnalyzerEvidence runUuid={props.runUuid} artifactIndex={props.artifactIndex} /></RetainedTab>
    <RetainedTab active={source === 'program'} id={`${prefix}-program`}><Suspense fallback={<p role="status">Loading program graph viewer…</p>}><ProgramGraphsPanel runUuid={props.runUuid} /></Suspense></RetainedTab>
  </div>
}
