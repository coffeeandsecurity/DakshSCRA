import { useEffect, useMemo, useState } from 'react'
import { artifactUrl } from '../api'

function pickDefault(index) {
  return index?.report_html || index?.xref_html || index?.other_html?.[0] || ''
}

export default function RunDetails({ run, log, artifactIndex }) {
  const [selectedArtifact, setSelectedArtifact] = useState('')

  useEffect(() => {
    setSelectedArtifact('')
  }, [run?.run_uuid])

  const allArtifacts = useMemo(() => {
    if (!artifactIndex) return []
    return [
      ...(artifactIndex.report_html ? [artifactIndex.report_html] : []),
      ...(artifactIndex.xref_html ? [artifactIndex.xref_html] : []),
      ...(artifactIndex.other_html || []),
      ...(artifactIndex.json_files || []),
      ...(artifactIndex.logs || []),
      ...(artifactIndex.pdf_files || [])
    ]
  }, [artifactIndex])

  const active = selectedArtifact || pickDefault(artifactIndex)

  if (!run) {
    return (
      <section className="panel details-panel">
        <div className="panel-head"><h2>Findings Workspace</h2></div>
        <p className="meta-row">Select a scan to inspect report, taint flow, xref and logs.</p>
      </section>
    )
  }

  return (
    <section className="panel details-panel">
      <div className="panel-head">
        <h2>{run.project_name} · {run.run_uuid}</h2>
        <span className={`badge ${run.status}`}>{run.status}</span>
      </div>

      <div className="detail-grid">
        <div><label>Project</label><code>{run.project_name}</code></div>
        <div><label>Rules</label><code>{run.rules}</code></div>
        <div><label>Target</label><code>{run.target_dir}</code></div>
        <div><label>Report</label><code>{run.report_format}</code></div>
      </div>

      <div className="artifact-picker">
        {allArtifacts.map((a) => (
          <button key={a} className={`chip-btn ${a === active ? 'active' : ''}`} onClick={() => setSelectedArtifact(a)}>
            {a.split('/').slice(-1)[0]}
          </button>
        ))}
      </div>

      {active && active.endsWith('.html') && (
        <div className="viewer-wrap">
          <iframe title="finding-viewer" className="finding-frame" src={artifactUrl(active)} />
        </div>
      )}

      {active && !active.endsWith('.html') && (
        <div className="artifact-row">
          <a className="link-btn" target="_blank" rel="noreferrer" href={artifactUrl(active)}>Open Selected Artifact</a>
        </div>
      )}

      <h3>Execution Log</h3>
      <pre className="log-pane">{log || 'No log output yet.'}</pre>
    </section>
  )
}
