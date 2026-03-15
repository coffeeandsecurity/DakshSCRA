function niceDuration(sec) {
  if (sec === null || sec === undefined) return '-'
  if (sec < 60) return `${sec}s`
  return `${Math.floor(sec / 60)}m ${Math.round(sec % 60)}s`
}

export default function RunTable({ runs, selected, onSelect }) {
  return (
    <section className="panel runs-panel">
      <div className="panel-head">
        <h2>Recent Scans</h2>
        <span>{runs.length} items</span>
      </div>
      <div className="runs-grid header">
        <span>Status</span>
        <span>Project</span>
        <span>Rules</span>
        <span>Target</span>
        <span>Duration</span>
        <span>Open</span>
      </div>
      {runs.map((r) => (
        <button
          type="button"
          key={r.run_uuid}
          className={`runs-grid row ${selected?.run_uuid === r.run_uuid ? 'selected' : ''}`}
          onClick={() => onSelect(r)}
        >
          <span><b className={`dot ${r.status}`}></b>{r.status}</span>
          <span>{r.project_name || '-'}</span>
          <span>{r.rules}</span>
          <span className="truncate" title={r.target_dir}>{r.target_dir}</span>
          <span>{niceDuration(r.duration_sec)}</span>
          <span className="artifacts-cell">open</span>
        </button>
      ))}
    </section>
  )
}
