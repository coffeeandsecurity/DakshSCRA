import { useState } from 'react'

function niceDate(iso) {
  if (!iso) return null
  return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
}

function TrashIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 20 20" fill="currentColor">
      <path fillRule="evenodd" d="M9 2a1 1 0 00-.894.553L7.382 4H4a1 1 0 000 2v10a2 2 0 002 2h8a2 2 0 002-2V6a1 1 0 100-2h-3.382l-.724-1.447A1 1 0 0011 2H9zM7 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm5-1a1 1 0 00-1 1v6a1 1 0 102 0V8a1 1 0 00-1-1z" clipRule="evenodd" />
    </svg>
  )
}

export default function ProjectsPanel({ projects, selectedProject, onSelectProject, onNewScan, onDeleteProject }) {
  const [confirming, setConfirming] = useState(null) // project_key being confirmed

  if (projects.length === 0) {
    return (
      <div className="empty-state" style={{ paddingTop: 80 }}>
        <svg className="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
          <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 12.75V12A2.25 2.25 0 014.5 9.75h15A2.25 2.25 0 0121.75 12v.75m-8.69-6.44l-2.12-2.12a1.5 1.5 0 00-1.061-.44H4.5A2.25 2.25 0 002.25 6v12a2.25 2.25 0 002.25 2.25h15A2.25 2.25 0 0021.75 18V9a2.25 2.25 0 00-2.25-2.25h-5.379a1.5 1.5 0 01-1.06-.44z" />
        </svg>
        <div className="empty-title">No projects yet</div>
        <div className="empty-msg">Projects are created automatically when you run your first scan. Start a scan to see your projects here.</div>
        <button className="btn btn-primary" style={{ marginTop: 20 }} onClick={onNewScan}>
          + Start First Scan
        </button>
      </div>
    )
  }

  return (
    <div>
      <div className="section-header">
        <div>
          <div className="section-title">Projects</div>
          <div className="section-sub">{projects.length} project{projects.length !== 1 ? 's' : ''}</div>
        </div>
      </div>

      <div className="project-grid">
        {projects.map((p) => {
          const isConfirming = confirming === p.project_key
          return (
            <div key={p.project_key} className="project-card-wrap">
              <button
                className={`project-card${selectedProject === p.project_key ? ' selected' : ''}`}
                onClick={() => !isConfirming && onSelectProject(p.project_key)}
              >
                {/* Header */}
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8, marginBottom: 6 }}>
                  <div className="project-name">{p.project_name}</div>
                  {p.running_scans > 0 && (
                    <span className="badge running" style={{ flexShrink: 0 }}>
                      <span className="badge-dot pulse" />
                      {p.running_scans} running
                    </span>
                  )}
                </div>

                <div className="project-target" title={p.target_dir}>
                  <svg width="12" height="12" viewBox="0 0 20 20" fill="currentColor" style={{ display: 'inline', marginRight: 4, verticalAlign: 'middle', flexShrink: 0 }}>
                    <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
                  </svg>
                  {p.target_dir}
                </div>

                {/* Stats */}
                <div className="project-stats">
                  <div className="project-stat">
                    <span className="project-stat-value">{p.total_scans}</span>
                    <span className="project-stat-label">Scans</span>
                  </div>
                  {p.failed_scans > 0 && (
                    <div className="project-stat">
                      <span className="project-stat-value" style={{ color: 'var(--danger-color)' }}>{p.failed_scans}</span>
                      <span className="project-stat-label">Failed</span>
                    </div>
                  )}
                  {p.rules && (
                    <div className="project-stat" style={{ marginLeft: 'auto' }}>
                      <span className="code-inline" style={{ fontSize: 11 }}>{p.rules}</span>
                      <span className="project-stat-label">Rules</span>
                    </div>
                  )}
                </div>

                {/* Footer */}
                {p.latest_scan_at && (
                  <div className="project-footer">
                    <span>Last scan</span>
                    <span>{niceDate(p.latest_scan_at)}</span>
                  </div>
                )}
              </button>

              {/* Delete controls — outside the card button */}
              <div className="project-delete-bar">
                {isConfirming ? (
                  <div className="project-delete-confirm">
                    <span className="project-delete-confirm-text">Delete project and all scan history?</span>
                    <button
                      className="btn btn-danger btn-xs"
                      onClick={(e) => { e.stopPropagation(); onDeleteProject(p.project_key); setConfirming(null) }}
                    >
                      Delete
                    </button>
                    <button
                      className="btn btn-ghost btn-xs"
                      onClick={(e) => { e.stopPropagation(); setConfirming(null) }}
                    >
                      Cancel
                    </button>
                  </div>
                ) : (
                  <button
                    className="btn-icon project-delete-btn"
                    title="Delete project"
                    onClick={(e) => { e.stopPropagation(); setConfirming(p.project_key) }}
                  >
                    <TrashIcon />
                  </button>
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
