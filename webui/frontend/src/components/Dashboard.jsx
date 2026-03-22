import { useState } from 'react'

function StatusBadge({ status }) {
  return (
    <span className={`badge ${status}`}>
      <span className={`badge-dot${status === 'running' ? ' pulse' : ''}`} />
      {status}
    </span>
  )
}

function ActivityChart({ data = [] }) {
  const max = Math.max(...data.map((d) => d.count), 1)
  return (
    <div className="activity-chart">
      {data.map((d) => (
        <div key={d.date} className="bar-wrap" title={`${d.date}: ${d.count} scans`}>
          <div
            className="bar-fill"
            style={{ height: `${Math.max(4, (d.count / max) * 68)}px` }}
          />
          <span className="bar-label">{d.date.slice(5)}</span>
        </div>
      ))}
    </div>
  )
}

function StatusDonut({ counts = {} }) {
  const segments = [
    { key: 'success', color: '#3fb950', label: 'Success' },
    { key: 'running', color: '#388bfd', label: 'Running' },
    { key: 'queued', color: '#8b949e', label: 'Queued' },
    { key: 'failed', color: '#f85149', label: 'Failed' },
  ]
  const total = segments.reduce((s, seg) => s + (counts[seg.key] || 0), 0)
  if (!total) {
    return (
      <div className="donut-wrap">
        <svg width="90" height="90" viewBox="0 0 90 90">
          <circle cx="45" cy="45" r="34" fill="none" stroke="#e1e4e8" strokeWidth="12" />
        </svg>
        <div className="chart-legend">
          {segments.map((s) => (
            <div key={s.key} className="legend-item">
              <span className="legend-label">
                <span className="legend-dot" style={{ background: s.color }} />
                {s.label}
              </span>
              <span className="legend-count">0</span>
            </div>
          ))}
        </div>
      </div>
    )
  }

  const r = 34
  const cx = 45
  const cy = 45
  const circumference = 2 * Math.PI * r
  let offset = 0
  const arcs = segments.map((seg) => {
    const count = counts[seg.key] || 0
    const fraction = count / total
    const dash = fraction * circumference
    const gap = circumference - dash
    const startOffset = offset
    offset += dash
    return { ...seg, count, dash, gap, startOffset }
  })

  return (
    <div className="donut-wrap">
      <div style={{ position: 'relative', flexShrink: 0 }}>
        <svg width="90" height="90" viewBox="0 0 90 90" style={{ transform: 'rotate(-90deg)' }}>
          {arcs.map((arc) =>
            arc.count > 0 ? (
              <circle
                key={arc.key}
                cx={cx}
                cy={cy}
                r={r}
                fill="none"
                stroke={arc.color}
                strokeWidth="12"
                strokeDasharray={`${arc.dash} ${arc.gap}`}
                strokeDashoffset={-arc.startOffset}
                strokeLinecap="butt"
              />
            ) : null
          )}
        </svg>
        <div style={{
          position: 'absolute', inset: 0,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexDirection: 'column', lineHeight: 1
        }}>
          <span style={{ fontSize: 20, fontWeight: 800, color: 'var(--text)' }}>{total}</span>
          <span style={{ fontSize: 9, color: 'var(--text-3)', marginTop: 2 }}>SCANS</span>
        </div>
      </div>
      <div className="chart-legend">
        {arcs.map((arc) => (
          <div key={arc.key} className="legend-item">
            <span className="legend-label">
              <span className="legend-dot" style={{ background: arc.color }} />
              {arc.label}
            </span>
            <span className="legend-count">{arc.count}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function ProjectsTable({ projects = [], onNavigate, onOpenProject, onDeleteProject }) {
  const [confirming, setConfirming] = useState(null)
  if (projects.length === 0) return null
  return (
    <div className="card">
      <div className="card-header">
        <div>
          <div className="card-title">Projects</div>
          <div className="card-subtitle">{projects.length} project{projects.length !== 1 ? 's' : ''}</div>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={() => onNavigate('projects')}>Manage →</button>
      </div>
      <div className="card-body p0">
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Project</th>
                <th>Target</th>
                <th>Rules</th>
                <th>Scans</th>
                <th>Last Scan</th>
                <th style={{ width: 40 }}></th>
              </tr>
            </thead>
            <tbody>
              {projects.map((p) => (
                <tr key={p.project_key}>
                  <td style={{ fontWeight: 600, color: 'var(--text)', cursor: 'pointer' }}
                    onClick={() => onOpenProject(p)}>
                    {p.project_name}
                    {p.running_scans > 0 && (
                      <span className="badge running" style={{ marginLeft: 8, fontSize: 10 }}>
                        <span className="badge-dot pulse" />
                        {p.running_scans} running
                      </span>
                    )}
                  </td>
                  <td className="truncate" style={{ maxWidth: 200 }} title={p.target_dir}>
                    <span className="text-muted font-mono text-sm">{p.target_dir}</span>
                  </td>
                  <td><span className="code-inline">{p.rules || '—'}</span></td>
                  <td className="text-muted">{p.total_scans}</td>
                  <td className="text-muted">{p.latest_scan_at ? new Date(p.latest_scan_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) : '—'}</td>
                  <td>
                    {confirming === p.project_key ? (
                      <div className="dash-del-confirm">
                        <button className="btn btn-danger btn-xs" onClick={() => { onDeleteProject(p.project_key); setConfirming(null) }}>Delete</button>
                        <button className="btn btn-ghost btn-xs" onClick={() => setConfirming(null)}>Cancel</button>
                      </div>
                    ) : (
                      <button
                        className="btn-icon dash-del-btn"
                        title="Delete project"
                        onClick={() => setConfirming(p.project_key)}
                      >
                        <svg width="13" height="13" viewBox="0 0 20 20" fill="currentColor">
                          <path fillRule="evenodd" d="M9 2a1 1 0 00-.894.553L7.382 4H4a1 1 0 000 2v10a2 2 0 002 2h8a2 2 0 002-2V6a1 1 0 100-2h-3.382l-.724-1.447A1 1 0 0011 2H9zM7 8a1 1 0 012 0v6a1 1 0 11-2 0V8zm5-1a1 1 0 00-1 1v6a1 1 0 102 0V8a1 1 0 00-1-1z" clipRule="evenodd" />
                        </svg>
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function niceDuration(sec) {
  if (sec == null) return '—'
  if (sec < 60) return `${Math.round(sec)}s`
  return `${Math.floor(sec / 60)}m ${Math.round(sec % 60)}s`
}

function niceDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

/* ─── localStorage keys ──────────────────────────────────────── */
const LS_UPDATE   = 'daksh_update_pref'     // { dontShowTag: string }
const LS_OFFLINE  = 'daksh_offline_pref'    // { dontShowAgain: bool, remindAfter: number }
const REMIND_MS   = 7 * 24 * 60 * 60 * 1000  // 7 days

function lsGet(key) {
  try { return JSON.parse(localStorage.getItem(key) || 'null') } catch { return null }
}
function lsSet(key, val) {
  try { localStorage.setItem(key, JSON.stringify(val)) } catch {}
}

/* ─── Version notification component ───────────────────────────
   Handles three states:
   'update'   – GitHub reachable, newer version found
   'offline'  – GitHub unreachable, current release is > 30 days old
   null       – nothing to show
────────────────────────────────────────────────────────────────── */
function VersionNotification({ versionInfo, latestRelease, githubChecked }) {
  const [dismissed, setDismissed] = useState(false)

  if (dismissed || !versionInfo) return null

  const current = String(versionInfo.version).replace(/^v/i, '').trim()
  const repoUrl = `https://github.com/${versionInfo.github_repo || 'coffeeandsecurity/DakshSCRA'}`

  /** Parse only the leading numeric portion — ignore -beta, -alpha, etc. */
  function numericVer(tag) {
    const m = String(tag).replace(/^v/i, '').match(/^[\d.]+/)
    return m ? m[0].split('.').map(Number) : [0]
  }

  /** Returns true only when b's numeric version is strictly greater than a's */
  function isNewer(current, latest) {
    const a = numericVer(current)
    const b = numericVer(latest)
    const len = Math.max(a.length, b.length)
    for (let i = 0; i < len; i++) {
      const av = a[i] ?? 0
      const bv = b[i] ?? 0
      if (bv > av) return true
      if (bv < av) return false
    }
    return false
  }

  /* ── Case 1: new version available ── */
  if (latestRelease) {
    const latest = String(latestRelease.tag).replace(/^v/i, '').trim()
    if (!latest || !isNewer(current, latest)) return null

    const latestNumericKey = numericVer(latest).join('.')
    const pref = lsGet(LS_UPDATE)
    if (pref?.dontShowTag === latestNumericKey) return null

    return (
      <div className="update-banner update-banner-new">
        <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor" className="update-banner-icon">
          <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
        </svg>
        <span className="update-banner-text">
          New version available — <strong>{latestRelease.tag}</strong>
          <span className="update-banner-sub"> (you are on v{current})</span>
        </span>
        <a href={latestRelease.url} target="_blank" rel="noreferrer" className="btn btn-sm update-banner-btn">
          View release ↗
        </a>
        <button className="btn btn-ghost btn-sm update-banner-action"
          onClick={() => { lsSet(LS_UPDATE, { dontShowTag: latestNumericKey }); setDismissed(true) }}>
          Don't show again
        </button>
        <button className="btn-icon update-banner-dismiss" onClick={() => setDismissed(true)} title="Dismiss for this session">✕</button>
      </div>
    )
  }

  /* ── Case 2: GitHub unreachable — check if release is stale ── */
  if (!githubChecked) return null   // still loading

  const releaseDate = versionInfo.release_date ? new Date(versionInfo.release_date) : null
  const ageMs = releaseDate ? (Date.now() - releaseDate.getTime()) : 0
  const THIRTY_DAYS = 30 * 24 * 60 * 60 * 1000
  if (ageMs < THIRTY_DAYS) return null   // recent release, no warning needed

  const pref = lsGet(LS_OFFLINE)
  if (pref?.dontShowAgain) return null
  if (pref?.remindAfter && Date.now() < pref.remindAfter) return null

  const ageDays = Math.floor(ageMs / (24 * 60 * 60 * 1000))

  return (
    <div className="update-banner update-banner-offline">
      <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor" className="update-banner-icon">
        <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
      </svg>
      <span className="update-banner-text">
        Unable to check for updates — no internet access.
        <span className="update-banner-sub"> Current release v{current} is {ageDays} days old. Check <a href={repoUrl + '/releases'} target="_blank" rel="noreferrer" className="update-banner-link">GitHub releases</a> manually.</span>
      </span>
      <button className="btn btn-ghost btn-sm update-banner-action"
        onClick={() => { lsSet(LS_OFFLINE, { dontShowAgain: false, remindAfter: Date.now() + REMIND_MS }); setDismissed(true) }}>
        Remind in 7 days
      </button>
      <button className="btn btn-ghost btn-sm update-banner-action"
        onClick={() => { lsSet(LS_OFFLINE, { dontShowAgain: true }); setDismissed(true) }}>
        Don't show again
      </button>
      <button className="btn-icon update-banner-dismiss" onClick={() => setDismissed(true)} title="Ignore for this session">✕</button>
    </div>
  )
}

export default function Dashboard({ metrics, projects = [], runs = [], onNavigate, onOpenProject, onDeleteProject, versionInfo, latestRelease, githubChecked }) {
  const statusCounts = {
    success: metrics?.success_scans || 0,
    running: metrics?.running_scans || 0,
    queued: metrics?.queued_scans || 0,
    failed: metrics?.failed_scans || 0,
  }

  const recentRuns = runs.slice(0, 6)

  return (
    <div>
      <VersionNotification
        versionInfo={versionInfo}
        latestRelease={latestRelease}
        githubChecked={githubChecked}
      />
      {/* Stat Cards */}
      <div className="stat-grid">
        <div className="stat-card accent-blue">
          <div className="stat-icon blue">
            <svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor">
              <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
            </svg>
          </div>
          <div className="stat-label">Projects</div>
          <div className="stat-value">{metrics?.total_projects ?? '—'}</div>
          <div className="stat-meta">Total code repositories</div>
        </div>

        <div className="stat-card accent-purple">
          <div className="stat-icon purple">
            <svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M3 4a1 1 0 011-1h3a1 1 0 011 1v3a1 1 0 01-1 1H4a1 1 0 01-1-1V4zm2 2V5h1v1H5zM3 13a1 1 0 011-1h3a1 1 0 011 1v3a1 1 0 01-1 1H4a1 1 0 01-1-1v-3zm2 2v-1h1v1H5zM13 3a1 1 0 00-1 1v3a1 1 0 001 1h3a1 1 0 001-1V4a1 1 0 00-1-1h-3zm1 2v1h1V5h-1zM11 13a1 1 0 011-1h3a1 1 0 011 1v3a1 1 0 01-1 1h-3a1 1 0 01-1-1v-3zm2 2v-1h1v1h-1z" clipRule="evenodd" />
            </svg>
          </div>
          <div className="stat-label">Total Scans</div>
          <div className="stat-value">{metrics?.total_scans ?? '—'}</div>
          <div className="stat-meta">All-time scan runs</div>
        </div>

        <div className="stat-card accent-green">
          <div className="stat-icon green">
            <svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
            </svg>
          </div>
          <div className="stat-label">Success Rate</div>
          <div className="stat-value">{metrics?.success_rate ?? 0}<span style={{ fontSize: 16 }}>%</span></div>
          <div className="stat-meta">{metrics?.success_scans || 0} successful scans</div>
        </div>

        <div className="stat-card accent-orange">
          <div className="stat-icon orange">
            <svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm1-12a1 1 0 10-2 0v4a1 1 0 00.293.707l2.828 2.829a1 1 0 101.415-1.415L11 9.586V6z" clipRule="evenodd" />
            </svg>
          </div>
          <div className="stat-label">Avg Duration</div>
          <div className="stat-value" style={{ fontSize: 22 }}>{niceDuration(metrics?.avg_duration_sec)}</div>
          <div className="stat-meta">Per scan run</div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="dashboard-grid">
        {/* Activity Chart */}
        <div className="card">
          <div className="card-header">
            <div>
              <div className="card-title">Scan Activity</div>
              <div className="card-subtitle">Last 7 days</div>
            </div>
            <button
              className="btn btn-ghost btn-sm"
              onClick={() => onNavigate('scans')}
            >
              View all →
            </button>
          </div>
          <div className="card-body">
            <ActivityChart data={metrics?.recent_daily || []} />
          </div>
        </div>

        {/* Status Distribution */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">Status Distribution</div>
          </div>
          <div className="card-body" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '20px 16px' }}>
            <StatusDonut counts={statusCounts} />
          </div>
        </div>
      </div>

      {/* Projects */}
      <ProjectsTable projects={projects} onNavigate={onNavigate} onOpenProject={onOpenProject} onDeleteProject={onDeleteProject} />

      {/* Recent Scans */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">Recent Scans</div>
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => onNavigate('scans')}
          >
            View all →
          </button>
        </div>
        <div className="card-body p0">
          {recentRuns.length === 0 ? (
            <div className="empty-state">
              <svg className="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25m18 0A2.25 2.25 0 0018.75 3H5.25A2.25 2.25 0 003 5.25m18 0H3" />
              </svg>
              <div className="empty-title">No scans yet</div>
              <div className="empty-msg">Run your first scan to start reviewing source code for security issues.</div>
            </div>
          ) : (
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Status</th>
                    <th>Project</th>
                    <th>Rules</th>
                    <th>Target</th>
                    <th>Duration</th>
                    <th>Date</th>
                  </tr>
                </thead>
                <tbody>
                  {recentRuns.map((r) => (
                    <tr
                      key={r.run_uuid}
                      onClick={() => onNavigate('scans', r)}
                    >
                      <td><StatusBadge status={r.status} /></td>
                      <td style={{ fontWeight: 600, color: 'var(--text)' }}>{r.project_name || '—'}</td>
                      <td><span className="code-inline">{r.rules}</span></td>
                      <td className="truncate" style={{ maxWidth: 260 }} title={r.target_dir}>
                        <span className="text-muted font-mono text-sm">{r.target_dir}</span>
                      </td>
                      <td className="text-muted">{niceDuration(r.duration_sec)}</td>
                      <td className="text-muted">{niceDate(r.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
