import { useMemo, useState } from 'react'
import { artifactUrl } from '../api'

/* ─── Confidence helpers ─────────────────────────────────────── */
const CONF_COLOR = { high: '#f85149', medium: '#d29922', low: '#3fb950', critical: '#f85149', info: '#58a6ff' }
const CONF_BG    = { high: 'rgba(248,81,73,0.09)', medium: 'rgba(210,153,34,0.09)', low: 'rgba(63,185,80,0.09)' }
const CONF_BORDER= { high: 'rgba(248,81,73,0.25)', medium: 'rgba(210,153,34,0.25)', low: 'rgba(63,185,80,0.25)' }

function ConfBadge({ level }) {
  const l = (level || 'low').toLowerCase()
  return (
    <span className="ip-conf-badge" style={{ color: CONF_COLOR[l] || '#8b949e', background: CONF_BG[l] || 'rgba(139,148,158,0.09)', border: `1px solid ${CONF_BORDER[l] || 'rgba(139,148,158,0.25)'}` }}>
      {l}
    </span>
  )
}

/* ═══════════════════════════════════════════════════════════════
   FILE PATHS SECTION
   filepaths_aoi: [{rule_title, filepath:[], confidence_score, confidence_level}]
═══════════════════════════════════════════════════════════════ */
function FilePaths({ filepaths }) {
  const [openIds, setOpenIds] = useState(new Set())
  const [search, setSearch] = useState('')

  const sorted = useMemo(() => {
    const q = search.toLowerCase()
    const list = (filepaths || []).filter((f) => {
      if (!q) return true
      return (
        (f.rule_title || '').toLowerCase().includes(q) ||
        (f.filepath || []).some((p) => p.toLowerCase().includes(q))
      )
    })
    return [...list].sort((a, b) => (b.confidence_score || 0) - (a.confidence_score || 0))
  }, [filepaths, search])

  function toggle(i) {
    setOpenIds((prev) => { const n = new Set(prev); n.has(i) ? n.delete(i) : n.add(i); return n })
  }

  if (!filepaths?.length) {
    return (
      <div className="empty-state" style={{ padding: '40px 20px' }}>
        <div className="empty-title">No file path findings</div>
        <div className="empty-msg">File path analysis matches rules against file and directory names rather than code content. No matches were found, or this scan did not run file path analysis.</div>
      </div>
    )
  }

  return (
    <div className="ip-section-body">
      <div className="ip-toolbar">
        <span className="ip-count-badge">{sorted.length} rule{sorted.length !== 1 ? 's' : ''} matched</span>
        <div className="ip-search-wrap">
          <svg width="12" height="12" viewBox="0 0 20 20" fill="currentColor" className="ip-search-icon">
            <path fillRule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clipRule="evenodd" />
          </svg>
          <input className="ip-search" placeholder="Search rules or paths…" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
      </div>

      <div className="ip-fp-list">
        {sorted.map((item, i) => {
          const paths = item.filepath || []
          const isOpen = openIds.has(i)
          return (
            <div key={i} className={`ip-fp-card${isOpen ? ' open' : ''}`} style={{ '--conf-color': CONF_COLOR[item.confidence_level?.toLowerCase()] || '#8b949e' }}>
              <button className="ip-fp-header" onClick={() => toggle(i)}>
                <ConfBadge level={item.confidence_level} />
                {item.confidence_score > 0 && <span className="ip-fp-score">{item.confidence_score}%</span>}
                <span className="ip-fp-title">{item.rule_title || `Rule #${i + 1}`}</span>
                <span className="ip-fp-count">{paths.length} file{paths.length !== 1 ? 's' : ''}</span>
                <span className="ip-caret">{isOpen ? '▲' : '▼'}</span>
              </button>
              {isOpen && paths.length > 0 && (
                <div className="ip-fp-paths">
                  {paths.map((p, pi) => (
                    <div key={pi} className="ip-fp-path">
                      <svg width="11" height="11" viewBox="0 0 20 20" fill="currentColor" style={{ color: 'var(--text-3)', flexShrink: 0 }}>
                        <path fillRule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clipRule="evenodd" />
                      </svg>
                      <span className="ip-fp-path-text">{p}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════
   RECONNAISSANCE SECTION
   recon: { meta:{...}, categories:{ CategoryName: { TechName: {...} } } }
═══════════════════════════════════════════════════════════════ */
const CATEGORY_ICONS = {
  'Backend':        <svg viewBox="0 0 20 20" fill="currentColor"><path fillRule="evenodd" d="M2 5a2 2 0 012-2h12a2 2 0 012 2v2a2 2 0 01-2 2H4a2 2 0 01-2-2V5zm14 1a1 1 0 11-2 0 1 1 0 012 0zM2 13a2 2 0 012-2h12a2 2 0 012 2v2a2 2 0 01-2 2H4a2 2 0 01-2-2v-2zm14 1a1 1 0 11-2 0 1 1 0 012 0z" clipRule="evenodd" /></svg>,
  'Frontend':       <svg viewBox="0 0 20 20" fill="currentColor"><path fillRule="evenodd" d="M3 5a2 2 0 012-2h10a2 2 0 012 2v8a2 2 0 01-2 2h-2.22l.123.489.804.804A1 1 0 0113 18H7a1 1 0 01-.707-1.707l.804-.804L7.22 15H5a2 2 0 01-2-2V5zm5.771 7H5V5h10v7H8.771z" clipRule="evenodd" /></svg>,
  'Framework':      <svg viewBox="0 0 20 20" fill="currentColor"><path d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H4a1 1 0 01-1-1v-6zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z" /></svg>,
  'Mobile':         <svg viewBox="0 0 20 20" fill="currentColor"><path fillRule="evenodd" d="M7 2a2 2 0 00-2 2v12a2 2 0 002 2h6a2 2 0 002-2V4a2 2 0 00-2-2H7zm3 14a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" /></svg>,
  'Database':       <svg viewBox="0 0 20 20" fill="currentColor"><path d="M3 12v3c0 1.657 3.134 3 7 3s7-1.343 7-3v-3c0 1.657-3.134 3-7 3s-7-1.343-7-3z" /><path d="M3 7v3c0 1.657 3.134 3 7 3s7-1.343 7-3V7c0 1.657-3.134 3-7 3S3 8.657 3 7z" /><path d="M17 5c0 1.657-3.134 3-7 3S3 6.657 3 5s3.134-3 7-3 7 1.343 7 3z" /></svg>,
  'Infrastructure': <svg viewBox="0 0 20 20" fill="currentColor"><path fillRule="evenodd" d="M2 5a2 2 0 012-2h12a2 2 0 012 2v2a2 2 0 01-2 2H4a2 2 0 01-2-2V5zm14 1a1 1 0 11-2 0 1 1 0 012 0zM2 13a2 2 0 012-2h12a2 2 0 012 2v2a2 2 0 01-2 2H4a2 2 0 01-2-2v-2zm14 1a1 1 0 11-2 0 1 1 0 012 0z" clipRule="evenodd" /></svg>,
}

function defaultIcon() {
  return <svg viewBox="0 0 20 20" fill="currentColor"><path fillRule="evenodd" d="M3 3a1 1 0 000 2v8a2 2 0 002 2h2.586l-1.293 1.293a1 1 0 101.414 1.414L10 15.414l2.293 2.293a1 1 0 001.414-1.414L12.414 15H15a2 2 0 002-2V5a1 1 0 100-2H3zm11 4a1 1 0 10-2 0v4a1 1 0 102 0V7zm-3 1a1 1 0 10-2 0v3a1 1 0 102 0V8zM8 9a1 1 0 00-2 0v2a1 1 0 102 0V9z" clipRule="evenodd" /></svg>
}

function confDots(counts) {
  const total = (counts?.high || 0) + (counts?.medium || 0) + (counts?.low || 0)
  if (!total) return null
  return (
    <div className="ip-conf-dots">
      {counts.high > 0 && <span className="ip-dot" style={{ background: CONF_COLOR.high }} title={`${counts.high} high-confidence`} />}
      {counts.medium > 0 && <span className="ip-dot" style={{ background: CONF_COLOR.medium }} title={`${counts.medium} medium`} />}
      {counts.low > 0 && <span className="ip-dot" style={{ background: CONF_COLOR.low }} title={`${counts.low} low`} />}
      <span className="ip-dot-total">{total}</span>
    </div>
  )
}

function ReconTechCard({ name, data }) {
  const [expanded, setExpanded] = useState(false)
  const dom = (data.dominantConfidence || 'low').toLowerCase()
  const dirs = data.directories || []
  const samples = data.sampleFiles || []
  const showFiles = expanded ? samples : samples.slice(0, 2)

  return (
    <div className="ip-tech-card" style={{ '--dom-color': CONF_COLOR[dom] || '#8b949e' }}>
      <div className="ip-tech-header">
        <div className="ip-tech-name">{name}</div>
        <div className="ip-tech-meta">
          {confDots(data.confidenceCounts)}
          <span className="ip-tech-files">{data.totalFiles || 0} file{data.totalFiles !== 1 ? 's' : ''}</span>
          <ConfBadge level={dom} />
        </div>
      </div>

      {dirs.length > 0 && (
        <div className="ip-tech-dirs">
          {dirs.slice(0, expanded ? dirs.length : 2).map((d, i) => (
            <div key={i} className="ip-tech-dir">
              <svg width="10" height="10" viewBox="0 0 20 20" fill="currentColor" style={{ color: 'var(--text-3)', flexShrink: 0 }}>
                <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
              </svg>
              <span className="ip-tech-dir-path">{String(d.directory || d).split(/[\\/]/).slice(-3).join('/')}</span>
              {d.fileCount != null && <span className="ip-tech-dir-count">{d.fileCount}</span>}
            </div>
          ))}
        </div>
      )}

      {samples.length > 0 && (
        <div className="ip-tech-samples">
          {showFiles.map((f, i) => (
            <span key={i} className="ip-sample-chip">{String(f).split(/[\\/]/).slice(-1)[0]}</span>
          ))}
          {samples.length > 2 && (
            <button className="ip-expand-btn" onClick={() => setExpanded((v) => !v)}>
              {expanded ? 'less' : `+${samples.length - 2} more`}
            </button>
          )}
        </div>
      )}
    </div>
  )
}

function Recon({ recon }) {
  const categories = recon?.categories || recon  // support both {categories:{...}} and raw {...} shapes

  if (!categories || !Object.keys(categories).filter((k) => k !== 'meta').length) {
    return (
      <div className="empty-state" style={{ padding: '40px 20px' }}>
        <div className="empty-title">No reconnaissance data</div>
        <div className="empty-msg">Enable <strong>Reconnaissance</strong> in scan options to detect technologies, frameworks, and file distributions before scanning.</div>
      </div>
    )
  }

  const catEntries = Object.entries(categories).filter(([k]) => k !== 'meta' && typeof categories[k] === 'object')
  const meta = recon?.meta

  return (
    <div className="ip-section-body">
      {/* Meta strip */}
      {meta && (
        <div className="ip-recon-meta">
          {meta.recon_target_directory && (
            <div className="ip-meta-item">
              <span className="ip-meta-label">Target</span>
              <span className="ip-meta-val">{meta.recon_target_directory}</span>
            </div>
          )}
          {meta.generated_at && (
            <div className="ip-meta-item">
              <span className="ip-meta-label">Generated</span>
              <span className="ip-meta-val">{meta.generated_at}</span>
            </div>
          )}
        </div>
      )}

      {catEntries.map(([catName, techs]) => {
        const techEntries = Object.entries(techs || {})
        if (!techEntries.length) return null
        const icon = CATEGORY_ICONS[catName] || defaultIcon()
        return (
          <div key={catName} className="ip-recon-category">
            <div className="ip-cat-header">
              <span className="ip-cat-icon">{icon}</span>
              <span className="ip-cat-name">{catName}</span>
              <span className="ip-cat-count">{techEntries.length} detected</span>
            </div>
            <div className="ip-tech-grid">
              {techEntries.map(([techName, techData]) => (
                <ReconTechCard key={techName} name={techName} data={techData} />
              ))}
            </div>
          </div>
        )
      })}
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════
   EFFORT ESTIMATE SECTION
═══════════════════════════════════════════════════════════════ */
function EffortEstimate({ artifactIndex, ranEstimate }) {
  const estimateArtifacts = useMemo(() => {
    const all = [
      ...(artifactIndex?.other_html || []),
      ...(artifactIndex?.pdf_files || []),
    ]
    return all.filter((a) => a.toLowerCase().includes('estimate'))
  }, [artifactIndex])

  if (!ranEstimate && !estimateArtifacts.length) {
    return (
      <div className="empty-state" style={{ padding: '40px 20px' }}>
        <svg className="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <div className="empty-title">Effort estimate not run</div>
        <div className="empty-msg">Enable <strong>Effort Estimate</strong> in scan options to generate a manual review effort estimate based on findings complexity and volume.</div>
      </div>
    )
  }

  if (!estimateArtifacts.length) {
    return (
      <div className="empty-state" style={{ padding: '40px 20px' }}>
        <div className="empty-title">Estimate report not yet available</div>
        <div className="empty-msg">The scan ran with effort estimation enabled. The report may still be generating, or was not saved to the output directory.</div>
      </div>
    )
  }

  return (
    <div className="ip-section-body">
      <div className="ip-estimate-intro">
        <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor" style={{ color: 'var(--primary)', flexShrink: 0 }}>
          <path fillRule="evenodd" d="M6 2a1 1 0 00-1 1v1H4a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2h-1V3a1 1 0 10-2 0v1H7V3a1 1 0 00-1-1zm0 5a1 1 0 000 2h8a1 1 0 100-2H6z" clipRule="evenodd" />
        </svg>
        <span>Effort estimate reports show estimated manual review days broken down by language and component.</span>
      </div>

      <div className="ip-estimate-list">
        {estimateArtifacts.map((a) => {
          const name = a.split('/').slice(-1)[0]
          const isPdf = a.toLowerCase().endsWith('.pdf')
          return (
            <div key={a} className="ip-estimate-card">
              <div className="ip-estimate-card-icon">
                {isPdf ? (
                  <svg width="28" height="28" viewBox="0 0 20 20" fill="currentColor" style={{ color: '#f85149' }}>
                    <path fillRule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4zm2 6a1 1 0 011-1h6a1 1 0 110 2H7a1 1 0 01-1-1zm1 3a1 1 0 100 2h6a1 1 0 100-2H7z" clipRule="evenodd" />
                  </svg>
                ) : (
                  <svg width="28" height="28" viewBox="0 0 20 20" fill="currentColor" style={{ color: 'var(--primary)' }}>
                    <path fillRule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clipRule="evenodd" />
                  </svg>
                )}
              </div>
              <div className="ip-estimate-card-info">
                <div className="ip-estimate-card-name">{name}</div>
                <div className="ip-estimate-card-path">{a}</div>
              </div>
              <div className="ip-estimate-card-actions">
                <a href={artifactUrl(a)} target="_blank" rel="noreferrer" className="btn btn-primary btn-sm">
                  Open Report ↗
                </a>
                <a href={artifactUrl(a)} download className="btn btn-ghost btn-sm">Download</a>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════
   LINES OF CODE SECTION
   loc_breakdown: string[] | {path, loc}[]
   scan_meta.detection_summary: {total_loc, total_files_scanned, ...}
═══════════════════════════════════════════════════════════════ */
function LoCSection({ locBreakdown, scanMeta }) {
  const [search, setSearch] = useState('')
  const [sortBy, setSortBy] = useState('loc')   // 'loc' | 'path'
  const [sortDir, setSortDir] = useState('desc')
  const [page, setPage] = useState(0)
  const PAGE_SIZE = 100

  const det = scanMeta?.detection_summary || {}
  const totalLoc = det.total_loc != null ? Number(det.total_loc) : null
  const totalFiles = det.total_files_scanned ?? det.total_files_identified
  const hasLocData = Array.isArray(locBreakdown) && locBreakdown.length > 0 && typeof locBreakdown[0] === 'object'

  const rows = useMemo(() => {
    if (!hasLocData) return []
    const q = search.toLowerCase()
    const filtered = locBreakdown.filter((r) => !q || r.path.toLowerCase().includes(q))
    const sorted = [...filtered].sort((a, b) => {
      if (sortBy === 'loc') return sortDir === 'desc' ? (b.loc - a.loc) : (a.loc - b.loc)
      const ap = (a.path || '').toLowerCase()
      const bp = (b.path || '').toLowerCase()
      return sortDir === 'desc' ? bp.localeCompare(ap) : ap.localeCompare(bp)
    })
    return sorted
  }, [locBreakdown, search, sortBy, sortDir, hasLocData])

  function toggleSort(col) {
    if (sortBy === col) setSortDir((d) => d === 'desc' ? 'asc' : 'desc')
    else { setSortBy(col); setSortDir('desc') }
    setPage(0)
  }

  const pageRows = rows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)
  const totalPages = Math.ceil(rows.length / PAGE_SIZE)

  if (!hasLocData && totalLoc == null) {
    return (
      <div className="empty-state" style={{ padding: '40px 20px' }}>
        <svg className="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
          <path strokeLinecap="round" strokeLinejoin="round" d="M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 16.5" />
        </svg>
        <div className="empty-title">Lines of Code not counted</div>
        <div className="empty-msg">Enable <strong>Count Lines of Code</strong> in scan options to see per-file LoC breakdown and totals.</div>
      </div>
    )
  }

  return (
    <div className="ip-section-body">
      {/* Summary stats strip */}
      <div className="ip-loc-stats">
        {totalFiles != null && (
          <div className="ip-loc-stat">
            <span className="ip-loc-stat-val">{Number(totalFiles).toLocaleString()}</span>
            <span className="ip-loc-stat-label">Files Scanned</span>
          </div>
        )}
        {totalLoc != null && (
          <div className="ip-loc-stat">
            <span className="ip-loc-stat-val">{Number(totalLoc).toLocaleString()}</span>
            <span className="ip-loc-stat-label">Total Effective LoC</span>
          </div>
        )}
        {hasLocData && totalLoc > 0 && (
          <div className="ip-loc-stat">
            <span className="ip-loc-stat-val">{Math.round(totalLoc / locBreakdown.length).toLocaleString()}</span>
            <span className="ip-loc-stat-label">Avg LoC / File</span>
          </div>
        )}
      </div>

      {hasLocData && (
        <>
          <div className="ip-toolbar" style={{ marginTop: 12 }}>
            <span className="ip-count-badge">{rows.length} file{rows.length !== 1 ? 's' : ''}{search ? ' matched' : ''}</span>
            <div className="ip-search-wrap">
              <svg width="12" height="12" viewBox="0 0 20 20" fill="currentColor" className="ip-search-icon">
                <path fillRule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clipRule="evenodd" />
              </svg>
              <input className="ip-search" placeholder="Filter by file path…" value={search} onChange={(e) => { setSearch(e.target.value); setPage(0) }} />
            </div>
          </div>

          <div className="ip-loc-table-wrap">
            <table className="ip-loc-table">
              <thead>
                <tr>
                  <th className="ip-loc-th ip-loc-th-path" onClick={() => toggleSort('path')} style={{ cursor: 'pointer' }}>
                    File Path {sortBy === 'path' ? (sortDir === 'desc' ? '▼' : '▲') : ''}
                  </th>
                  <th className="ip-loc-th ip-loc-th-loc" onClick={() => toggleSort('loc')} style={{ cursor: 'pointer' }}>
                    Eff. LoC {sortBy === 'loc' ? (sortDir === 'desc' ? '▼' : '▲') : ''}
                  </th>
                </tr>
              </thead>
              <tbody>
                {pageRows.map((r, i) => (
                  <tr key={i} className="ip-loc-row">
                    <td className="ip-loc-td ip-loc-path">{r.path}</td>
                    <td className="ip-loc-td ip-loc-val">{r.loc?.toLocaleString() ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
            <div className="ip-loc-pagination">
              <button className="btn btn-ghost btn-sm" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>← Prev</button>
              <span className="text-sm text-muted">Page {page + 1} of {totalPages}</span>
              <button className="btn btn-ghost btn-sm" disabled={page >= totalPages - 1} onClick={() => setPage((p) => p + 1)}>Next →</button>
            </div>
          )}
        </>
      )}
    </div>
  )
}

/* ═══════════════════════════════════════════════════════════════
   MAIN InsightsPanel
═══════════════════════════════════════════════════════════════ */
const SECTIONS = [
  {
    id: 'filepaths',
    label: 'File Paths',
    icon: (
      <svg viewBox="0 0 20 20" fill="currentColor">
        <path fillRule="evenodd" d="M2 6a2 2 0 012-2h4l2 2h4a2 2 0 012 2v1H8a3 3 0 00-3 3v1.5a1.5 1.5 0 01-3 0V6z" clipRule="evenodd" />
        <path d="M6 12a2 2 0 012-2h8a2 2 0 012 2v2a2 2 0 01-2 2H2h2a2 2 0 002-2v-2z" />
      </svg>
    ),
  },
  {
    id: 'recon',
    label: 'Reconnaissance',
    icon: (
      <svg viewBox="0 0 20 20" fill="currentColor">
        <path d="M10 12a2 2 0 100-4 2 2 0 000 4z" />
        <path fillRule="evenodd" d="M.458 10C1.732 5.943 5.522 3 10 3s8.268 2.943 9.542 7c-1.274 4.057-5.064 7-9.542 7S1.732 14.057.458 10zM14 10a4 4 0 11-8 0 4 4 0 018 0z" clipRule="evenodd" />
      </svg>
    ),
  },
  {
    id: 'estimate',
    label: 'Effort Estimate',
    icon: (
      <svg viewBox="0 0 20 20" fill="currentColor">
        <path fillRule="evenodd" d="M6 2a1 1 0 00-1 1v1H4a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2h-1V3a1 1 0 10-2 0v1H7V3a1 1 0 00-1-1zm0 5a1 1 0 000 2h8a1 1 0 100-2H6z" clipRule="evenodd" />
      </svg>
    ),
  },
  {
    id: 'loc',
    label: 'Lines of Code',
    icon: (
      <svg viewBox="0 0 20 20" fill="currentColor">
        <path fillRule="evenodd" d="M12.316 3.051a1 1 0 01.633 1.265l-4 12a1 1 0 11-1.898-.632l4-12a1 1 0 011.265-.633zM5.707 6.293a1 1 0 010 1.414L3.414 10l2.293 2.293a1 1 0 11-1.414 1.414l-3-3a1 1 0 010-1.414l3-3a1 1 0 011.414 0zm8.586 0a1 1 0 011.414 0l3 3a1 1 0 010 1.414l-3 3a1 1 0 11-1.414-1.414L16.586 10l-2.293-2.293a1 1 0 010-1.414z" clipRule="evenodd" />
      </svg>
    ),
  },
]

export default function InsightsPanel({ findingsData, artifactIndex, run }) {
  const [activeSection, setActiveSection] = useState('filepaths')

  const filepaths = findingsData?.filepaths || []
  const recon = findingsData?.recon
  const ranEstimate = run?.estimate
  const locBreakdown = findingsData?.loc_breakdown || []
  const scanMeta = findingsData?.scan_meta
  const hasLoc = run?.loc || (scanMeta?.detection_summary?.total_loc != null)

  const counts = {
    filepaths: filepaths.length,
    recon: recon ? Object.keys(recon.categories || recon).filter((k) => k !== 'meta').length : 0,
    estimate: (artifactIndex?.other_html || []).filter((a) => a.toLowerCase().includes('estimate')).length
      + (artifactIndex?.pdf_files || []).filter((a) => a.toLowerCase().includes('estimate')).length,
    loc: locBreakdown.filter((r) => typeof r === 'object').length,
  }

  return (
    <div className="ip-root">
      {/* Section nav */}
      <div className="ip-nav">
        {SECTIONS.map(({ id, label, icon }) => {
          const count = counts[id]
          const hasData = count > 0 || (id === 'estimate' && ranEstimate) || (id === 'loc' && hasLoc)
          return (
            <button
              key={id}
              className={`ip-nav-btn${activeSection === id ? ' active' : ''}${!hasData && id !== activeSection ? ' dim' : ''}`}
              onClick={() => setActiveSection(id)}
            >
              <span className="ip-nav-icon">{icon}</span>
              <span className="ip-nav-label">{label}</span>
              {count > 0 && <span className="ip-nav-count">{count}</span>}
              {id === 'estimate' && ranEstimate && count === 0 && (
                <span className="ip-nav-dot" title="Estimate was run" />
              )}
              {id === 'loc' && hasLoc && count === 0 && (
                <span className="ip-nav-dot" title="LoC counted" />
              )}
            </button>
          )
        })}
      </div>

      {/* Content */}
      <div className="ip-content">
        {activeSection === 'filepaths' && <FilePaths filepaths={filepaths} />}
        {activeSection === 'recon' && <Recon recon={recon} />}
        {activeSection === 'estimate' && (
          <EffortEstimate artifactIndex={artifactIndex} ranEstimate={ranEstimate} />
        )}
        {activeSection === 'loc' && (
          <LoCSection locBreakdown={locBreakdown} scanMeta={scanMeta} />
        )}
      </div>
    </div>
  )
}
