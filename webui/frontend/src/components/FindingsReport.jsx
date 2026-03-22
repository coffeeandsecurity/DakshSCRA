import { useMemo, useState } from 'react'

/* ─── Confidence helpers ─────────────────────────────────────── */
const CONF_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown']

function confLevel(finding) {
  return (finding.confidence_level || '').toLowerCase() || 'unknown'
}

function confScore(finding) {
  return finding.confidence_score ?? 0
}

function confClass(level) {
  const map = {
    critical: 'fr-badge critical',
    high: 'fr-badge high',
    medium: 'fr-badge medium',
    low: 'fr-badge low',
    info: 'fr-badge info',
  }
  return map[level] || 'fr-badge unknown'
}

function confColor(level) {
  const map = {
    critical: '#f85149',
    high: '#e3842a',
    medium: '#d29922',
    low: '#3fb950',
    info: '#58a6ff',
    unknown: '#8b949e',
  }
  return map[level] || '#8b949e'
}

/* ─── Stat card ──────────────────────────────────────────────── */
function StatCard({ label, value, color, icon }) {
  return (
    <div className="fr-stat-card" style={{ '--stat-color': color }}>
      <div className="fr-stat-icon">{icon}</div>
      <div>
        <div className="fr-stat-value">{value}</div>
        <div className="fr-stat-label">{label}</div>
      </div>
    </div>
  )
}

/* ─── Distribution bar ───────────────────────────────────────── */
function DistributionBar({ counts, total }) {
  if (!total) return null
  const levels = CONF_ORDER.filter((l) => counts[l] > 0)
  return (
    <div className="fr-dist-wrap">
      <div className="fr-dist-bar">
        {levels.map((l) => (
          <div
            key={l}
            className="fr-dist-segment"
            style={{ width: `${(counts[l] / total) * 100}%`, background: confColor(l) }}
            title={`${l}: ${counts[l]}`}
          />
        ))}
      </div>
      <div className="fr-dist-legend">
        {levels.map((l) => (
          <span key={l} className="fr-dist-item">
            <span className="fr-dist-dot" style={{ background: confColor(l) }} />
            <span className="fr-dist-label-text">{l}</span>
            <span className="fr-dist-count">{counts[l]}</span>
          </span>
        ))}
      </div>
    </div>
  )
}

/* ─── Code snippet block ─────────────────────────────────────── */
function FileIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 20 20" fill="currentColor" style={{ color: 'var(--text-3)', flexShrink: 0 }}>
      <path fillRule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4zm5 5a1 1 0 10-2 0v3a1 1 0 102 0V9z" clipRule="evenodd" />
    </svg>
  )
}

function CodeViewer({ lines, matchLineNums }) {
  if (!lines.length) return null
  const maxLen = String(Math.max(...lines.map(l => l.line || 0))).length
  return (
    <div className="fr-code-viewer">
      {lines.map((l, i) => {
        const isMatch = matchLineNums.has(l.line)
        return (
          <div key={i} className={`fr-cv-row${isMatch ? ' fr-cv-match' : ''}`}>
            <span className="fr-cv-ln">{l.line != null ? String(l.line).padStart(maxLen) : ''}</span>
            <code className="fr-cv-code">{l.code}</code>
          </div>
        )
      })}
    </div>
  )
}

function CodeEvidence({ evidence }) {
  if (!evidence?.length) return null
  return (
    <div className="fr-evidence-list">
      {evidence.map((e, i) => {
        let lines, matchLineNums
        if (e.aggregated) {
          lines = (e.matches || []).map(m => ({ line: m.line, code: m.code }))
          matchLineNums = new Set(lines.map(l => l.line))
        } else {
          lines = [
            ...(e.context_before || []),
            { line: e.line, code: e.code },
            ...(e.context_after || []),
          ]
          matchLineNums = new Set([e.line])
        }
        return (
          <div key={i} className="fr-evidence-item">
            <div className="fr-evidence-header">
              <FileIcon />
              <span className="fr-evidence-file">{e.file || '—'}</span>
              {!e.aggregated && e.line && <span className="fr-evidence-line">:{e.line}</span>}
            </div>
            <CodeViewer lines={lines} matchLineNums={matchLineNums} />
          </div>
        )
      })}
    </div>
  )
}

function buildAnalyzerReviewIndex(analysis) {
  const out = new Map()
  for (const result of analysis?.results || []) {
    for (const review of result?.security_inventory?.finding_reviews || []) {
      const key = [
        review.platform || result.platform || '',
        review.rule_title || '',
        review.rule_id || '',
      ].join('::').toLowerCase()
      out.set(key, review)
    }
  }
  return out
}

/* ─── Single area-of-interest card ───────────────────────────── */
function FindingCard({ finding, index, open, onToggle, review, onViewAnalysis }) {
  const level = confLevel(finding)
  const score = confScore(finding)
  const showAnalysisLink = review?.status === 'confirmed_vulnerability' && onViewAnalysis
  const logicEngine = finding.logic_engine || ''
  const logicTrace = Array.isArray(finding.logic_trace) ? finding.logic_trace : []
  const consultedFiles = Array.isArray(finding.logic_consulted_files) ? finding.logic_consulted_files : []
  return (
    <div className={`fr-card${open ? ' open' : ''}`} style={{ '--conf-color': confColor(level) }}>
      <button className="fr-card-header" onClick={onToggle}>
        <span className={confClass(level)}>{level}</span>
        {score > 0 && <span className="fr-score">{score}%</span>}
        <span className="fr-card-title">{finding.rule_title || finding.rule_id || `Area of Interest #${index + 1}`}</span>
        {finding.category && <span className="fr-category-chip">{finding.category}</span>}
        {finding.platform && <span className="fr-platform-chip">{finding.platform}</span>}
        {logicEngine ? <span className="fr-platform-chip">{logicEngine.toUpperCase()}</span> : null}
        {review?.status === 'confirmed_vulnerability' && <span className="fr-platform-chip">Confirmed Vulnerability</span>}
        {showAnalysisLink ? (
          <span
            className="fr-platform-chip"
            onClick={(e) => {
              e.stopPropagation()
              onViewAnalysis()
            }}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault()
                e.stopPropagation()
                onViewAnalysis()
              }
            }}
            style={{ cursor: 'pointer' }}
            title="Open confirmed vulnerability analysis"
          >
            View Analysis
          </span>
        ) : null}
        {review?.status === 'suppressed_false_positive' && <span className="fr-category-chip">Suppressed False Positive</span>}
        {review?.status === 'manual_review_recommended' && <span className="fr-category-chip">Manual Inspection Recommended</span>}
        <span className="fr-card-caret">{open ? '▲' : '▼'}</span>
      </button>

      {open && (
        <div className="fr-card-body">
          {review?.technical_rationale ? (
            <div className="fr-note rev">
              <div className="fr-note-label">Analyzer Review</div>
              <div className="fr-note-text">{review.technical_rationale}</div>
              {showAnalysisLink ? (
                <div style={{ marginTop: 10 }}>
                  <button className="btn btn-sm btn-secondary" onClick={onViewAnalysis}>
                    View Vulnerability Analysis
                  </button>
                </div>
              ) : null}
            </div>
          ) : null}

          {finding.issue_desc && (
            <p className="fr-issue-desc">{finding.issue_desc}</p>
          )}

          {(finding.logic_reason || logicTrace.length || consultedFiles.length) ? (
            <div className="fr-note logic">
              <div className="fr-note-label">Rule Logic{logicEngine ? ` (${logicEngine.toUpperCase()})` : ''}</div>
              {finding.logic_reason ? <div className="fr-note-text">{finding.logic_reason}</div> : null}
              {logicTrace.length ? (
                <div className="fr-logic-list">
                  {logicTrace.map((entry, idx) => <div key={idx} className="fr-note-text">{entry}</div>)}
                </div>
              ) : null}
              {consultedFiles.length ? (
                <div className="fr-note-text">Consulted files: {consultedFiles.join(', ')}</div>
              ) : null}
            </div>
          ) : null}

          <CodeEvidence evidence={finding.evidence} />

          {(finding.developer_note || finding.reviewer_note) && (
            <div className="fr-notes-row">
              {finding.developer_note && (
                <div className="fr-note dev">
                  <div className="fr-note-label">Developer Note</div>
                  <div className="fr-note-text">{finding.developer_note}</div>
                </div>
              )}
              {finding.reviewer_note && (
                <div className="fr-note rev">
                  <div className="fr-note-label">Reviewer Note</div>
                  <div className="fr-note-text">{finding.reviewer_note}</div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

/* ─── File heatmap section ───────────────────────────────────── */
function FileHeatmap({ findings }) {
  const fileMap = useMemo(() => {
    const m = {}
    for (const f of findings) {
      for (const e of (f.evidence || [])) {
        if (e.file) {
          m[e.file] = (m[e.file] || 0) + 1
        }
      }
    }
    return Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 15)
  }, [findings])

  if (!fileMap.length) return null
  const maxCount = fileMap[0]?.[1] || 1

  return (
    <div className="fr-section">
      <div className="fr-section-title" style={{ padding: '0 0 10px' }}>
        <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor" style={{ color: 'var(--primary)' }}>
          <path fillRule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clipRule="evenodd" />
        </svg>
        Top Files by Areas of Interest
      </div>
      <div className="fr-heatmap">
        {fileMap.map(([file, count]) => {
          const pct = (count / maxCount) * 100
          const shortFile = file.split('/').slice(-2).join('/')
          return (
            <div key={file} className="fr-heatmap-row" title={file}>
              <div className="fr-heatmap-file">{shortFile}</div>
              <div className="fr-heatmap-bar-wrap">
                <div className="fr-heatmap-bar" style={{ width: `${pct}%` }} />
              </div>
              <div className="fr-heatmap-count">{count}</div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

/* ─── Scan metadata panel ────────────────────────────────────── */
function ScanMeta({ summary, scanMeta }) {
  const src = summary || scanMeta
  if (!src) return null

  const timeline = src.scanning_timeline || {}
  const detection = src.detection_summary || {}
  const sources = src.source_files_scanning_summary || {}

  const items = [
    { label: 'Total Files Scanned', value: sources.total_files_scanned ?? detection.total_files_scanned },
    { label: 'Files with Areas of Interest', value: detection.files_with_aoi },
    { label: 'Rules Applied', value: detection.rules_applied },
    { label: 'Scan Duration', value: timeline.scan_completed_in },
    { label: 'Start Time', value: timeline.scan_start_time },
    { label: 'End Time', value: timeline.scan_end_time },
  ].filter((i) => i.value != null)

  if (!items.length) return null

  return (
    <div className="fr-meta-grid">
      {items.map(({ label, value }) => (
        <div key={label} className="fr-meta-item">
          <div className="fr-meta-label">{label}</div>
          <div className="fr-meta-value">{String(value)}</div>
        </div>
      ))}
    </div>
  )
}

/* ─── Empty state ────────────────────────────────────────────── */
function EmptyFindings({ status }) {
  const isPending = status === 'running' || status === 'queued'
  return (
    <div className="empty-state" style={{ padding: '40px 20px' }}>
      <svg className="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h3.75M9 15h3.75M9 18h3.75m3 .75H18a2.25 2.25 0 002.25-2.25V6.108c0-1.135-.845-2.098-1.976-2.192a48.424 48.424 0 00-1.123-.08m-5.801 0c-.065.21-.1.433-.1.664 0 .414.336.75.75.75h4.5a.75.75 0 00.75-.75 2.25 2.25 0 00-.1-.664m-5.8 0A2.251 2.251 0 0113.5 2.25H15c1.012 0 1.867.668 2.15 1.586m-5.8 0c-.376.023-.75.05-1.124.08C9.095 4.01 8.25 4.973 8.25 6.108V8.25m0 0H4.875c-.621 0-1.125.504-1.125 1.125v11.25c0 .621.504 1.125 1.125 1.125h9.75c.621 0 1.125-.504 1.125-1.125V9.375c0-.621-.504-1.125-1.125-1.125H8.25z" />
      </svg>
      <div className="empty-title">
        {isPending ? 'Scan in progress…' : 'No areas of interest available'}
      </div>
      <div className="empty-msg">
        {isPending
          ? 'Areas of interest will appear here once the scan completes.'
          : 'This scan did not produce any areas of interest, or the scan output was not found.'}
      </div>
    </div>
  )
}

/* ─── Main AreasOfInterestReport ─────────────────────────────── */
export default function FindingsReport({ data, status, onViewAnalysis }) {
  const [search, setSearch] = useState('')
  const [filterLevel, setFilterLevel] = useState('all')
  const [filterCategory, setFilterCategory] = useState('all')
  const [openIds, setOpenIds] = useState(new Set())
  const [expandAll, setExpandAll] = useState(false)

  const findings = data?.findings || []
  const summary = data?.summary
  const scanMeta = data?.scan_meta
  const analyzerReviewIndex = useMemo(() => buildAnalyzerReviewIndex(data?.analysis), [data?.analysis])

  /* ── counts ── */
  const counts = useMemo(() => {
    const c = {}
    for (const f of findings) {
      const l = confLevel(f)
      c[l] = (c[l] || 0) + 1
    }
    return c
  }, [findings])

  const categories = useMemo(() => {
    const s = new Set(findings.map((f) => f.category).filter(Boolean))
    return ['all', ...Array.from(s).sort()]
  }, [findings])

  /* ── filter ── */
  const filtered = useMemo(() => {
    const q = search.toLowerCase()
    return findings.filter((f) => {
      if (filterLevel !== 'all' && confLevel(f) !== filterLevel) return false
      if (filterCategory !== 'all' && f.category !== filterCategory) return false
      if (q) {
        const haystack = [
          f.rule_title, f.rule_id, f.category, f.issue_desc,
          ...(f.evidence || []).map((e) => e.file),
        ].join(' ').toLowerCase()
        if (!haystack.includes(q)) return false
      }
      return true
    })
  }, [findings, filterLevel, filterCategory, search])

  function toggleCard(id) {
    setOpenIds((prev) => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  function toggleAll() {
    if (expandAll) {
      setOpenIds(new Set())
    } else {
      setOpenIds(new Set(filtered.map((_, i) => i)))
    }
    setExpandAll((v) => !v)
  }

  if (!findings.length && status !== 'running' && status !== 'queued') {
    return <EmptyFindings status={status} />
  }
  if (!findings.length) {
    return <EmptyFindings status={status} />
  }

  return (
    <div className="fr-root">
      {/* ── Stats Row ── */}
      <div className="fr-stats-row">
        <StatCard
          label="Total Areas of Interest"
          value={findings.length}
          color="var(--primary)"
          icon={
            <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
            </svg>
          }
        />
        {counts.critical > 0 && (
          <StatCard label="Critical" value={counts.critical} color={confColor('critical')}
            icon={<svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor"><path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" /></svg>}
          />
        )}
        {counts.high > 0 && (
          <StatCard label="High" value={counts.high} color={confColor('high')}
            icon={<svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor"><path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" /></svg>}
          />
        )}
        {counts.medium > 0 && (
          <StatCard label="Medium" value={counts.medium} color={confColor('medium')}
            icon={<svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor"><path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92z" clipRule="evenodd" /></svg>}
          />
        )}
        {counts.low > 0 && (
          <StatCard label="Low" value={counts.low} color={confColor('low')}
            icon={<svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor"><path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" /></svg>}
          />
        )}
      </div>

      {/* ── Distribution bar ── */}
      <DistributionBar counts={counts} total={findings.length} />

      {/* ── Scan meta ── */}
      <ScanMeta summary={summary} scanMeta={scanMeta} />

      {/* ── File heatmap ── */}
      <FileHeatmap findings={findings} />

      {/* ── Areas of Interest header ── */}
      <div className="fr-findings-header">
        <div>
          <div className="fr-findings-title">
            Areas of Interest
            <span className="fr-findings-count">{filtered.length}{filtered.length !== findings.length ? ` / ${findings.length}` : ''}</span>
          </div>
          <div className="fr-section-subcopy">Potential issues pending analyzer confirmation, false-positive suppression, or manual inspection where automatic analysis is not supported yet.</div>
        </div>
        <div className="fr-filter-row">
          {/* Search */}
          <div className="fr-search-wrap">
            <svg width="14" height="14" viewBox="0 0 20 20" fill="currentColor" className="fr-search-icon">
              <path fillRule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clipRule="evenodd" />
            </svg>
            <input
              className="fr-search"
              placeholder="Search areas of interest…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          {/* Level filter */}
          <select className="fr-select" value={filterLevel} onChange={(e) => setFilterLevel(e.target.value)}>
            <option value="all">All levels</option>
            {CONF_ORDER.filter((l) => counts[l] > 0).map((l) => (
              <option key={l} value={l}>{l} ({counts[l]})</option>
            ))}
          </select>
          {/* Category filter */}
          {categories.length > 1 && (
            <select className="fr-select" value={filterCategory} onChange={(e) => setFilterCategory(e.target.value)}>
              {categories.map((c) => (
                <option key={c} value={c}>{c === 'all' ? 'All categories' : c}</option>
              ))}
            </select>
          )}
          {/* Expand/collapse all */}
          <button className="btn btn-ghost btn-sm" onClick={toggleAll}>
            {expandAll ? 'Collapse all' : 'Expand all'}
          </button>
        </div>
      </div>

      {/* ── Areas of Interest list ── */}
      {filtered.length === 0 ? (
        <div className="empty-state" style={{ padding: '30px 20px' }}>
          <div className="empty-title">No matching areas of interest</div>
          <div className="empty-msg">Try adjusting your search or filters.</div>
        </div>
      ) : (
        <div className="fr-findings-list">
          {filtered.map((f, i) => (
            <FindingCard
              key={i}
              finding={f}
              index={i}
              open={openIds.has(i)}
              onToggle={() => toggleCard(i)}
              review={analyzerReviewIndex.get([f.platform || '', f.rule_title || '', f.rule_id || ''].join('::').toLowerCase())}
              onViewAnalysis={() => onViewAnalysis?.(f)}
            />
          ))}
        </div>
      )}
    </div>
  )
}
