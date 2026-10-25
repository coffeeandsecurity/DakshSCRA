import MobileReviewView from './MobileReviewView'
import { splitMobileFindings } from '../lib/mobileReview'
import { findingCheckKey, findingCheckLabel, groupFindingFamilies } from '../lib/findingFamilies'
import { formatDateTime } from '../lib/datetime'
import { useMemo, useState } from 'react'
import { HighlightedSource } from './PatternEvidence'
import { ReviewGuidance } from './ReportAudience'

/* ─── Confidence helpers ─────────────────────────────────────── */
const CONF_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown']

function confLevel(finding) {
  return (finding.confidence_level || '').trim().toLowerCase() || 'unknown'
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

function CodeViewer({ lines, matchLineNums, highlightEnabled }) {
  if (!lines.length) return null
  const maxLen = String(Math.max(...lines.map(l => l.line || 0))).length
  return (
    <div className="fr-code-viewer">
      {lines.map((l, i) => {
        const isMatch = highlightEnabled && matchLineNums.has(l.line)
        return (
          <div key={i} className={`fr-cv-row${isMatch ? ' fr-cv-match' : ''}`}>
            <span className="fr-cv-ln">{l.line != null ? String(l.line).padStart(maxLen) : ''}</span>
            <code className="fr-cv-code"><HighlightedSource code={l.code} highlights={highlightEnabled ? l.highlights : []} /></code>
          </div>
        )
      })}
    </div>
  )
}

function SnippetList({ evidence, scanConfig }) {
  if (!evidence?.length) return null
  return (
    <div className="fr-evidence-list">
      {evidence.map((e, i) => {
        let lines, matchLineNums
        if (e.aggregated) {
          const rows = new Map()
          for (const match of e.matches || []) {
            for (const row of [...(match.context_before || []), ...(match.context_after || [])]) {
              if (!rows.has(row.line)) rows.set(row.line, row)
            }
          }
          for (const match of e.matches || []) rows.set(match.line, match)
          lines = [...rows.values()].sort((a, b) => a.line - b.line)
          matchLineNums = new Set((e.matches || []).map(match => match.line))
        } else {
          lines = [
            ...(e.context_before || []),
            { line: e.line, code: e.code, highlights: e.highlights },
            ...(e.context_after || []),
          ]
          matchLineNums = new Set([e.line])
        }
        return (
          <details key={i} className="fr-evidence-item">
            <summary className="fr-evidence-header">
              <FileIcon />
              <span className="fr-evidence-file">{`Lines ${lines[0]?.line ?? e.line ?? '?'}–${lines[lines.length - 1]?.line ?? e.line ?? '?'}`}</span>
              <span className="fr-category-chip">{e.matches?.length || 1} {(e.matches?.length || 1) === 1 ? 'instance' : 'instances'}</span>
              {(e.code_truncated || e.matches?.some(match => match.code_truncated)) && <span className="fr-evidence-line">Excerpt shortened</span>}
              <span className="fr-disclosure-icon" aria-hidden="true">▸</span>
            </summary>
            <CodeViewer lines={lines} matchLineNums={matchLineNums} highlightEnabled={!['false', '0', 'no'].includes(String(scanConfig?.highlight_enabled ?? true).toLowerCase())} />
          </details>
        )
      })}
    </div>
  )
}

function CodeEvidence({ evidence, scanConfig }) {
  const [openFiles, setOpenFiles] = useState(new Set())
  const groups = useMemo(() => {
    const files = new Map()
    for (const item of evidence || []) {
      const file = item.file || 'Source file'
      if (!files.has(file)) files.set(file, [])
      files.get(file).push(item)
    }
    return [...files]
  }, [evidence])
  if (!groups.length) return null
  const allOpen = groups.every(([file]) => openFiles.has(file))
  return <div className="fr-code-groups">
    <div className="fr-code-group-toolbar">
      <span>Code evidence · {groups.length} {groups.length === 1 ? 'file' : 'files'}</span>
      <button type="button" className="btn btn-ghost btn-sm" onClick={() => setOpenFiles(allOpen ? new Set() : new Set(groups.map(([file]) => file)))}>{allOpen ? 'Collapse code groups' : 'Expand code groups'}</button>
    </div>
    {groups.map(([file, items]) => <details className="fr-file-group" key={file} open={openFiles.has(file)} onToggle={event => {
      const expanded = event.currentTarget.open
      setOpenFiles(previous => {
        if (previous.has(file) === expanded) return previous
        const next = new Set(previous)
        expanded ? next.add(file) : next.delete(file)
        return next
      })
    }}>
      <summary className="fr-evidence-header"><FileIcon /><span className="fr-evidence-file" title={file}>{file}</span><span className="fr-category-chip">{items.reduce((total, item) => total + (item.matches?.length || 1), 0)} {items.reduce((total, item) => total + (item.matches?.length || 1), 0) === 1 ? 'instance' : 'instances'}</span><span className="fr-disclosure-icon" aria-hidden="true">▸</span></summary>
      {openFiles.has(file) && <SnippetList evidence={items} scanConfig={scanConfig} />}
    </details>)}
  </div>
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
function FindingCard({ finding, index, open, onToggle, review, onViewAnalysis, nested = false, instanceCount, heading }) {
  const Header = 'button'
  const level = confLevel(finding)
  const score = confScore(finding)
  const showAnalysisLink = review?.status === 'confirmed_vulnerability' && onViewAnalysis
  const logicEngine = finding.logic_engine || ''
  return (
    <div className={`fr-card${open ? ' open' : ''}`} style={{ '--conf-color': confColor(level) }}>
      <Header className="fr-card-header" type="button" onClick={onToggle} aria-expanded={open}>
        <span className={confClass(level)}>{level}</span>
        {score > 0 && <span className="fr-score" title="Heuristic evidence confidence, not probability or severity">{score}/100</span>}
        <span className="fr-card-title">{heading || (nested ? findingCheckLabel(finding) : finding.rule_title || finding.rule_id || `Area of Interest #${index + 1}`)}</span>
        {instanceCount != null && <span className="fr-category-chip">{instanceCount} {instanceCount === 1 ? 'instance' : 'instances'}</span>}
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
      </Header>

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
            <div className="fr-note"><div className="fr-note-label">Issue description</div><p className="fr-issue-desc">{finding.issue_desc}</p></div>
          )}
          {finding.security_impact && (
            <div className="fr-note"><div className="fr-note-label">Security impact</div><p className="fr-issue-desc">{finding.security_impact}</p></div>
          )}

          <ReviewGuidance developer={finding.developer_note} reviewer={finding.reviewer_note} />

          <CodeEvidence evidence={finding.evidence} scanConfig={finding.scan_config} />

        </div>
      )}
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
    { label: 'Start Time', value: formatDateTime(timeline.scan_start_time) },
    { label: 'End Time', value: formatDateTime(timeline.scan_end_time) },
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
  const [filterPlatform, setFilterPlatform] = useState('all')
  const [openIds, setOpenIds] = useState(new Set())
  const [expandAll, setExpandAll] = useState(false)

  const findings = data?.findings || []
  const families = useMemo(() => groupFindingFamilies(findings), [findings])
  const summary = data?.summary
  const scanMeta = data?.scan_meta
  const analyzerReviewIndex = useMemo(() => buildAnalyzerReviewIndex(data?.analysis), [data?.analysis])

  /* ── counts ── */
  const counts = useMemo(() => {
    const c = {}
    for (const { representative: f } of families) {
      const l = confLevel(f)
      c[l] = (c[l] || 0) + 1
    }
    return c
  }, [families])

  const categories = useMemo(() => {
    const s = new Set(findings.map((f) => f.category).filter(Boolean))
    return ['all', ...Array.from(s).sort()]
  }, [findings])

  const platforms = useMemo(() => [...new Set(findings.map(finding => String(finding.platform || 'Unspecified').trim().toLowerCase()))].sort(), [findings])
  const levelCounts = useMemo(() => Object.fromEntries(CONF_ORDER.map(level => [level, families.filter(group => group.members.some(member => confLevel(member) === level)).length])), [families])

  /* ── filter ── */
  const filtered = useMemo(() => {
    const q = search.toLowerCase()
    return findings.filter((f) => {
      if (filterPlatform !== 'all' && String(f.platform || 'Unspecified').trim().toLowerCase() !== filterPlatform) return false
      if (filterLevel !== 'all' && confLevel(f) !== filterLevel) return false
      if (filterCategory !== 'all' && f.category !== filterCategory) return false
      if (q) {
        const haystack = [
          f.rule_title, f.rule_id, f.category, f.issue_desc, f.platform,
          ...(f.evidence || []).map((e) => e.file),
        ].join(' ').toLowerCase()
        if (!haystack.includes(q)) return false
      }
      return true
    }).sort((a, b) => {
      const rank = finding => {
        const index = CONF_ORDER.indexOf(confLevel(finding))
        return index < 0 ? CONF_ORDER.length : index
      }
      return rank(a) - rank(b) || confScore(b) - confScore(a)
    })
  }, [findings, filterLevel, filterCategory, filterPlatform, search])

  const filteredFamilies = useMemo(() => groupFindingFamilies(filtered), [filtered])

  const mobileBuckets = useMemo(() => splitMobileFindings(filtered), [filtered])
  const mobileFamilies = useMemo(() => Object.fromEntries(Object.entries(mobileBuckets).map(([key, items]) => [key, groupFindingFamilies(items)])), [mobileBuckets])

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
      setOpenIds(new Set(filteredFamilies.flatMap(group => [group.key, ...group.members.map((member, index) => findingCheckKey(group.key, member, index)), ...group.platforms.flatMap(platform => [platform.key, ...platform.members.map((member, index) => findingCheckKey(platform.key, member, index))])])))
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
          label="Areas of Interest"
          value={families.length}
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
      <p className="fr-family-summary">{families.length} {families.length === 1 ? 'issue family' : 'issue families'} · {platforms.length} {platforms.length === 1 ? 'platform' : 'platforms'} · {findings.length} recorded checks · {families.reduce((sum, group) => sum + group.instanceCount, 0)} instances. Instances are distinct source locations within each platform. Parent confidence is the highest recorded check confidence.</p>
      <DistributionBar counts={counts} total={families.length} />

      {/* ── Scan meta ── */}
      <ScanMeta summary={summary} scanMeta={scanMeta} />

      {/* ── Areas of Interest header ── */}
      <div className="fr-findings-header">
        <div>
          <div className="fr-findings-title">
            Areas of Interest
            <span className="fr-findings-count">{filteredFamilies.length}{filteredFamilies.length !== families.length ? ` / ${families.length}` : ''}</span>
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
            {CONF_ORDER.filter((l) => levelCounts[l] > 0).map((l) => (
              <option key={l} value={l}>{l} ({levelCounts[l]})</option>
            ))}
          </select>
          {platforms.length > 1 && <select className="fr-select" aria-label="Filter by platform" value={filterPlatform} onChange={event => setFilterPlatform(event.target.value)}>
            <option value="all">All platforms</option>
            {platforms.map(platform => <option key={platform} value={platform}>{platform.toUpperCase()}</option>)}
          </select>}
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
        <MobileReviewView buckets={mobileBuckets}>{scope => <div className="fr-findings-list">
          {(scope ? mobileFamilies[scope] : filteredFamilies).map((group, i) => {
            const f = group.representative
            const renderCheck = (member, index, nested = false, parentKey = group.key, heading) => {
              const key = nested ? findingCheckKey(parentKey, member, index) : group.key
              return <FindingCard key={key} finding={member} index={index} nested={nested} heading={heading} instanceCount={nested ? groupFindingFamilies([member])[0].instanceCount : group.instanceCount} open={openIds.has(key)} onToggle={() => toggleCard(key)} review={analyzerReviewIndex.get([member.platform || '', member.rule_title || '', member.rule_id || ''].join('::').toLowerCase())} onViewAnalysis={() => onViewAnalysis?.(member)} />
            }
            if (group.members.length === 1) return <div key={group.key}>{renderCheck(f, i)}</div>
            return <section key={group.key} className="fr-card fr-family" style={{ '--conf-color': confColor(confLevel(f)) }}>
              <button type="button" className="fr-card-header" aria-expanded={openIds.has(group.key)} onClick={() => toggleCard(group.key)}>
                <span className="fr-confidence-label">Highest confidence</span>
                <span className={confClass(confLevel(f))}>{confLevel(f)}</span>
                {confScore(f) > 0 && <span className="fr-score" title="Heuristic evidence confidence, not probability or severity">{confScore(f)}/100</span>}
                <span className="fr-card-title">{f.rule_title}</span>
                <span className="fr-category-chip">{group.instanceCount} {group.instanceCount === 1 ? 'instance' : 'instances'} · {group.platforms.length} {group.platforms.length === 1 ? 'platform' : 'platforms'} · {group.members.length} checks</span>
                {group.platforms.map(platform => <span key={platform.key} className="fr-platform-chip">{platform.name.toUpperCase()} {platform.instanceCount}</span>)}
                <span className="fr-card-caret">{openIds.has(group.key) ? '▲' : '▼'}</span>
              </button>
              {openIds.has(group.key) && <div className="fr-family-checks">
                <p>Expand a platform or source operation to review its guidance and code evidence.</p>
                {group.platforms.length === 1 ? group.members.map((member, index) => renderCheck(member, index, true)) : group.platforms.map(platform => {
                  const primary = platform.representative
                  const open = openIds.has(platform.key)
                  return <section className="fr-card fr-platform-group" key={platform.key} style={{ '--conf-color': confColor(confLevel(primary)) }}>
                    <button type="button" className="fr-card-header" aria-expanded={open} onClick={() => toggleCard(platform.key)}>
                      {platform.members.length > 1 && <span className="fr-confidence-label">Highest confidence</span>}
                      <span className={confClass(confLevel(primary))}>{confLevel(primary)}</span>
                      {confScore(primary) > 0 && <span className="fr-score" title="Heuristic evidence confidence, not probability or severity">{confScore(primary)}/100</span>}
                      <span className="fr-card-title">{platform.name.toUpperCase()}</span>
                      <span className="fr-category-chip">{platform.instanceCount} {platform.instanceCount === 1 ? 'instance' : 'instances'} · {platform.members.length} {platform.members.length === 1 ? 'check' : 'checks'}</span>
                      <span className="fr-card-caret">{open ? '▲' : '▼'}</span>
                    </button>
                    {open && <div className="fr-family-checks">{platform.members.map((member, index) => renderCheck(member, index, true, platform.key))}</div>}
                  </section>
                })}
              </div>}
            </section>
          })}
        </div>}</MobileReviewView>
      )}
    </div>
  )
}
