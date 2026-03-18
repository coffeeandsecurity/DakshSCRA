import { useEffect, useMemo, useState } from 'react'
import {
  getSuppressedFindings,
  getSuppressedReportUrl,
  promoteSuppressedItem,
  regenerateReports,
} from '../api'

/* ── Shared styles (defined first — referenced by all components below) ── */
const inputStyle = {
  background: '#0d1117',
  border: '1px solid #30363d',
  borderRadius: '6px',
  color: '#e6edf3',
  padding: '6px 10px',
  fontSize: '13px',
  outline: 'none',
}

const codeStyle = {
  margin: '4px 0',
  padding: '8px 12px',
  background: '#0d1117',
  borderRadius: '6px',
  fontSize: '12px',
  fontFamily: 'monospace',
  overflowX: 'auto',
  border: '1px solid #21262d',
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-all',
}

const btnGhost = {
  background: 'transparent',
  border: '1px solid #30363d',
  borderRadius: '6px',
  color: '#8b949e',
  padding: '6px 12px',
  fontSize: '12px',
  cursor: 'pointer',
  textDecoration: 'none',
  display: 'inline-flex',
  alignItems: 'center',
}

const btnPrimary = {
  background: '#1f6feb',
  border: '1px solid #388bfd',
  borderRadius: '6px',
  color: '#f8fafc',
  padding: '6px 14px',
  fontSize: '12px',
  cursor: 'pointer',
}

const btnPromote = {
  background: 'rgba(34,197,94,0.12)',
  border: '1px solid rgba(34,197,94,0.35)',
  borderRadius: '6px',
  color: '#22c55e',
  padding: '6px 14px',
  fontSize: '12px',
  cursor: 'pointer',
}

/* ── Status colour map ───────────────────────────────────────── */
const STATUS_COLOR = {
  suppressed: { bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.35)', text: '#f59e0b' },
  confirmed_finding: { bg: 'rgba(34,197,94,0.12)', border: 'rgba(34,197,94,0.35)', text: '#22c55e' },
}

/* ── Helpers ─────────────────────────────────────────────────── */
function safeLines(val) {
  if (Array.isArray(val)) {
    return val.map((item) =>
      typeof item === 'string'
        ? item
        : `${item.line != null ? item.line + ': ' : ''}${item.code || ''}`
    )
  }
  if (typeof val === 'string' && val.length > 0) return val.split('\n')
  return []
}

function StatusBadge({ status }) {
  const s = STATUS_COLOR[status] || STATUS_COLOR.suppressed
  const label = status === 'confirmed_finding' ? 'Promoted' : 'Suppressed'
  return (
    <span style={{
      background: s.bg, border: `1px solid ${s.border}`, color: s.text,
      padding: '2px 8px', borderRadius: '4px', fontSize: '11px', fontWeight: 600,
    }}>
      {label}
    </span>
  )
}

function SummaryCard({ value, label, color }) {
  return (
    <div style={{
      background: '#161b22', border: '1px solid #30363d', borderRadius: '8px',
      padding: '16px 20px', minWidth: '140px', flex: '1',
    }}>
      <div style={{ fontSize: '28px', fontWeight: 700, color: color || '#f8fafc' }}>{value}</div>
      <div style={{ fontSize: '12px', color: '#8b949e', marginTop: '4px' }}>{label}</div>
    </div>
  )
}

/* ── Promote Modal ───────────────────────────────────────────── */
function PromoteModal({ item, onClose, onPromoted }) {
  const [form, setForm] = useState({
    confidence: 50,
    confidence_level: 'medium',
    severity: 'medium',
    rating: '',
    notes: '',
  })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  function set(k, v) { setForm((f) => ({ ...f, [k]: v })) }

  async function handleSubmit(e) {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      await promoteSuppressedItem(item._runUuid, item.id, form)
      onPromoted(item.id)
    } catch (err) {
      setError(err.message || 'Promotion failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', zIndex: 1000,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}
      onClick={(e) => { if (e.target === e.currentTarget) onClose() }}
    >
      <div style={{
        background: '#0d1117', border: '1px solid #30363d', borderRadius: '12px',
        padding: '24px', width: '480px', maxWidth: '95vw',
      }}>
        <h3 style={{ margin: '0 0 4px', color: '#f8fafc', fontSize: '16px' }}>Promote to Active Finding</h3>
        <p style={{ margin: '0 0 20px', color: '#8b949e', fontSize: '13px' }}>
          {item.rule_title} — {item.file}:{item.line}
        </p>

        {error && (
          <div style={{
            background: 'rgba(248,81,73,0.1)', border: '1px solid rgba(248,81,73,0.3)',
            borderRadius: '6px', padding: '8px 12px', color: '#f85149', fontSize: '13px', marginBottom: '16px',
          }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '12px' }}>
            <label style={{ display: 'flex', flexDirection: 'column', gap: '4px', color: '#8b949e', fontSize: '12px' }}>
              Confidence Score
              <input
                type="number" min="0" max="100" value={form.confidence}
                onChange={(e) => set('confidence', Number(e.target.value))}
                style={inputStyle}
              />
            </label>
            <label style={{ display: 'flex', flexDirection: 'column', gap: '4px', color: '#8b949e', fontSize: '12px' }}>
              Confidence Level
              <select value={form.confidence_level} onChange={(e) => set('confidence_level', e.target.value)} style={inputStyle}>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </label>
            <label style={{ display: 'flex', flexDirection: 'column', gap: '4px', color: '#8b949e', fontSize: '12px' }}>
              Severity
              <select value={form.severity} onChange={(e) => set('severity', e.target.value)} style={inputStyle}>
                <option value="info">Info</option>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </label>
            <label style={{ display: 'flex', flexDirection: 'column', gap: '4px', color: '#8b949e', fontSize: '12px' }}>
              Rating
              <input
                type="text" placeholder="e.g. P2, CVSS:7.5"
                value={form.rating}
                onChange={(e) => set('rating', e.target.value)}
                style={inputStyle}
              />
            </label>
          </div>
          <label style={{ display: 'flex', flexDirection: 'column', gap: '4px', color: '#8b949e', fontSize: '12px', marginBottom: '20px' }}>
            Notes
            <textarea
              value={form.notes}
              onChange={(e) => set('notes', e.target.value)}
              placeholder="Analyst notes — why is this a true positive?"
              rows={3}
              style={{ ...inputStyle, resize: 'vertical', fontFamily: 'inherit' }}
            />
          </label>

          <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
            <button type="button" onClick={onClose} style={btnGhost}>Cancel</button>
            <button type="submit" disabled={busy} style={btnPrimary}>
              {busy ? 'Promoting…' : 'Promote to Finding'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

/* ── Row ─────────────────────────────────────────────────────── */
function SuppressedRow({ item, runUuid, onPromoted }) {
  const [open, setOpen] = useState(false)
  const [showModal, setShowModal] = useState(false)
  const isPromoted = item.status === 'confirmed_finding'

  const ctxBefore = safeLines(item.context_before)
  const ctxAfter = safeLines(item.context_after)

  function handleHeaderClick(e) {
    // Ignore clicks on interactive children (buttons, inputs, anchors)
    if (e.target.closest('button, a, input, select, textarea')) return
    setOpen((v) => !v)
  }

  return (
    <>
      {showModal && (
        <PromoteModal
          item={{ ...item, _runUuid: runUuid }}
          onClose={() => setShowModal(false)}
          onPromoted={(id) => { setShowModal(false); onPromoted(id) }}
        />
      )}
      <div style={{
        background: '#0d1117', border: '1px solid #21262d', borderRadius: '8px',
        marginBottom: '8px', overflow: 'hidden',
      }}>
        {/* Header row */}
        <div
          onClick={handleHeaderClick}
          style={{
            display: 'flex', alignItems: 'center', gap: '10px',
            padding: '10px 14px', cursor: 'pointer',
            background: open ? '#161b22' : 'transparent',
            userSelect: 'none',
          }}
        >
          <svg
            width="12" height="12" viewBox="0 0 20 20" fill="currentColor"
            style={{
              color: '#8b949e', flexShrink: 0, transition: 'transform .15s',
              transform: open ? 'rotate(90deg)' : 'none',
            }}
          >
            <path fillRule="evenodd" d="M7.293 4.293a1 1 0 011.414 0l5 5a1 1 0 010 1.414l-5 5a1 1 0 01-1.414-1.414L11.586 10 7.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
          </svg>

          <span style={{ fontSize: '12px', color: '#58a6ff', fontWeight: 600, fontFamily: 'monospace', flexShrink: 0 }}>
            {item.platform || '—'}
          </span>
          <span style={{
            fontSize: '13px', color: '#e6edf3', fontWeight: 500,
            flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          }}>
            {item.rule_title || '(no title)'}
          </span>
          <span style={{ fontSize: '11px', color: '#8b949e', fontFamily: 'monospace', flexShrink: 0 }}>
            {(item.file || '').split('/').slice(-1)[0] || '—'}:{item.line ?? '?'}
          </span>
          <StatusBadge status={item.status} />
        </div>

        {/* Expanded detail */}
        {open && (
          <div style={{ padding: '0 14px 14px', borderTop: '1px solid #21262d' }}>
            {/* Full file path */}
            <div style={{ fontSize: '11px', color: '#8b949e', fontFamily: 'monospace', marginTop: '10px', marginBottom: '8px' }}>
              {item.file || ''}:{item.line ?? ''}
            </div>

            {/* Context before */}
            {ctxBefore.length > 0 && (
              <pre style={codeStyle}>
                {ctxBefore.map((l, i) => (
                  <span key={i} style={{ color: '#8b949e', display: 'block' }}>{l}</span>
                ))}
              </pre>
            )}

            {/* Flagged line */}
            <pre style={{ ...codeStyle, borderLeft: '3px solid #f59e0b', marginTop: 0, marginBottom: 0 }}>
              <span style={{ color: '#fbbf24' }}>{item.line ?? ''}: {item.code || ''}</span>
            </pre>

            {/* Context after */}
            {ctxAfter.length > 0 && (
              <pre style={{ ...codeStyle, marginTop: 0 }}>
                {ctxAfter.map((l, i) => (
                  <span key={i} style={{ color: '#8b949e', display: 'block' }}>{l}</span>
                ))}
              </pre>
            )}

            {/* RDL condition */}
            <div style={{
              marginTop: '12px', padding: '10px 12px', background: '#161b22',
              borderRadius: '6px', border: '1px solid #21262d',
            }}>
              <div style={{ fontSize: '11px', color: '#8b949e', marginBottom: '4px', textTransform: 'uppercase', letterSpacing: '.05em' }}>
                RDL Condition Triggered
              </div>
              <code style={{ fontSize: '12px', color: '#a5d6ff', fontFamily: 'monospace', wordBreak: 'break-all' }}>
                {item.rdl_condition || item.rdl_text || '—'}
              </code>
            </div>

            {/* Suppression reason */}
            <div style={{
              marginTop: '8px', padding: '10px 12px',
              background: 'rgba(245,158,11,0.06)', borderRadius: '6px',
              border: '1px solid rgba(245,158,11,0.2)',
            }}>
              <div style={{ fontSize: '11px', color: '#8b949e', marginBottom: '4px', textTransform: 'uppercase', letterSpacing: '.05em' }}>
                Why Suppressed
              </div>
              <span style={{ fontSize: '13px', color: '#e6edf3' }}>
                {item.suppression_reason || 'RDL condition was not satisfied.'}
              </span>
            </div>

            {/* Promote action */}
            {!isPromoted && (
              <div style={{ marginTop: '12px', display: 'flex', justifyContent: 'flex-end' }}>
                <button
                  onClick={(e) => { e.stopPropagation(); setShowModal(true) }}
                  style={btnPromote}
                >
                  Promote to Finding
                </button>
              </div>
            )}

            {/* Analyst note (post-promotion) */}
            {isPromoted && item.notes && (
              <div style={{
                marginTop: '8px', padding: '8px 12px',
                background: 'rgba(34,197,94,0.06)', borderRadius: '6px',
                border: '1px solid rgba(34,197,94,0.2)',
                fontSize: '12px', color: '#86efac',
              }}>
                <strong>Analyst note:</strong> {item.notes}
              </div>
            )}
          </div>
        )}
      </div>
    </>
  )
}

/* ── Main Panel ──────────────────────────────────────────────── */
export default function SuppressedPanel({ runUuid, onLoaded }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [filterStatus, setFilterStatus] = useState('all')
  const [regenerating, setRegenerating] = useState(false)
  const [regenMsg, setRegenMsg] = useState('')

  useEffect(() => {
    if (!runUuid) return
    setLoading(true)
    setError('')
    getSuppressedFindings(runUuid)
      .then((d) => {
        setData(d)
        if (typeof onLoaded === 'function') {
          onLoaded(d?.summary?.total_suppressed ?? 0)
        }
      })
      .catch((e) => setError(e.message || 'Failed to load suppressed findings'))
      .finally(() => setLoading(false))
  }, [runUuid])

  function handlePromoted(itemId) {
    setData((prev) => {
      if (!prev) return prev
      const updated = (prev.suppressed || []).map((s) =>
        s.id === itemId ? { ...s, status: 'confirmed_finding' } : s
      )
      const promoted = updated.filter((s) => s.status === 'confirmed_finding').length
      return {
        ...prev,
        suppressed: updated,
        summary: { ...prev.summary, promoted_to_findings: promoted },
      }
    })
  }

  async function handleRegenerate() {
    setRegenerating(true)
    setRegenMsg('')
    try {
      await regenerateReports(runUuid)
      setRegenMsg('Reports regenerated successfully.')
    } catch (e) {
      setRegenMsg(`Error: ${e.message}`)
    } finally {
      setRegenerating(false)
    }
  }

  const filtered = useMemo(() => {
    const list = data?.suppressed || []
    const q = search.toLowerCase()
    return list.filter((s) => {
      if (filterStatus !== 'all' && s.status !== filterStatus) return false
      if (!q) return true
      return (
        (s.rule_title || '').toLowerCase().includes(q) ||
        (s.file || '').toLowerCase().includes(q) ||
        (s.platform || '').toLowerCase().includes(q) ||
        (s.rdl_condition || '').toLowerCase().includes(q) ||
        (s.suppression_reason || '').toLowerCase().includes(q)
      )
    })
  }, [data, search, filterStatus])

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '40px 20px', color: '#8b949e' }}>
        <div className="fr-spinner" />
        <span>Loading suppressed findings…</span>
      </div>
    )
  }

  if (error) {
    return (
      <div style={{ padding: '40px 20px' }}>
        <div className="empty-title">Error loading data</div>
        <div className="empty-msg">{error}</div>
      </div>
    )
  }

  const summary = data?.summary || {}
  const total = summary.total_suppressed ?? 0
  const rdlHit = summary.rdl_conditions_triggered ?? 0
  const promoted = summary.promoted_to_findings ?? 0

  if (total === 0) {
    return (
      <div className="empty-state" style={{ padding: '40px 20px' }}>
        <div className="empty-title">No suppressed findings</div>
        <div className="empty-msg">
          RDL conditions have not suppressed any matches for this scan.
          Rules need IF() conditions and regex matches must fail those conditions
          for suppressions to be recorded.
        </div>
      </div>
    )
  }

  const jsonReportUrl = getSuppressedReportUrl(runUuid, 'json')
  const htmlReportUrl = getSuppressedReportUrl(runUuid, 'html')

  return (
    <div style={{ padding: '0 0 32px' }}>
      {/* Summary cards */}
      <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', marginBottom: '24px' }}>
        <SummaryCard value={total} label="Total Suppressed" color="#f59e0b" />
        <SummaryCard value={rdlHit} label="RDL Conditions Triggered" color="#58a6ff" />
        <SummaryCard value={promoted} label="Promoted to Findings" color="#22c55e" />
      </div>

      {/* Toolbar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px', flexWrap: 'wrap' }}>
        <div style={{ position: 'relative', flex: 1, minWidth: '200px' }}>
          <svg
            width="12" height="12" viewBox="0 0 20 20" fill="currentColor"
            style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: '#8b949e', pointerEvents: 'none' }}
          >
            <path fillRule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clipRule="evenodd" />
          </svg>
          <input
            placeholder="Search rule, file, platform, condition…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{ ...inputStyle, paddingLeft: '28px', width: '100%', boxSizing: 'border-box' }}
          />
        </div>

        <select value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)} style={{ ...inputStyle, width: 'auto' }}>
          <option value="all">All statuses</option>
          <option value="suppressed">Suppressed only</option>
          <option value="confirmed_finding">Promoted only</option>
        </select>

        <span style={{ fontSize: '12px', color: '#8b949e', flexShrink: 0 }}>
          {filtered.length} / {total} shown
        </span>

        <a href={jsonReportUrl} download style={btnGhost}>Export JSON</a>
        <a href={htmlReportUrl} download style={btnGhost}>Export HTML</a>

        <button onClick={handleRegenerate} disabled={regenerating} style={btnPrimary}>
          {regenerating ? 'Regenerating…' : 'Regenerate Reports'}
        </button>
      </div>

      {regenMsg && (
        <div style={{
          marginBottom: '12px', padding: '8px 12px', borderRadius: '6px', fontSize: '13px',
          background: regenMsg.startsWith('Error') ? 'rgba(248,81,73,0.1)' : 'rgba(34,197,94,0.1)',
          border: `1px solid ${regenMsg.startsWith('Error') ? 'rgba(248,81,73,0.3)' : 'rgba(34,197,94,0.3)'}`,
          color: regenMsg.startsWith('Error') ? '#f85149' : '#22c55e',
        }}>
          {regenMsg}
        </div>
      )}

      {/* List */}
      {filtered.length === 0 ? (
        <div style={{ textAlign: 'center', color: '#8b949e', padding: '32px', fontSize: '14px' }}>
          No results match the current filter.
        </div>
      ) : (
        filtered.map((item, idx) => (
          <SuppressedRow
            key={item.id || String(idx)}
            item={item}
            runUuid={runUuid}
            onPromoted={handlePromoted}
          />
        ))
      )}
    </div>
  )
}
