import { suppressionDetails } from '../lib/suppression'
import { useEffect, useMemo, useRef, useState } from 'react'
import {
  getSuppressedFindings,
  getSuppressedReportUrl,
  promoteSuppressedItem,
} from '../api'

/* ── Shared styles (defined first - referenced by all components below) ── */
const inputStyle = {
  background: 'var(--surface)',
  border: '1px solid var(--border)',
  borderRadius: '6px',
  color: 'var(--text)',
  padding: '6px 10px',
  fontSize: '13px',
}

const btnGhost = {
  background: 'transparent',
  border: '1px solid var(--border)',
  borderRadius: '6px',
  color: 'var(--text-3)',
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
  color: 'var(--primary-text)',
  padding: '6px 14px',
  fontSize: '12px',
  cursor: 'pointer',
}

/* ── Status colour map ───────────────────────────────────────── */
const STATUS_COLOR = {
  suppressed: { bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.35)', text: 'var(--warning-text)' },
  confirmed_finding: { bg: 'rgba(34,197,94,0.12)', border: 'rgba(34,197,94,0.35)', text: 'var(--success-text)' },
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
  return <div className="fr-stat-card" style={{ '--stat-color': color }}><div><div className="fr-stat-value">{value}</div><div className="fr-stat-label">{label}</div></div></div>
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
  const dialogRef = useRef(null)
  useEffect(() => {
    const previous = document.activeElement
    dialogRef.current?.querySelector('input')?.focus()
    return () => previous?.focus()
  }, [])
  function handleDialogKey(event) {
    if (event.key === 'Escape' && !busy) onClose()
    if (event.key !== 'Tab') return
    const controls = [...dialogRef.current.querySelectorAll('input, select, textarea, button')].filter(node => !node.disabled)
    const first = controls[0], last = controls[controls.length - 1]
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus() }
    if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus() }
  }

  function set(k, v) { setForm((f) => ({ ...f, [k]: v })) }

  async function handleSubmit(e) {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      await promoteSuppressedItem(item._runUuid, item.id, form)
      onPromoted(item.id, form)
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
      <div ref={dialogRef} onKeyDown={handleDialogKey} role="dialog" aria-modal="true" aria-label="Promote to active finding" style={{
        background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: '12px',
        padding: '24px', width: '480px', maxWidth: '95vw', maxHeight: '90vh', overflowY: 'auto',
      }}>
        <h3 style={{ margin: '0 0 4px', color: 'var(--text)', fontSize: '16px' }}>Promote to Active Finding</h3>
        <p style={{ margin: '0 0 20px', color: 'var(--text-3)', fontSize: '13px' }}>
          {item.rule_title} - {item.file}:{item.line}
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
            <label style={{ display: 'flex', flexDirection: 'column', gap: '4px', color: 'var(--text-3)', fontSize: '12px' }}>
              Confidence Score
              <input
                type="number" min="0" max="100" value={form.confidence}
                onChange={(e) => set('confidence', Number(e.target.value))}
                style={inputStyle}
              />
            </label>
            <label style={{ display: 'flex', flexDirection: 'column', gap: '4px', color: 'var(--text-3)', fontSize: '12px' }}>
              Confidence Level
              <select value={form.confidence_level} onChange={(e) => set('confidence_level', e.target.value)} style={inputStyle}>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </label>
            <label style={{ display: 'flex', flexDirection: 'column', gap: '4px', color: 'var(--text-3)', fontSize: '12px' }}>
              Severity
              <select value={form.severity} onChange={(e) => set('severity', e.target.value)} style={inputStyle}>
                <option value="info">Info</option>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </label>
            <label style={{ display: 'flex', flexDirection: 'column', gap: '4px', color: 'var(--text-3)', fontSize: '12px' }}>
              Rating
              <input
                type="text" placeholder="e.g. P2, CVSS:7.5"
                value={form.rating}
                onChange={(e) => set('rating', e.target.value)}
                style={inputStyle}
              />
            </label>
          </div>
          <label style={{ display: 'flex', flexDirection: 'column', gap: '4px', color: 'var(--text-3)', fontSize: '12px', marginBottom: '20px' }}>
            Notes
            <textarea
              value={form.notes}
              onChange={(e) => set('notes', e.target.value)}
              placeholder="Analyst notes - why is this a true positive?"
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

function SuppressedRow({ item, runUuid, onPromoted }) {
  const [open, setOpen] = useState(false)
  const [showModal, setShowModal] = useState(false)
  const promoted = item.status === 'confirmed_finding'
  const details = suppressionDetails(item)
  const trace = Array.isArray(item.logic_trace) ? item.logic_trace : item.logic_trace ? [item.logic_trace] : []
  const consulted = Array.isArray(item.logic_consulted_files) ? item.logic_consulted_files : item.logic_consulted_files ? [item.logic_consulted_files] : []
  const asText = value => typeof value === 'string' ? value : JSON.stringify(value, null, 2)
  return <>
    {showModal && <PromoteModal item={{ ...item, _runUuid: runUuid }} onClose={() => setShowModal(false)} onPromoted={(id, fields) => { setShowModal(false); onPromoted(id, fields) }} />}
    <article className={`fr-card suppression-card${open ? ' open' : ''}`} style={{ '--conf-color': promoted ? 'var(--success-color)' : 'var(--warning-color)' }}>
      <button className="fr-card-header" onClick={() => setOpen(value => !value)} aria-expanded={open}>
        <StatusBadge status={item.status} />
        <span className="fr-card-title">{item.rule_title || 'Untitled rule'}</span>
        {item.platform && <span className="fr-platform-chip">{item.platform}</span>}
        <span className="fr-platform-chip">{details.engine}</span>
        <span className="fr-card-caret" aria-hidden="true">{open ? '▲' : '▼'}</span>
      </button>
      <div className="suppression-overview">
        <div className="suppression-location">{item.file || 'File not recorded'}:{item.line ?? '?'}</div>
        <p><strong>{promoted ? 'Original suppression reason' : 'Why suppressed'}:</strong> {details.reason}</p>
      </div>
      {open && <div className="fr-card-body">
        <dl className="suppression-metadata">
          <div><dt>Suppressing engine</dt><dd>{details.engine}</dd></div>
          <div><dt>Rule</dt><dd>{item.rule_title || 'Not recorded'}{item.rule_id ? ` (${item.rule_id})` : ''}</dd></div>
          <div><dt>RDL / logic source</dt><dd className="suppression-location">{details.source || 'Not recorded'}</dd></div>
          {item.rdl_condition && item.rdl_condition !== `RDL:${details.source}` && <div><dt>Recorded condition</dt><dd>{item.rdl_condition}</dd></div>}
          {item.rule_source && <div><dt>Rule definition</dt><dd>{item.rule_source}</dd></div>}
          {item.category && <div><dt>Category</dt><dd>{item.category}</dd></div>}
        </dl>
        <section className="fr-note logic">
          <h4 className="fr-note-label">Suppression decision</h4>
          <p className="fr-note-text">{details.reason}</p>
          {trace.length > 0 && <><h4 className="fr-note-label suppression-subheading">Evaluation trace</h4><ol className="suppression-trace">{trace.map((entry, index) => <li key={index}>{asText(entry)}</li>)}</ol></>}
          {consulted.length > 0 && <><h4 className="fr-note-label suppression-subheading">Consulted files</h4><ul className="suppression-trace">{consulted.map((file, index) => <li key={index}>{asText(file)}</li>)}</ul></>}
        </section>
        <section><h4 className="fr-note-label">Source evidence</h4>
          <pre className="suppression-code">{safeLines(item.context_before).map((line, index) => <span key={`before-${index}`}>{line}{'\n'}</span>)}<mark>{item.line ?? '?'}: {item.code || '(Source text not recorded)'}</mark>{'\n'}{safeLines(item.context_after).map((line, index) => <span key={`after-${index}`}>{line}{'\n'}</span>)}</pre>
        </section>
        {item.rdl_text && <details className="suppression-rule"><summary>Full RDL rule</summary><pre className="suppression-code">{item.rdl_text}</pre></details>}
        {item.logic_reason && <p className="fr-note-text"><strong>Rule intent:</strong> {item.logic_reason}</p>}
        {promoted && item.notes && <div className="fr-note dev"><h4 className="fr-note-label">Analyst note</h4><p>{item.notes}</p></div>}
        {!promoted && <div className="suppression-actions"><button className="btn btn-secondary btn-sm" onClick={() => setShowModal(true)}>Promote to Finding</button></div>}
      </div>}
    </article>
  </>
}

export default function SuppressedPanel({ runUuid, onLoaded }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [search, setSearch] = useState('')
  const [filterStatus, setFilterStatus] = useState('all')
  const [filterEngine, setFilterEngine] = useState('all')
  const [page, setPage] = useState(0)
  useEffect(() => {
    if (!runUuid) return
    let cancelled = false
    setLoading(true); setError(''); setData(null); setPage(0)
    getSuppressedFindings(runUuid).then(result => {
      if (cancelled) return
      setData(result)
      onLoaded?.(result?.summary?.total_suppressed ?? 0)
    }).catch(err => { if (!cancelled) setError(err.message || 'Failed to load suppressed findings') })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [runUuid])
  const items = useMemo(() => (data?.suppressed || []).map(item => ({ ...item, details: suppressionDetails(item) })), [data])
  const engines = useMemo(() => [...new Set(items.map(item => item.details.engine))].sort(), [items])
  const ruleCount = useMemo(() => new Set(items.map(item => item.details.source || item.rule_title).filter(Boolean)).size, [items])
  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase()
    return items.filter(item => (filterStatus === 'all' || item.status === filterStatus) &&
      (filterEngine === 'all' || item.details.engine === filterEngine) &&
      (!query || [item.rule_title, item.rule_id, item.file, item.platform, item.category, item.details.source, item.details.engine, item.details.reason, item.rdl_text].some(value => String(value || '').toLowerCase().includes(query))))
  }, [items, search, filterStatus, filterEngine])
  function handlePromoted(id, fields) {
    setData(previous => ({ ...previous, suppressed: previous.suppressed.map(item => item.id === id ? { ...item, ...fields, status: 'confirmed_finding' } : item) }))
  }
  function change(setter, value) { setter(value); setPage(0) }
  const pages = Math.max(1, Math.ceil(filtered.length / 50))
  const currentPage = Math.min(page, pages - 1)
  const promoted = items.filter(item => item.status === 'confirmed_finding').length
  if (loading) return <div className="empty-state"><div className="fr-spinner" />Loading suppressed findings…</div>
  if (error) return <div className="error-banner" role="alert">{error}</div>
  if (!items.length) return <div className="empty-state"><div className="empty-title">No suppressed findings</div><div className="empty-msg">No suppression decisions were recorded for this scan.</div></div>
  return <div className="suppression-panel">
    <div className="suppression-intro"><h3>Suppressed Findings</h3><p>Matches excluded by recorded rule logic. Suppression does not by itself confirm a false positive; review the decision and evidence below.</p></div>
    <div className="fr-stats-row">
      <SummaryCard value={items.length - promoted} label="Currently suppressed" color="var(--warning-color)" />
      <SummaryCard value={ruleCount} label="Rules with suppressions" color="var(--primary)" />
      <SummaryCard value={promoted} label="Promoted to findings" color="var(--success-color)" />
    </div>
    <div className="suppression-toolbar">
      <input className="fr-search" aria-label="Search suppressed findings" placeholder="Search rule, file, reason or RDL…" value={search} onChange={event => change(setSearch, event.target.value)} />
      <select aria-label="Suppression status" value={filterStatus} onChange={event => change(setFilterStatus, event.target.value)}><option value="all">All statuses</option><option value="suppressed">Suppressed only</option><option value="confirmed_finding">Promoted only</option></select>
      <select aria-label="Suppressing engine" value={filterEngine} onChange={event => change(setFilterEngine, event.target.value)}><option value="all">All engines</option>{engines.map(engine => <option key={engine}>{engine}</option>)}</select>
      <a className="btn btn-secondary btn-sm" href={getSuppressedReportUrl(runUuid, 'json')} download>Export JSON</a>
      <a className="btn btn-secondary btn-sm" href={getSuppressedReportUrl(runUuid, 'html')} download>Export HTML</a>
    </div>
    <div className="suppression-count" role="status">{filtered.length} of {items.length} records · {engines.join(', ')}</div>
    <div className="suppression-list">
      {filtered.slice(currentPage * 50, (currentPage + 1) * 50).map((item, index) => <SuppressedRow key={`${runUuid}:${item.id || currentPage * 50 + index}`} item={item} runUuid={runUuid} onPromoted={handlePromoted} />)}
      {!filtered.length && <div className="empty-state">No findings match these filters.</div>}
    </div>
    {pages > 1 && <nav className="suppression-pagination" aria-label="Suppressed findings pages"><button className="btn btn-secondary btn-sm" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>Previous</button><span>Page {currentPage + 1} of {pages}</span><button className="btn btn-secondary btn-sm" disabled={currentPage === pages - 1} onClick={() => setPage(currentPage + 1)}>Next</button></nav>}
  </div>
}
