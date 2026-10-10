import { useEffect, useRef, useState } from 'react'
import { createEffortPlan, getEffortPlan, artifactUrl } from '../api'
import EffortAssumptions from './EffortAssumptions'

const SCENARIOS = [
  ['assisted', 'Daksh-assisted manual review', 'Inspect all inventoried code, validate findings and suppressed decisions, and review retained traces with Daksh context.'],
  ['targeted', 'Targeted review', 'Choose authentication, authorization, taint analysis and other domains. Shared evidence and files count once.'],
  ['manual', 'Fully manual review', 'Inspect all inventoried code and manually map files, technologies and paths. Scan evidence supplies a workload proxy.'],
  ['ai', 'AI-assisted review', 'Inventory the work and benchmark your model and hardware. No universal duration or speedup is assumed.'],
]
const range = (value) => value ? `${value[0].toLocaleString()}–${value[1].toLocaleString()}` : 'Not estimable'

function save(content, name, type) {
  const url = URL.createObjectURL(new Blob([content], { type }))
  const link = document.createElement('a'); link.href = url; link.download = name; link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export default function EffortPlanner({ run, artifactIndex }) {
  const [report, setReport] = useState(null)
  const [mode, setMode] = useState('assisted')
  const [domains, setDomains] = useState([])
  const [assumptions, setAssumptions] = useState({})
  const [calibration, setCalibration] = useState([])
  const [busy, setBusy] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [dirty, setDirty] = useState(false)
  const alive = useRef(true)
  const runId = run?.run_uuid
  const pending = ['running', 'queued', 'stopping'].includes(run?.status)
  useEffect(() => {
    alive.current = true
    let cancelled = false
    if (!runId || pending) { setLoading(false); return () => { alive.current = false } }
    getEffortPlan(runId).then((data) => {
      if (cancelled) return
      setReport(data); setAssumptions(data.assumptions); setDomains(data.selected_domains)
    }).catch((err) => { if (!cancelled) setError(err.message) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true; alive.current = false }
  }, [runId, pending])

  const options = { mode, domains, assumptions, calibration }
  async function generate() {
    setBusy(true); setError('')
    try {
      const result = await createEffortPlan(runId, options)
      if (alive.current) { setReport(result); setDirty(false) }
    } catch (err) { if (alive.current) setError(err.message) }
    finally { if (alive.current) setBusy(false) }
  }
  async function downloadHtml() {
    setBusy(true); setError('')
    try { save(await createEffortPlan(runId, options, true), 'review-effort-plan.html', 'text/html') }
    catch (err) { if (alive.current) setError(err.message) }
    finally { if (alive.current) setBusy(false) }
  }
  async function importCalibration(event) {
    const file = event.target.files?.[0]
    if (!file) return
    try {
      if (file.size > 1024 * 1024) throw new Error('Calibration file must be smaller than 1 MB')
      const samples = JSON.parse(await file.text())
      if (!Array.isArray(samples)) throw new Error('Calibration must be a JSON array of component, units and hours samples')
      setCalibration(samples); setDirty(true); setError('')
    } catch (err) { setError(err.message) }
    event.target.value = ''
  }
  async function importBaseline(event) {
    const file = event.target.files?.[0]
    if (!file) return
    try {
      if (file.size > 1024 * 1024) throw new Error('Baseline file must be smaller than 1 MB')
      const profile = JSON.parse(await file.text())
      if (profile.model_version && profile.model_version !== report.model_version) throw new Error('Unsupported baseline model version')
      const values = profile.assumptions
      if (!values || typeof values !== 'object' || Array.isArray(values)) throw new Error('Baseline requires an assumptions object')
      const defaults = report.baseline_defaults
      for (const [key, value] of Object.entries(values)) {
        if (!(key in defaults)) throw new Error(`Unknown baseline rate: ${key}`)
        if (key === 'hours_per_day') {
          if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0 || value > 24) throw new Error('Productive hours must be greater than zero and at most 24')
        } else if (!Array.isArray(value) || value.length !== 2 || value.some((v) => typeof v !== 'number' || !Number.isFinite(v) || v < 0 || v > 100000) || value[0] > value[1] || (key === 'inspection_loc_per_hour' && value[0] <= 0)) {
          throw new Error(`${key} requires an ordered [low, high] range`)
        }
      }
      setAssumptions({ ...defaults, ...values }); setCalibration([]); setDirty(true); setError('')
    } catch (err) { setError(err.message) }
    event.target.value = ''
  }
  if (pending) return <div className="empty-state"><div className="empty-title">Effort planning follows the completed scan</div><p>Findings, suppression decisions, LOC and analysis must be available before review work is estimated.</p></div>
  if (loading) return <p role="status">Loading review workload…</p>
  if (!report) return <div className="empty-state"><div className="empty-title">Review workload unavailable</div><p role="alert">{error || 'No retained scan data.'}</p></div>
  const counts = report.selected_workload
  const historical = [...(artifactIndex?.other_html || []), ...(artifactIndex?.pdf_files || [])].filter((a) => a.toLowerCase().includes('estimat'))
  return <div className="effort-planner ip-section-body">
    <div className="effort-heading"><div><h2>Review effort planner</h2><p>Measured scope, explicit assumptions and selectable review work. Ranges are planning bounds, not confidence intervals.</p></div><span className="badge">Model {report.model_version}</span></div>
    <fieldset className="effort-scenarios" disabled={busy}><legend>Review scenario</legend>{SCENARIOS.map(([id, title, description]) => <label key={id} className={mode === id ? 'selected' : ''}>
      <input type="radio" name="effort-scenario" value={id} checked={mode === id} onChange={() => { setMode(id); setDirty(true) }} />
      <span><strong>{title}</strong><small>{description}</small></span></label>)}</fieldset>
    {mode === 'targeted' ? <fieldset className="effort-domains" disabled={busy}><legend>Review domains</legend>
      <div className="effort-actions"><button className="btn btn-ghost btn-sm" onClick={() => { setDomains(report.workload.domains.map((d) => d.id)); setDirty(true) }}>Select all</button><button className="btn btn-ghost btn-sm" onClick={() => { setDomains([]); setDirty(true) }}>Clear all</button></div>
      <p>Related files come from retained evidence. Controls without findings still require exploration; this is not a complete control inventory.</p>
      <div className="effort-domain-grid">{report.workload.domains.map((domain) => <label key={domain.id}><input type="checkbox" checked={domains.includes(domain.id)} aria-label={domain.label}
        onChange={(event) => { setDomains((current) => event.target.checked ? [...current, domain.id] : current.filter((id) => id !== domain.id)); setDirty(true) }} />
        <span><strong>{domain.label}</strong><small>{domain.review_units} sites · {domain.related_files} related files</small></span></label>)}</div>
    </fieldset> : null}
    <details className="effort-settings"><summary>Custom reviewer or company baseline</summary>
      <p>Use the organization defaults or override rates for this report. Enter 10 and 15 for a 10–15 minute range, or 20 and 20 for a fixed 20 minutes. Areas of interest and confirmed/RDL-supported findings have separate rates; fully manual review has its own issue rates. RDL support is not proof of exploitability.</p>
      <p>Save organization-wide baselines in Settings → Effort Estimation. Export a baseline to reuse or share it with another reviewer; omitted rates in imported profiles use the current organization defaults. Code inspection uses effective LOC.</p>
      <div className="effort-actions"><button className="btn btn-ghost btn-sm" disabled={busy} onClick={() => { setAssumptions(report.baseline_defaults); setCalibration([]); setDirty(true) }}>Use organization defaults</button>
        <button className="btn btn-ghost btn-sm" disabled={busy} onClick={() => save(JSON.stringify({ model_version: report.model_version, assumptions }, null, 2), 'reviewer-effort-baseline.json', 'application/json')}>Export baseline</button>
        <label>Import baseline <input type="file" accept="application/json,.json" onChange={importBaseline} disabled={busy} /></label></div>
      <EffortAssumptions values={assumptions} disabled={busy} onChange={(values) => { setAssumptions(values); setDirty(true) }} />
      <p>Import observed task samples as JSON: <code>{'[{"component":"active_minutes","units":5,"hours":1}]'}</code>. At least five observations per component are required. Observed ranges are not confidence intervals.</p>
      <label className="effort-calibration">Import calibration samples<input type="file" accept="application/json,.json" onChange={importCalibration} disabled={busy} /></label>
      {calibration.length ? <p>{calibration.length} samples loaded. <button className="btn btn-ghost btn-sm" disabled={busy} onClick={() => { setCalibration([]); setDirty(true) }}>Remove calibration</button></p> : null}
    </details>
    <div className="effort-actions"><button className="btn btn-primary" disabled={busy} onClick={generate}>{busy ? 'Preparing…' : 'Generate estimation report'}</button>
      <button className="btn btn-ghost" disabled={busy || dirty} onClick={downloadHtml}>Download HTML</button>
      <button className="btn btn-ghost" disabled={busy || dirty} onClick={() => save(JSON.stringify(report, null, 2), 'review-effort-plan.json', 'application/json')}>Download JSON</button>
    </div>
    {error ? <p role="alert" className="effort-notice">{error}</p> : null}
    {dirty ? <p role="status" className="effort-notice">Selection changed. Generate a report to update the result and enable downloads.</p> : null}
    <div className="effort-results" aria-live="polite"><div><small>Person-hours · {report.mode} scenario</small><strong>{range(report.total_hours)}</strong></div><div><small>Person-days · {report.assumptions.hours_per_day} productive hours/day</small><strong>{report.total_days_min == null ? 'Not estimable' : `${report.total_days_min}–${report.total_days_max}`}</strong></div><div><small>Selected code scope</small><strong>{counts.files.toLocaleString()} files</strong><small>{counts.effective_loc.toLocaleString()} effective LOC</small></div></div>
    <p>{counts.areas_of_interest} areas of interest, {counts.confirmed_review_sites} confirmed/RDL-supported review sites ({counts.reviewer_confirmed} reviewer-confirmed), {counts.suppressed} suppressed, {counts.unresolved} unresolved. {counts.trace_steps} trace steps. RDL support is not reviewer confirmation of exploitability.</p>
    <p className="muted">Technologies: {report.workload.technologies.join(', ') || 'Not recorded'}. Scope: {report.code_scope}. {report.assumption_basis}.</p>
    {report.mode === 'ai' ? <div className="effort-notice"><strong>AI duration requires your own benchmark</strong><ul>{report.ai_measurements_required.map((item) => <li key={item}>{item}</li>)}</ul></div> : null}
    {report.warnings.map((warning) => <p key={warning} className="effort-notice">{warning}</p>)}
    <p>{report.rounding}</p>
    {report.total_hours == null && report.mode !== 'ai' ? <p>Known task subtotal: {range(report.known_work_hours)} hours. Unmeasured inspection work is additional.</p> : null}
    <div className="effort-table"><table><thead><tr><th>Review task</th><th>Quantity</th><th>Person-hours</th><th>Applied rate</th></tr></thead><tbody>{report.components.map((row) => <tr key={row.id}><td>{row.label}</td><td>{row.quantity.toLocaleString()}</td><td>{range(row.hours)}</td><td>{range(report.assumptions[row.assumption])}{report.calibration[row.assumption] ? ' (observed)' : ''}</td></tr>)}</tbody></table></div>
    <details><summary>Method, limits and traceability</summary><p>{report.deduplication}</p><ul>{report.limitations.map((item) => <li key={item}>{item}</li>)}</ul><p>Fingerprint: <code>{report.input_fingerprint}</code>. JSON includes exact inputs and calculations. Remediation and retesting are separate.</p></details>
    {historical.length ? <details><summary>Saved estimate artifacts</summary>{historical.map((path) => <p key={path}><a href={artifactUrl(path)} target="_blank" rel="noreferrer">{path.split('/').pop()}</a></p>)}</details> : null}
  </div>
}
