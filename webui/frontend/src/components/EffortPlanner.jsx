import { useEffect, useRef, useState } from 'react'
import { createEffortPlan, getEffortPlan, artifactUrl } from '../api'
import EffortAssumptions from './EffortAssumptions'

const SCENARIOS = [
  ['assisted', 'Daksh-assisted review', 'Plan at 50% of manual reviewer time by default, using the scan inventory and traces.'],
  ['targeted', 'Targeted review', 'Choose authentication, authorization, taint analysis and other domains. Shared evidence and files count once.'],
  ['manual', 'Fully manual review', 'Review the same scope, map files and technologies, and reconstruct paths without Daksh guidance.'],
  ['ai', 'AI-assisted review', 'Plan at 10% of Daksh-assisted reviewer time by default; adjust using your measured workflow.'],
]
const range = (value, digits = 2) => {
  if (!value) return 'Not estimable'
  const format = (n) => n.toLocaleString(undefined, { maximumFractionDigits: digits })
  return value[0] === value[1] ? format(value[0]) : `${format(value[0])}–${format(value[1])}`
}
const hourRange = (values) => {
  if (!values) return 'Not estimable'
  const labels = values.map(value => value > 0 && value < 0.25 ? '<0.5' : (Math.round(value * 2) / 2).toLocaleString(undefined, { maximumFractionDigits: 1 }))
  return labels[0] === labels[1] ? labels[0] : labels.join('–')
}
const dayRange = (values) => {
  if (!values) return 'Not estimable'
  const labels = values.map(value => value > 0 && value < 0.125 ? '<0.25' : (Math.round(value * 4) / 4).toLocaleString(undefined, { maximumFractionDigits: 2 }))
  return labels[0] === labels[1] ? labels[0] : labels.join('–')
}
const scenarioTitle = (mode) => SCENARIOS.find(([id]) => id === mode)?.[1] || 'Review'


function save(content, name, type) {
  const url = URL.createObjectURL(new Blob([content], { type }))
  const link = document.createElement('a'); link.href = url; link.download = name; link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export default function EffortPlanner({ run, artifactIndex, onReady }) {
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
  const requestVersion = useRef(0)
  const readyCallback = useRef(onReady)
  readyCallback.current = onReady
  const runId = run?.run_uuid
  const pending = ['running', 'queued', 'stopping'].includes(run?.status)
  useEffect(() => {
    alive.current = true
    let cancelled = false
    const version = ++requestVersion.current
    setLoading(true); setReport(null); setError(''); setDirty(false); setBusy(false)
    if (!runId || pending) { setLoading(false); return () => { alive.current = false } }
    getEffortPlan(runId).then((data) => {
      if (cancelled || version !== requestVersion.current) return
      setReport(data); setMode(data.mode); setAssumptions(data.assumptions); setDomains(data.selected_domains)
      readyCallback.current?.()
    }).catch((err) => { if (!cancelled && version === requestVersion.current) setError(err.message) })
      .finally(() => { if (!cancelled && version === requestVersion.current) setLoading(false) })
    return () => { cancelled = true; alive.current = false; ++requestVersion.current }
  }, [runId, pending])

  const options = { mode, domains, assumptions, calibration }
  async function generate(nextOptions = options) {
    const version = ++requestVersion.current
    setBusy(true); setError('')
    try {
      const result = await createEffortPlan(runId, nextOptions)
      if (alive.current && version === requestVersion.current) { setReport(result); setDirty(false); readyCallback.current?.() }
    } catch (err) { if (alive.current && version === requestVersion.current) setError(err.message) }
    finally { if (alive.current && version === requestVersion.current) setBusy(false) }
  }
  function changeDomains(next) {
    setDomains(next); setDirty(true)
    generate({ ...options, domains: next })
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
      if (profile.model_version && !['2.0', report.model_version].includes(profile.model_version)) throw new Error('Unsupported baseline model version')
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
  const resultCurrent = !dirty && report.mode === mode
  const comparison = report.comparison
  const historical = [...(artifactIndex?.other_html || []), ...(artifactIndex?.pdf_files || [])].filter((a) => a.toLowerCase().includes('estimat'))
  return <div className="effort-planner ip-section-body">
    <div className="effort-heading"><div><h2>Security review estimate</h2><p>Plan reviewer time for the scanned code. Choose a scenario to compare the work required.</p></div><span className="badge">Model {report.model_version}</span></div>
    <fieldset className="effort-scenarios" disabled={busy}><legend>Review scenario</legend>{SCENARIOS.map(([id, title, description]) => <label key={id} className={mode === id ? 'selected' : ''}>
      <input type="radio" name="effort-scenario" value={id} checked={mode === id} onChange={() => { setMode(id); setDirty(true); generate({ ...options, mode: id }) }} />
      <span><strong>{title}</strong><small>{description}</small></span></label>)}</fieldset>
    {mode === 'targeted' ? <fieldset className="effort-domains" disabled={busy}><legend>Review domains</legend>
      <div className="effort-actions"><button className="btn btn-ghost btn-sm" onClick={() => { changeDomains(report.workload.domains.map((d) => d.id)) }}>Select all</button><button className="btn btn-ghost btn-sm" onClick={() => { changeDomains([]) }}>Clear all</button></div>
      <p>Changes recalculate automatically. Shared files count once; inspection effort uses the selected domains’ share of each file’s recorded domains. This is a planning allocation, not measured line coverage. Controls without findings still require exploration.</p>
      <div className="effort-domain-grid">{report.workload.domains.map((domain) => <label key={domain.id}><input type="checkbox" checked={domains.includes(domain.id)} aria-label={domain.label}
        onChange={(event) => { changeDomains(event.target.checked ? [...domains, domain.id] : domains.filter((id) => id !== domain.id)) }} />
        <span><strong>{domain.label}</strong><small>{domain.review_units} sites · {domain.related_files} related files</small></span></label>)}</div>
    </fieldset> : null}
    <details className="effort-settings"><summary>Custom reviewer or company baseline</summary>
      <p>Set the manual task baseline and scenario fractions. A fraction of 0.5 means 50% of manual effort for Daksh; 0.1 means 10% of Daksh effort for AI. Additional evidence work shares the configured inspection budget; the task breakdown shows the allocated hours.</p>
      <p>Save organization-wide baselines in Settings → Effort Estimation. Export a baseline to reuse or share it with another reviewer; omitted rates in imported profiles use the current organization defaults. Code inspection uses effective LOC.</p>
      <div className="effort-actions"><button className="btn btn-ghost btn-sm" disabled={busy} onClick={() => { setAssumptions(report.baseline_defaults); setCalibration([]); setDirty(true) }}>Use organization defaults</button>
        <button className="btn btn-ghost btn-sm" disabled={busy} onClick={() => save(JSON.stringify({ model_version: report.model_version, assumptions }, null, 2), 'reviewer-effort-baseline.json', 'application/json')}>Export baseline</button>
        <label>Import baseline <input type="file" accept="application/json,.json" onChange={importBaseline} disabled={busy} /></label></div>
      <EffortAssumptions values={assumptions} disabled={busy} onChange={(values) => { setAssumptions(values); setDirty(true) }} />
      <p>Import observed task samples as JSON: <code>{'[{"component":"active_minutes","units":5,"hours":1}]'}</code>. At least five observations per component are required. Observed ranges are not confidence intervals.</p>
      <label className="effort-calibration">Import calibration samples<input type="file" accept="application/json,.json" onChange={importCalibration} disabled={busy} /></label>
      {calibration.length ? <p>{calibration.length} samples loaded. <button className="btn btn-ghost btn-sm" disabled={busy} onClick={() => { setCalibration([]); setDirty(true) }}>Remove calibration</button></p> : null}
    </details>
    <div className="effort-actions"><button className="btn btn-primary" disabled={busy} onClick={() => generate()}>{busy ? 'Updating estimate…' : 'Update estimate'}</button>
      <button className="btn btn-ghost" disabled={busy || dirty} onClick={downloadHtml}>Download HTML</button>
      <button className="btn btn-ghost" disabled={busy || dirty} onClick={() => save(JSON.stringify(report, null, 2), 'review-effort-plan.json', 'application/json')}>Download JSON</button>
    </div>
    {error ? <p role="alert" className="effort-notice">{error}</p> : null}
    {dirty && !busy ? <p role="status" className="effort-notice">Settings changed. Update the estimate to see the new result and enable downloads.</p> : null}
    {resultCurrent ? <div className="effort-report" aria-busy={busy}>
      <h3>{scenarioTitle(report.mode)}</h3>
      <div className="effort-results" aria-live="polite"><div><small>Reviewer hours</small><strong>{hourRange(report.total_hours)}</strong></div><div><small>Reviewer days · {report.assumptions.hours_per_day} hours/day</small><strong>{report.total_days_min == null ? 'Not estimable' : dayRange([report.total_days_min, report.total_days_max])}</strong></div><div><small>Code in scope</small><strong>{counts.files.toLocaleString()} files</strong><small>{counts.effective_loc.toLocaleString()} lines of code, excluding comments and blanks</small></div></div>
      {report.mode === 'targeted' ? <p>{report.selected_domains.length} selected domains · {counts.files} related files · {counts.inspection_effective_loc?.toLocaleString()} equivalent LOC of planned inspection. Shared files are allocated across their recorded domains; this does not measure the exact source lines implementing each control.</p> : null}
      {comparison ? <section className="effort-comparison" aria-label="Assisted and manual comparison">
        <h3>Same scope, three review approaches</h3>
        <div className="effort-comparison-totals"><div><span>Daksh-assisted review</span><strong>{hourRange(comparison.assisted.total_hours)}{comparison.assisted.total_hours ? ' hours' : ''}</strong></div><div><span>Fully manual review</span><strong>{hourRange(comparison.manual.total_hours)}{comparison.manual.total_hours ? ' hours' : ''}</strong></div>{comparison.ai ? <div><span>AI-assisted review</span><strong>{hourRange(comparison.ai.total_hours)}{comparison.ai.total_hours ? ' hours' : ''}</strong></div> : null}</div>
        <p>{comparison.basis}</p>
        <details><summary>Where the effort differs</summary>
          {comparison.differences.length ? <div className="effort-table"><table><thead><tr><th>Task</th><th>Daksh-assisted hours</th><th>Manual hours</th></tr></thead><tbody>{comparison.differences.map((row) => <tr key={row.label}><td>{row.label}</td><td>{hourRange(row.assisted_hours)}</td><td>{hourRange(row.manual_hours)}</td></tr>)}</tbody></table></div> : <p>The current task rates produce the same effort. Adjust the reviewer baseline if your measured workflow differs.</p>}
        </details>
      </section> : null}
      <p className="effort-basis">{report.planning_basis}</p>
      <p className="effort-basis">{report.calibration_samples?.length ? 'Uses your observed task rates.' : 'Uses configurable planning rates.'} These estimates cover reviewer work; actual effort depends on code complexity and the reviewer.</p>
      {report.warnings.length ? <aside className="effort-notice"><strong>Scope notes</strong><ul>{report.warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul></aside> : null}
      <details className="effort-evidence"><summary>Scan evidence used in this estimate</summary>
        <dl><div><dt>Flagged locations</dt><dd>{counts.areas_of_interest.toLocaleString()}</dd></div><div><dt>Rule-supported or reviewer-confirmed locations</dt><dd>{counts.confirmed_review_sites.toLocaleString()}</dd></div><div><dt>Confirmed by a reviewer</dt><dd>{counts.reviewer_confirmed.toLocaleString()}</dd></div><div><dt>Excluded matches to check</dt><dd>{counts.suppressed.toLocaleString()}</dd></div><div><dt>Unresolved checks</dt><dd>{counts.unresolved.toLocaleString()}</dd></div><div><dt>Trace steps</dt><dd>{counts.trace_steps.toLocaleString()}</dd></div></dl>
        <p>Rule support means a check matched; it does not confirm a vulnerability. Counts group overlapping evidence into review locations.</p>
        <p>Technologies: {report.workload.technologies.join(', ') || 'Not recorded'}.</p>
      </details>
      {report.mode === 'ai' ? <div className="effort-notice"><strong>AI planning assumption</strong><p>Default reviewer effort is 10% of Daksh-assisted review (5% of manual). This includes human validation within the planned budget; model execution time is separate. Calibrate the fractions against your model, task mix and acceptance rate.</p></div> : null}
      {report.total_hours == null && report.mode !== 'ai' ? <p>Known task subtotal: {hourRange(report.known_work_hours)} hours. Unmeasured code inspection is additional.</p> : null}
      {report.size_ballparks?.length ? <section aria-label="Project size planning ballparks"><h3>Project size ballparks</h3><p>Representative full-code reviews at {report.assumptions.hours_per_day} productive hours per person-day, using the current baseline and full evidence allowance. These are planning examples; project complexity and selected scope change the effort.</p><div className="effort-table"><table><thead><tr><th>Project size</th><th>Effective LOC</th><th>Manual days</th><th>Daksh days</th><th>AI days</th></tr></thead><tbody>{report.size_ballparks.map(row => <tr key={row.size}><td>{row.size}</td><td>{row.effective_loc.toLocaleString()}</td><td>{dayRange(row.manual_days)}</td><td>{dayRange(row.assisted_days)}</td><td>{dayRange(row.ai_days)}</td></tr>)}</tbody></table></div></section> : null}
      <h3>Review work breakdown</h3>
      <p>Displayed hours round to the nearest half-hour; positive tasks below a quarter-hour show &lt;0.5. Rounded task rows may not add up to the displayed total. Displayed days use quarter-day increments. Calculations and JSON retain full precision.</p>
      <div className="effort-table"><table><thead><tr><th>Review task</th><th>Work to review</th><th>Reviewer hours</th><th>Planning rate</th></tr></thead><tbody>{report.components.map((row) => <tr key={row.id}><td>{row.label}</td><td><span className="effort-value-unit"><span>{row.quantity.toLocaleString()}</span>{' '}<span>{row.quantity_unit}</span></span></td><td>{hourRange(row.exact_hours || row.hours)}</td><td><span className="effort-value-unit"><span>{row.rate_unit.startsWith('hours/') ? hourRange(report.assumptions[row.assumption]) : range(report.assumptions[row.assumption])}</span>{' '}<span>{row.rate_unit}</span></span>{row.planning_multiplier ? <small> · baseline rate; shared allowance and scenario applied</small> : null}{report.calibration[row.assumption] ? ' (observed)' : ''}</td></tr>)}</tbody></table></div>
    </div> : <p role="status" className="effort-notice">{busy ? `Calculating ${scenarioTitle(mode).toLowerCase()}…` : 'Update the estimate to apply your selections.'}</p>}
    <details className="effort-explanation">
      <summary>What this estimate includes</summary>
      <ul>
        <li>Estimated reviewer time for the selected scope, using the rates above. The range is a planning guide.</li>
        <li>Overlapping findings and review domains share work. Suppressed and unresolved findings are reviewed separately.</li>
        <li>Fixing issues, retesting, runtime testing and scan or model execution time are excluded.</li>
        <li>Excluded or unsupported files may need additional review. Targeted review covers files linked to scan evidence and may miss other relevant code.</li>
        <li>Scan matches need validation. A suppressed finding does not prove the code is safe.</li>
      </ul>
      <p>Download JSON for the full inputs, assumptions and calculations.</p>
    </details>
    {historical.length ? <details><summary>Saved estimate artifacts</summary>{historical.map((path) => <p key={path}><a href={artifactUrl(path)} target="_blank" rel="noreferrer">{path.split('/').pop()}</a></p>)}</details> : null}
  </div>
}
