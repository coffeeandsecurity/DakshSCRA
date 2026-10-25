import { formatDateTime } from '../lib/datetime'
import { useEffect, useState } from 'react'
import { reportProgress } from '../lib/reportProgress'
import { generateReport, listReports, reportDownloadUrl } from '../api'
import { AudienceSelector, AUDIENCE_LABELS } from './ReportAudience'

const scopes = { full: 'Full scan', findings: 'Areas of interest', analysis: 'Advanced analysis', suppressed: 'Suppressed findings' }

export default function ReportGenerator({ runUuid, defaultAudience = 'both' }) {
  const [audience, setAudience] = useState(defaultAudience)
  const [scope, setScope] = useState('full')
  const [format, setFormat] = useState('html')
  const [reports, setReports] = useState([])
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [pollError, setPollError] = useState('')
  const [version, setVersion] = useState(0)
  useEffect(() => {
    if (!runUuid) return
    let disposed = false
    let timer
    async function refresh() {
      try {
        const items = await listReports(runUuid)
        if (disposed) return
        setReports(items)
        setPollError('')
        if (items.some(item => ['queued', 'running'].includes(item.status))) timer = setTimeout(refresh, 2000)
      } catch (err) { if (!disposed) { setPollError('Status updates are temporarily unavailable. Retrying…'); timer = setTimeout(refresh, 2000) } }
    }
    refresh()
    return () => { disposed = true; clearTimeout(timer) }
  }, [runUuid, version])
  async function generate() {
    setBusy(true); setError('')
    try {
      const item = await generateReport(runUuid, { scope, format, report_audience: audience })
      setReports(items => [item, ...items.filter(existing => existing.id !== item.id)])
      setVersion(value => value + 1)
    } catch (err) { setError(err.message) }
    finally { setBusy(false) }
  }
  return <section className="report-generator" aria-label="Generate reports">
    <h3>Generate a report</h3>
    <p>Create a report from this scan’s saved results. Reports are generated only when requested.</p>
    <AudienceSelector value={audience} onChange={setAudience} disabled={busy} />
    <div className="report-controls">
      <label>Report type<select aria-label="Report type" value={scope} onChange={event => setScope(event.target.value)}>{Object.entries(scopes).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></label>
      <label>Format<select aria-label="Format" value={format} onChange={event => setFormat(event.target.value)}><option value="html">HTML package (.zip)</option><option value="pdf">PDF</option><option value="docx">Word (.docx)</option><option value="json">JSON</option></select></label>
      <button className="btn btn-primary" disabled={!runUuid || busy} onClick={generate}>{busy ? 'Requesting…' : 'Generate report'}</button>
    </div>
    <p className="report-hint">HTML downloads as a ZIP: extract it and open index.html to browse the summary and linked detail reports offline. PDF and Word contain a consolidated report. Full scan includes saved findings, analysis, suppressed findings, and available RDL evidence and cross-references. Areas of interest are review leads, not confirmed vulnerabilities.</p>
    {error && <div className="error-banner" role="alert">{error}</div>}
    {pollError && <p role="status">{pollError}</p>}
    <div>
      {reports.length === 0 ? <p>No reports generated for this scan yet.</p> : <ul className="generated-reports">{reports.map(item => <ReportJob key={item.id} item={item} runUuid={runUuid}/>)}</ul>}
    </div>
  </section>
}

function ReportJob({ item, runUuid }) {
  const status = reportProgress(item)
  const stages = ['queued', 'collecting', 'building', 'packaging', 'finalizing', 'complete']
  const stage = stages.indexOf(status.phase)
  return <li className={`report-job report-job--${item.status}`}>
    <div className="report-job-content">
      <strong>{scopes[item.scope]} · {item.format.toUpperCase()} · {AUDIENCE_LABELS[item.report_audience || 'both']}</strong>
      <small>{formatDateTime(item.created_at)}{item.size != null ? ` · ${(item.size / 1024).toFixed(1)} KB` : ''}</small>
      <p className="report-job-status" role="status"><span className={status.active ? 'report-spinner' : 'report-status-dot'} aria-hidden="true"/>{status.message}</p>
      {status.active && <>
        <div className={`report-progress ${status.counted ? '' : 'report-progress--indeterminate'}`} role="progressbar" aria-label="Report generation" aria-valuemin={status.counted ? 0 : undefined} aria-valuemax={status.counted ? status.total : undefined} aria-valuenow={status.counted ? status.completed : undefined} aria-valuetext={status.message}>
          <span style={status.counted ? { width: `${status.completed / status.total * 100}%` } : undefined}/>
        </div>
        {status.counted && <small>{status.completed} of {status.total} {status.unit} in this stage</small>}
        {stage >= 0 && <ol className="report-stages" aria-label="Report stages">{[['Queued', 0], ['Building', 1], ['Packaging', 3], ['Ready', 5]].map(([label, threshold], index, list) => <li key={label} className={stage >= threshold ? 'is-reached' : ''} aria-current={stage >= threshold && (index === list.length - 1 || stage < list[index + 1][1]) ? 'step' : undefined}>{label}</li>)}</ol>}
      </>}
      {item.error && <p role="alert">{item.error}</p>}
    </div>
    {item.status === 'complete' && <a className="link-btn" href={reportDownloadUrl(runUuid, item.id)} download>Download {item.format.toUpperCase()}</a>}
  </li>
}
