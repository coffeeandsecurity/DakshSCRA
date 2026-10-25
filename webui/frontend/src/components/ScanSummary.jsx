import { useId, useMemo, useRef, useState } from 'react'
import { buildScanSummary, recordedNumber } from '../lib/scanSummary'
import { formatDuration } from '../lib/duration'

const TABS = ['Overview', 'Coverage', 'Execution', 'Configuration']
const MODES = { both: 'Comprehensive Review', v2: 'Finding Analysis Only', v1: 'Areas of Interest Review Only' }
const number = value => recordedNumber(value) == null ? 'Not recorded' : Number(value).toLocaleString()
const duration = value => value == null ? 'Not recorded' : formatDuration(value)
function Metric({ label, value, note }) { return <div className="ss-metric"><span>{label}</span><strong className={typeof value === 'string' && /^[A-Za-z]/.test(value) ? 'ss-value-text' : undefined}>{value}</strong>{note && <small>{note}</small>}</div> }
function Chart({ rows, onSelect }) {
  const maximum = Math.max(1, ...rows.map(row => row.value || 0))
  return <div className="ss-bars">{rows.map((row, index) => <div className="ss-bar-row" key={row.label}>
    {onSelect ? <button type="button" className="link-btn" onClick={() => onSelect(row)}>{row.label}</button> : <span>{row.label}</span>}
    <div className="ss-bar-track"><span style={{ width: `${(row.value || 0) / maximum * 100}%`, background: row.color || ['#356fe5', '#16877b', '#8563c2', '#929aaa'][index % 4] }} /></div><strong>{row.display ?? number(row.value)}</strong>
  </div>)}</div>
}
function Facts({ rows }) { return <dl className="ss-facts">{rows.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value == null || value === '' ? 'Not recorded' : value}</dd></div>)}</dl> }
export default function ScanSummary({ run, data, loading, error, suppressedCount, onNavigate, reportRoot, reportFolderUrl }) {
  const [tab, setTab] = useState('Overview'), [languageMetric, setLanguageMetric] = useState('files')
  const id = useId(), refs = useRef([])
  const m = useMemo(() => buildScanSummary(run, data, suppressedCount), [run, data, suppressedCount])
  const included = m.files ?? m.identified
  const v1Omitted = m.mode === 'v2'
  function tabKey(event, index) {
    let next
    if (event.key === 'ArrowRight') next = (index + 1) % TABS.length
    else if (event.key === 'ArrowLeft') next = (index + TABS.length - 1) % TABS.length
    else if (event.key === 'Home') next = 0
    else if (event.key === 'End') next = TABS.length - 1
    else return
    event.preventDefault(); setTab(TABS[next]); refs.current[next]?.focus()
  }
  return <section className="scan-summary">
    <div className="ss-heading"><h2>Scan overview</h2><p>Review signals and recorded scan coverage.</p></div>
    <div className="ss-tabs" role="tablist" aria-label="Summary sections">{TABS.map((label, index) => <button type="button" key={label} ref={element => { refs.current[index] = element }} role="tab" id={`${id}-tab-${label}`} aria-controls={`${id}-panel-${label}`} aria-selected={tab === label} tabIndex={tab === label ? 0 : -1} onClick={() => setTab(label)} onKeyDown={event => tabKey(event, index)}>{label}</button>)}</div>
    {loading && <p role="status" className="ss-note">Loading recorded scan metrics…</p>}
    {error && <p role="alert" className="error-banner">{error}</p>}
    {['queued', 'running', 'stopping'].includes(run.status) && <p className="ss-notice">This scan is still active. Final metrics will appear when its results are saved. Use Live Scan Telemetry for current progress.</p>}
    {m.removed && <p className="ss-notice">Saved scan data has been removed. Scan history and configuration remain available.</p>}
    <div role="tabpanel" id={`${id}-panel-${tab}`} aria-labelledby={`${id}-tab-${tab}`} tabIndex={0}>
      {tab === 'Overview' && <>
        <div className="ss-metrics">
          <Metric label={m.files == null ? 'Source files identified' : 'Files scanned'} value={number(included)} note="Source files selected for code review." />
          <Metric label="Lines of code" value={number(m.loc)} note="Recorded source line count." />
          <Metric label="Security areas of interest" value={v1Omitted ? 'Not included' : number(m.areas)} note="Source issue families and path rule groups." />
          <Metric label="Suppressed candidates" value={number(m.suppressed)} note="Stored suppression records." />
        </div>
        <div className="ss-columns">
          <div className="ss-chart"><h3>Review inventory</h3>{v1Omitted ? <p className="ss-note">This scan uses Finding Analysis Only. View its RDL findings in Vulnerability Analysis.</p> : <Chart rows={[{ label: 'Code areas of interest', value: m.code, color: '#356fe5', destination: 'code-aoi' }, { label: 'Path areas of interest', value: m.paths, color: '#16877b', destination: 'path-aoi' }, { label: 'Suppressed candidates', value: m.suppressed, color: '#929aaa', destination: 'suppressed' }]} onSelect={row => onNavigate(row.destination)} />}
            <p className="ss-note">Different review counts. Suppression is not proof of safety.</p></div>
          <div className="ss-chart"><h3>Scan scope</h3><div className="ss-scope-values"><Metric label="Selected source files" value={number(included)} /><Metric label="Other discovered files" value={number(m.otherFiles)} /><Metric label="Total discovered" value={number(m.discovered)} /></div>
            {m.otherFiles != null && m.discovered > 0 && <div className="ss-scope-bar" role="img" aria-label={`${number(included)} selected source files out of ${number(m.discovered)} discovered files`}><span style={{ width: `${included / m.discovered * 100}%` }} /><span style={{ width: `${m.otherFiles / m.discovered * 100}%` }} /></div>}
            <p className="ss-note">File selection does not measure vulnerability coverage.</p></div>
        </div>
        <div className="ss-execution"><h3>Execution at a glance</h3><div className="ss-metrics"><Metric label="Duration" value={duration(m.duration)} /><Metric label="Source rules" value={number(m.rules)} /><Metric label="Parser errors" value={number(m.parserErrors)} /><Metric label="Analyzer targets" value={m.completed == null || m.targets == null ? 'Not recorded' : `${m.completed} / ${m.targets}`} /></div></div>
        <div className="ss-actions"><button type="button" className="btn btn-primary" onClick={() => onNavigate(v1Omitted ? 'rdl-shadow' : 'findings')}>{v1Omitted ? 'View RDL findings' : 'View areas of interest'}</button>{!v1Omitted && m.mode !== 'v1' && <button type="button" className="btn btn-ghost" onClick={() => onNavigate('rdl-shadow')}>View RDL findings</button>}<button type="button" className="btn btn-ghost" onClick={() => onNavigate('advanced-analysis')}>View advanced analysis</button><button type="button" className="btn btn-ghost" onClick={() => onNavigate('suppressed')}>View suppressed areas of interest</button></div>
      </>}
      {tab === 'Coverage' && <>
        <div className="ss-metrics"><Metric label="Recorded evidence locations" value={number(m.locations)} note="Distinct locations within each source issue family." /><Metric label="Files with code review areas" value={number(m.evidenceFiles)} note="Distinct recorded source paths." /><Metric label="Directories visited" value={number(m.directories)} /><Metric label="Review mode" value={MODES[m.mode] || 'Not recorded'} /></div>
        <div className="ss-columns"><div className="ss-chart"><div className="ss-chart-heading"><h3>Source composition</h3><div className="ss-switch" role="group" aria-label="Source composition metric">{['files', 'loc'].map(value => <button key={value} type="button" aria-pressed={languageMetric === value} onClick={() => setLanguageMetric(value)}>{value === 'files' ? 'Files' : 'Lines of code'}</button>)}</div></div>
          {m.languages.length ? <Chart rows={m.languages.map(row => ({ label: row.label, value: row[languageMetric] })).sort((a, b) => b.value - a.value)} /> : <p className="ss-note">No per-file breakdown was recorded.</p>}<p className="ss-note">Grouped by file extension from the recorded line-count inventory.</p></div>
          <div className="ss-chart"><h3>Loaded source rules</h3>{m.platformRules.length ? <Chart rows={m.platformRules} /> : <p className="ss-note">No rule breakdown was recorded.</p>}<p className="ss-note">Rule counts describe loaded checks. They do not measure security coverage or exploitability.</p></div></div>
      </>}
      {tab === 'Execution' && <>
        <div className="ss-metrics"><Metric label="Scan status" value={run.status} /><Metric label="Analyzer targets completed" value={m.completed == null || m.targets == null ? 'Not recorded' : `${m.completed} / ${m.targets}`} /><Metric label="Analyzer targets failed" value={number(m.failed)} /><Metric label="Parser errors" value={number(m.parserErrors)} /></div>
        <div className="ss-columns"><div className="ss-chart"><h3>Recorded timings</h3><Chart rows={[{ label: 'Total run', value: m.duration, display: duration(m.duration) }, { label: 'Scanning', value: m.scanningDuration, display: duration(m.scanningDuration) }, { label: 'Reconnaissance', value: m.reconDuration, display: duration(m.reconDuration) }]} /><p className="ss-note">Timings can overlap. They are not added together.</p></div><div className="ss-chart"><h3>Supporting analysis</h3><Facts rows={[[ 'Analyzer observations', number(m.observations)], ['Platform targets completed', number(m.analysis.platform_targets_completed)], ['Platform targets total', number(m.analysis.platform_targets_total)], ['Taint-analysis targets', number(m.analysis.taint_targets)], ['Analyzer error', m.analysis.error || (m.failed === 0 ? 'None recorded' : null)]]} /><p className="ss-note">Analyzer observations are review evidence and are not a count of confirmed vulnerabilities.</p>{m.analysis.error && <p role="alert" className="error-banner">{m.analysis.error}</p>}</div></div>
      </>}
      {tab === 'Configuration' && <>
        <Facts rows={[[ 'Project', run.project_name], ['Project ID', m.inputs.project_id || run.project_key], ['Run ID', run.run_uuid], ['Status', run.status], ['Rules', run.rules], ['Review mode', MODES[m.mode]], ['File types', run.file_types], ['Report format', run.report_format], ['Custom RDL packs', Array.isArray(m.inputs.custom_rdl || run.custom_rdl) ? (m.inputs.custom_rdl || run.custom_rdl).length : null], ['Excluded check classes', Array.isArray(run.exclude_checks) ? run.exclude_checks.length : null], ['Excluded path patterns', Array.isArray(run.exclude_paths) ? run.exclude_paths.length : null], ['Excluded file types', Array.isArray(run.exclude_types) ? run.exclude_types.length : null], ['Excluded content keywords', Array.isArray(run.exclude_keywords) ? run.exclude_keywords.length : null], ['Target directory', run.target_dir], ['Report root', reportRoot || m.inputs.report_root]]} />
        {reportFolderUrl && <p><a className="link-btn" href={reportFolderUrl} target="_blank" rel="noreferrer">Open report folder</a></p>}
        <div className="ss-feature-list">{[['Reconnaissance', run.recon], ['Review effort estimate', run.estimate], ['Inter-file analysis', run.analysis], ['Line counting', run.loc]].map(([label, enabled]) => <span key={label}>{label}<strong>{enabled == null ? 'Not recorded' : enabled ? 'Enabled' : 'Disabled'}</strong></span>)}</div>
        <details className="ss-command"><summary>Scan command</summary>{run.command ? <pre className="log-pane">{run.command}</pre> : <p className="ss-note">No command was recorded.</p>}</details>
      </>}
    </div>
  </section>
}
