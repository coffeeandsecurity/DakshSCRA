import { useEffect, useState } from 'react'
import { listScans } from '../api'
import { formatDuration } from '../lib/duration'
import ProjectMetrics from './ProjectMetrics'
import ScanDeleteActions from './ScanDeleteActions'

const PAGE_SIZE = 25
const ACTIVE = new Set(['running', 'queued', 'stopping'])

export default function ProjectHistory({ project, onBack, onOpenScan, onDeleteData, onDeleteRecord }) {
  const [query, setQuery] = useState('')
  const [status, setStatus] = useState('')
  const [page, setPage] = useState(0)
  const [runs, setRuns] = useState([])
  const [more, setMore] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [version, setVersion] = useState(0)
  const active = project.running_scans + project.queued_scans + (project.stopping_scans || 0) > 0

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const records = await listScans(PAGE_SIZE + 1, project.project_key, { offset: page * PAGE_SIZE, status, search: query })
        if (cancelled) return
        setRuns(records.slice(0, PAGE_SIZE)); setMore(records.length > PAGE_SIZE); setError('')
      } catch (failure) { if (!cancelled) setError(failure.message) }
      finally { if (!cancelled) setLoading(false) }
    }
    setLoading(true); setRuns([])
    const delay = setTimeout(load, query ? 250 : 0)
    const polling = setInterval(load, active ? 3000 : 12000)
    return () => { cancelled = true; clearTimeout(delay); clearInterval(polling) }
  }, [project.project_key, query, status, page, active, version])

  async function remove(run, recordOnly) {
    await (recordOnly ? onDeleteRecord(run) : onDeleteData(run))
    setPage(0); setVersion(value => value + 1)
  }

  return <section className="project-history" aria-label={`${project.project_name} scan history`}>
    <div className="project-history-heading"><button className="btn btn-ghost btn-sm" onClick={onBack}>← All projects</button><h2>{project.project_name}</h2><button className="btn btn-ghost btn-sm" onClick={() => setVersion(value => value + 1)}>Refresh scans</button></div>
    <div className="project-history-overview"><div className="project-history-path"><span className="font-mono" title={project.target_dir}>{project.target_dir}</span><span className="code-inline">{project.rules || 'auto'} rules</span>{project.data_removed_scans > 0 && <span>{project.data_removed_scans} with data removed</span>}</div><ProjectMetrics project={project} /></div>
    <div className="projects-toolbar"><input type="search" className="search-input" aria-label="Search project scans" placeholder="Search run ID, rules or source path…" value={query} onChange={event => { setQuery(event.target.value); setPage(0) }} /><select className="filter-select" aria-label="Filter project scans" value={status} onChange={event => { setStatus(event.target.value); setPage(0) }}><option value="">All statuses</option>{['success', 'running', 'queued', 'stopping', 'failed', 'stopped'].map(value => <option key={value} value={value}>{value === 'success' ? 'Completed' : value[0].toUpperCase() + value.slice(1)}</option>)}<option value="data-removed">Data removed</option></select><span className="text-muted text-sm">{project.total_scans} scans in this project</span></div>
    {error && <div className="error-banner" role="alert">Could not load scan history: {error}<button className="btn btn-ghost btn-xs" onClick={() => setVersion(value => value + 1)}>Retry</button></div>}
    {loading ? <p role="status" className="project-history-loading">Loading scan history…</p> : <div className="project-run-list">{runs.map(run => <article className="project-run" key={run.run_uuid}>
      <div className="project-run-status"><span className={`badge ${run.status}`}><span className={`badge-dot${run.status === 'running' ? ' pulse' : ''}`} />{run.status}</span>{run.data_removed && <span className="badge removed">data removed</span>}</div>
      <div className="project-run-identity"><code>{run.run_uuid}</code><time dateTime={run.created_at}>{run.created_at ? new Date(run.created_at).toLocaleString() : 'Date not recorded'}</time></div>
      <div className="project-run-config"><span className="code-inline">{run.rules || 'auto'}</span><span title="Scan duration">{formatDuration(run.duration_sec)}</span></div>
      <div className="project-run-actions">{!run.data_removed ? <button className="btn btn-primary btn-sm" onClick={() => onOpenScan(run)}>{ACTIVE.has(run.status) ? (run.status === 'queued' ? 'View queued scan' : 'View active scan') : 'View results'}</button> : <span className="scan-record-note">History only</span>}<ScanDeleteActions run={run} onDeleteData={item => remove(item, false)} onDeleteRecord={item => remove(item, true)} compact /></div>
    </article>)}{!runs.length && !error && <div className="card empty-state"><div className="empty-title">{query || status ? 'No matching scans' : 'No scans yet'}</div><p>{query || status ? 'Adjust your search or filter.' : 'Scans for this project will appear here.'}</p></div>}</div>}
    {(page > 0 || more) && <nav className="completed-pagination" aria-label="Project scan pages"><button className="btn btn-ghost btn-sm" disabled={page === 0 || loading} onClick={() => setPage(value => value - 1)}>Previous</button><span>Page {page + 1} · {runs.length} scans shown</span><button className="btn btn-ghost btn-sm" disabled={!more || loading} onClick={() => setPage(value => value + 1)}>Next</button></nav>}
  </section>
}
