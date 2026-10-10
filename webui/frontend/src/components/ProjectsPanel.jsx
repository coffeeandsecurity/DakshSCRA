import { useState } from 'react'
import ProjectHistory from './ProjectHistory'
import ProjectMetrics from './ProjectMetrics'

function niceDate(iso) {
  return iso ? new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' }) : 'No scans'
}


export default function ProjectsPanel({ projects, projectKey, onSelectProject, onBack, onOpenScan, onNewScan, onDeleteProject, onDeleteData, onDeleteRecord }) {
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState('')
  const [sort, setSort] = useState('latest')
  const [confirming, setConfirming] = useState(null)
  const [deleting, setDeleting] = useState(false)
  const project = projects.find(item => item.project_key === projectKey)
  const needle = query.trim().toLowerCase()
  const filtered = projects.filter(item => {
    if (needle && ![item.project_name, item.project_key, item.target_dir, item.rules].join(' ').toLowerCase().includes(needle)) return false
    if (filter === 'active') return item.running_scans + item.queued_scans + (item.stopping_scans || 0) > 0
    return !filter || (item[filter] || 0) > 0
  }).sort((a, b) => sort === 'name' ? a.project_name.localeCompare(b.project_name) : sort === 'scans' ? b.total_scans - a.total_scans : (b.latest_scan_at || '').localeCompare(a.latest_scan_at || ''))

  async function removeProject(key) {
    setDeleting(true)
    try { await onDeleteProject(key); setConfirming(null) } catch { /* The parent reports the error. */ }
    finally { setDeleting(false) }
  }

  if (project) return <ProjectHistory key={project.project_key} project={project} onBack={onBack} onOpenScan={onOpenScan} onDeleteData={onDeleteData} onDeleteRecord={onDeleteRecord} />

  return <section className="projects-browser" aria-label="Projects">
    <div className="section-header"><div className="section-title">Projects <span className="projects-count">{projects.length}</span></div></div>
    <div className="projects-toolbar">
      <input type="search" className="search-input" aria-label="Search projects" placeholder="Search project, source path or rules…" value={query} onChange={event => setQuery(event.target.value)} />
      <select className="filter-select" aria-label="Filter projects" value={filter} onChange={event => setFilter(event.target.value)}>
        <option value="">All projects</option><option value="active">Active or queued</option><option value="success_scans">With completed scans</option><option value="failed_scans">With failed scans</option><option value="stopped_scans">With stopped scans</option><option value="data_removed_scans">With removed data</option>
      </select>
      <select className="filter-select" aria-label="Sort projects" value={sort} onChange={event => setSort(event.target.value)}><option value="latest">Latest scan</option><option value="name">Project name</option><option value="scans">Most scans</option></select>
      <span className="text-muted text-sm">{filtered.length} of {projects.length}</span>
    </div>
    <div className="project-row-list">{filtered.map(item => <article className="project-row" key={item.project_key}>
      <button type="button" className="project-row-open" aria-label={`Open project ${item.project_name}`} onClick={() => onSelectProject(item.project_key)}>
        <div className="project-row-identity"><strong>{item.project_name}</strong><span className="font-mono" title={item.target_dir}>{item.target_dir}</span>{item.data_removed_scans > 0 && <small>{item.data_removed_scans} scan{item.data_removed_scans === 1 ? '' : 's'} with data removed</small>}</div>
        <ProjectMetrics project={item} />
        <div className="project-row-meta"><span className="code-inline">{item.rules || 'auto'}</span><span>Last scan {niceDate(item.latest_scan_at)}</span></div>
      </button>
      <button type="button" className="btn-icon project-row-delete" aria-label={`Delete project ${item.project_name}`} onClick={() => setConfirming(item.project_key)}><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true"><path d="M3 6h18M9 6V4h6v2M5 6l1 14h12l1-14M10 10v6M14 10v6" /></svg></button>
      {confirming === item.project_key && <div className="project-row-confirm"><span>Delete this project and its scan data? History records will remain.</span><button className="btn btn-danger btn-xs" disabled={deleting} onClick={() => removeProject(item.project_key)}>{deleting ? 'Deleting…' : 'Delete project'}</button><button className="btn btn-ghost btn-xs" disabled={deleting} onClick={() => setConfirming(null)}>Cancel</button></div>}
    </article>)}</div>
    {!filtered.length && <div className="card empty-state"><div className="empty-title">{projects.length ? 'No matching projects' : 'No projects yet'}</div><p>{projects.length ? 'Adjust your search or filter.' : 'Start a scan to create your first project.'}</p>{!projects.length && <button className="btn btn-primary btn-sm" onClick={onNewScan}>+ New Scan</button>}</div>}
  </section>
}
