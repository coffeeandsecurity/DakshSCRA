import { formatDuration as niceDuration } from '../lib/duration'
import { useEffect, useMemo, useState } from 'react'
import ScanDeleteActions from './ScanDeleteActions'

const PAGE_SIZE = 10

function niceDate(iso) {
  if (!iso) return '-'
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}



export default function CompletedScans({ runs, selected, onView, onDeleteData, onDeleteRecord }) {
  const [query, setQuery] = useState('')
  const [page, setPage] = useState(1)
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase()
    if (!needle) return runs
    return runs.filter((run) => [run.project_name, run.project_key, run.run_uuid, run.rules, run.status]
      .join(' ').toLowerCase().includes(needle))
  }, [query, runs])
  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))

  useEffect(() => setPage(1), [query])
  useEffect(() => setPage((current) => Math.min(current, pageCount)), [pageCount])

  const visible = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

  return (
    <section className="completed-scans">
      <div className="scans-panel-head completed-head">
        <div>
          <div className="scans-panel-title">Completed scans</div>
          <div className="scans-panel-copy">Finished scan results grouped by project. Ten records are shown per page.</div>
        </div>
        <input
          className="search-input"
          type="search"
          placeholder="Search completed scans…"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
      </div>

      {visible.length === 0 ? (
        <div className="card empty-state">
          <div className="empty-title">{runs.length ? 'No matching completed scans' : 'No completed scans yet'}</div>
          <div className="empty-msg">{runs.length ? 'Try a different project, run ID, or status.' : 'Finished scans will move here automatically.'}</div>
        </div>
      ) : (
        <div className="completed-scan-list">
          {visible.map((run) => (
            <article className={`completed-scan-card${selected?.run_uuid === run.run_uuid ? ' selected' : ''}`} key={run.run_uuid}>
              <div className="completed-scan-main">
                <div className="completed-project-name">{run.project_name || run.project_key || 'Unnamed project'}</div>
                <div className="completed-run-meta">
                  <span className={`badge ${run.data_removed ? 'removed' : run.status}`}>{run.data_removed ? 'data removed' : run.status}</span>
                  <code>{run.run_uuid}</code>
                  <span>{niceDate(run.created_at)}</span>
                  <span className="completed-duration" title="Scan duration">{niceDuration(run.duration_sec)}</span>
                  <span>{run.rules || 'auto'} rules</span>
                </div>
                {run.data_removed ? <div className="scan-record-note">Scan data removed. This entry is retained only as a history record.</div> : null}
              </div>
              <div className="completed-scan-actions">
                {!run.data_removed ? (
                  <button type="button" className="btn btn-primary btn-sm" onClick={() => onView(run)}><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z" /><path d="M14 3v6h6M8 13h8M8 17h5" /></svg><span>View results</span></button>
                ) : null}
                <ScanDeleteActions run={run} onDeleteData={onDeleteData} onDeleteRecord={onDeleteRecord} compact />
              </div>
            </article>
          ))}
        </div>
      )}

      {pageCount > 1 ? (
        <nav className="completed-pagination" aria-label="Completed scan pages">
          <button type="button" className="btn btn-ghost btn-sm" disabled={page === 1} onClick={() => setPage((value) => value - 1)}>Previous</button>
          <span>Page {page} of {pageCount} · {filtered.length} scans</span>
          <button type="button" className="btn btn-ghost btn-sm" disabled={page === pageCount} onClick={() => setPage((value) => value + 1)}>Next</button>
        </nav>
      ) : null}
    </section>
  )
}
