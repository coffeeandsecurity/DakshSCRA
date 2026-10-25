import { formatDateTime } from '../lib/datetime'
import { formatDuration as niceDuration, scanDurationSeconds } from '../lib/duration'
import { useEffect, useState } from 'react'
import ScanDeleteActions from './ScanDeleteActions'

function StatusBadge({ status, dataRemoved }) {
  if (dataRemoved) {
    return (
      <span className="badge removed">
        <span className="badge-dot" />
        data removed
      </span>
    )
  }
  return (
    <span className={`badge ${status}`}>
      <span className={`badge-dot${status === 'running' ? ' pulse' : ''}`} />
      {status}
    </span>
  )
}



const niceDate = formatDateTime

export default function ScanTable({ runs, selected, onSelect, onDeleteData, onDeleteRecord, queuedOnly = false }) {
  const [query, setQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [now, setNow] = useState(() => Date.now())
  const hasRunningScan = !queuedOnly && runs.some(run => ['running', 'stopping'].includes(run.status) && run.started_at)
  useEffect(() => {
    if (!hasRunningScan) return
    setNow(Date.now())
    const timer = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [hasRunningScan])
  const queuePositions = queuedOnly ? new Map(runs.map((run, index) => [run.run_uuid, index + 1])) : null

  const filtered = runs.filter((r) => {
    const q = query.trim().toLowerCase()
    const matchQ = !q || [r.project_name, r.rules, r.target_dir, r.run_uuid].join(' ').toLowerCase().includes(q)
    const matchS = !statusFilter || (statusFilter === 'data-removed' ? r.data_removed : !r.data_removed && r.status === statusFilter)
    return matchQ && matchS
  })

  return (
    <div className="card">
      {/* Toolbar */}
      <div className="scans-toolbar">
        <input
          className="search-input"
          type="search"
          placeholder="Search scans..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          style={{ flex: 1, maxWidth: 300 }}
        />
        <select
          className="filter-select"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
        >
          <option value="">All Status</option>
          {!queuedOnly && <option value="success">Success</option>}
          {!queuedOnly && <option value="running">Running</option>}
          <option value="queued">Queued</option>
          {!queuedOnly && <option value="failed">Failed</option>}
          {!queuedOnly && <option value="data-removed">Data Removed</option>}
        </select>
        <span className="text-muted text-sm" style={{ marginLeft: 'auto', whiteSpace: 'nowrap' }}>
          {filtered.length} of {runs.length}
        </span>
      </div>

      {/* Table */}
      <div className="card-body p0">
        {filtered.length === 0 ? (
          <div className="empty-state">
            <svg className="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 15.803 7.5 7.5 0 0016.803 15.803z" />
            </svg>
            <div className="empty-title">{runs.length === 0 ? queuedOnly ? 'No queued scans' : 'No active scans' : 'No results'}</div>
            <div className="empty-msg">{runs.length === 0 ? queuedOnly ? 'Scans waiting to start will appear here. View executing scans under Active Scans.' : 'Use New Scan to start a scan. Finished scans are listed under Completed.' : 'Try adjusting your search or filter.'}</div>
          </div>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  {queuedOnly && <th>Queue position</th>}
                  <th className="col-status">Status</th>
                  <th>Project</th>
                  <th>Rules</th>
                  <th>Target</th>
                  <th>Duration</th>
                  <th>Date</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((r) => (
                  <tr
                    key={r.run_uuid}
                    className={`${selected?.run_uuid === r.run_uuid ? 'selected' : ''}${r.data_removed ? ' scan-record-only' : ''}`}
                    onClick={() => { if (!r.data_removed) onSelect(r) }}
                  >
                    {queuedOnly && <td>{queuePositions.get(r.run_uuid)}{queuePositions.get(r.run_uuid) === 1 ? ' · Next' : ''}</td>}
                    <td><StatusBadge status={r.status} dataRemoved={r.data_removed} />{queuedOnly && r.queue_reserved && <div className="text-muted text-sm">{r.queue_editing ? 'Editing · reserved' : 'Editing paused'}</div>}</td>
                    <td style={{ fontWeight: 600, color: 'var(--text)', maxWidth: 200 }}>
                      <div className="truncate">{r.project_name || '-'}</div>
                      {r.data_removed ? <div className="scan-record-note">Scan data removed. History record only.</div> : null}
                    </td>
                    <td>
                      <span className="code-inline">{r.rules}</span>
                    </td>
                    <td style={{ maxWidth: 240 }}>
                      <div className="truncate text-muted text-sm font-mono" title={r.target_dir}>
                        {r.target_dir}
                      </div>
                    </td>
                    <td className="text-muted" title={['running', 'stopping'].includes(r.status) ? 'Elapsed execution time' : 'Recorded execution duration'}>{niceDuration(scanDurationSeconds(r, now))}</td>
                    <td className="text-muted" style={{ whiteSpace: 'nowrap' }}>{niceDate(r.created_at)}</td>
                    <td>
                      <ScanDeleteActions run={r} onDeleteData={onDeleteData} onDeleteRecord={onDeleteRecord} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
