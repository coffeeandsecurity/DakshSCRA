import { useEffect, useRef, useState } from 'react'
import { getDiskInfo, getDiskFiles, deleteDiskUnit, deleteDiskScan } from '../api'

export function diskSize(bytes = 0) {
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let value = bytes / 1024, index = 0
  while (value >= 1024 && index < units.length - 1) { value /= 1024; index++ }
  return `${value.toFixed(1)} ${units[index]}`
}
const categories = { reports: 'Generated reports', data: 'Saved results', runtime: 'Scan runtime', temporary: 'Temporary diagnostics', logs: 'Logs' }

export default function SystemPanel({ health, version, onStorageChange }) {
  const [tab, setTab] = useState('disk')
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [project, setProject] = useState('')
  const [kind, setKind] = useState('')
  const [selection, setSelection] = useState({})
  const [pending, setPending] = useState(null)
  const [deleting, setDeleting] = useState(false)
  const cancelRef = useRef(null)
  async function refresh() {
    setLoading(true)
    try { setData(await getDiskInfo()); setSelection({}); setError('') }
    catch (err) { setError(err.message) }
    finally { setLoading(false) }
  }
  useEffect(() => {
    let disposed = false
    getDiskInfo().then(value => { if (!disposed) setData(value) }).catch(err => { if (!disposed) setError(err.message) }).finally(() => { if (!disposed) setLoading(false) })
    return () => { disposed = true }
  }, [])
  useEffect(() => { if (pending) cancelRef.current?.focus() }, [pending])
  function confirm(targets, wholeScan = false) { setPending({ targets, wholeScan }); setError(''); setNotice('') }
  async function cleanup() {
    setDeleting(true)
    let freed = 0, completed = 0, failure = ''
    for (const target of pending.targets) {
      try {
        const result = pending.wholeScan ? await deleteDiskScan(target.runUuid) : await deleteDiskUnit(target.runUuid, target.id)
        freed += result.removed_bytes; completed++
      } catch (err) { failure = err.message; break }
    }
    setPending(null)
    await refresh()
    if (completed) { setNotice(`Removed ${completed} ${pending.wholeScan ? 'scan data set(s)' : 'storage item(s)'} (${diskSize(freed)}). Disk usage has been refreshed.`); onStorageChange?.() }
    if (failure) setError(`Cleanup stopped: ${failure}`)
    setDeleting(false)
  }
  const selected = Object.values(selection)
  const groups = (data?.projects || []).filter(group => !project || group.project_key === project)
  return <section className="system-panel">
    <div className="system-tabs" role="tablist" aria-label="System tabs" onKeyDown={event => {
      if (['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) {
        event.preventDefault()
        const next = event.key === 'Home' ? 'disk' : event.key === 'End' ? 'status' : tab === 'disk' ? 'status' : 'disk'
        setTab(next); document.getElementById(`${next}-tab`)?.focus()
      }
    }}>
      <button role="tab" tabIndex={tab === 'disk' ? 0 : -1} id="disk-tab" aria-selected={tab === 'disk'} aria-controls="disk-panel" onClick={() => setTab('disk')}>Disk info</button>
      <button role="tab" tabIndex={tab === 'status' ? 0 : -1} id="status-tab" aria-selected={tab === 'status'} aria-controls="status-panel" onClick={() => setTab('status')}>System status</button>
    </div>
    {tab === 'status' ? <div role="tabpanel" id="status-panel" aria-labelledby="status-tab" className="disk-card"><h3>System status</h3><p>API: {health || 'Unknown'}</p><p>Version: {version || 'Unknown'}</p><p>Use Disk info to inspect project storage and free disk space.</p></div> : <div role="tabpanel" id="disk-panel" aria-labelledby="disk-tab">
      <div className="disk-heading"><div><h3>Disk info</h3><p>Review application files by project and scan. Remove generated downloads or diagnostic scratch files, or delete all data for a finished scan.</p></div><button className="btn btn-ghost" disabled={loading || deleting} onClick={refresh}>{loading ? 'Measuring…' : 'Refresh disk usage'}</button></div>
      {error && <div className="error-banner" role="alert">{error}</div>}
      {notice && <p className="disk-notice" role="status">{notice}</p>}
      {loading && !data && <p role="status">Measuring project files…</p>}
      {data && <>
        <div className="disk-metrics">{[
          ['Saved project files', data.projects.reduce((sum, group) => sum + group.bytes, 0), 'Results, reports, runtime files and logs listed by scan below.'],
          ['Entire filesystem used', data.filesystem.used, 'Includes scan files, system files, other applications and Docker storage.'],
          ['Filesystem free', data.filesystem.free, 'Space available on the filesystem holding scan storage.'],
        ].map(([label, bytes, description]) => <div className="disk-card" key={label}><span>{label}</span><strong>{diskSize(bytes)}</strong><small>{description}</small></div>)}</div>
        <div className="disk-scope-note"><strong>Where is the space used?</strong><p>The filesystem total covers more than project data. Every saved scan file is counted below, including its runtime files and logs. Expand a scan to inspect individual files or delete its saved data. Docker images and build caches belong to the server and are managed separately.</p></div>
        <StorageDistribution filesystem={data.filesystem} groups={groups} kind={kind} onFilter={category => { setKind(category === kind ? '' : category); setSelection({}) }} />
        <p className="disk-note">{data.note}</p>
        <div className="disk-toolbar"><label>Project<select value={project} onChange={e => { setProject(e.target.value); setSelection({}) }}><option value="">All projects</option>{data.projects.map(group => <option value={group.project_key} key={group.project_key}>{group.project_name}</option>)}</select></label><label>File category<select value={kind} onChange={e => { setKind(e.target.value); setSelection({}) }}><option value="">All categories</option>{Object.entries(categories).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></label><button className="btn btn-danger" disabled={!selected.length || deleting || loading} onClick={() => confirm(selected)}>Delete selected ({selected.length})</button></div>
        {pending && <div className="disk-confirm" role="alertdialog" aria-labelledby="disk-confirm-title" aria-describedby="disk-confirm-description" onKeyDown={e => { if (e.key === 'Escape' && !deleting) setPending(null) }}>
          <h4 id="disk-confirm-title">Delete {pending.wholeScan ? 'saved scan data' : 'selected files'}?</h4>
          <p id="disk-confirm-description">{pending.wholeScan ? 'This removes all saved results, reports, logs and runtime files for the selected scans. Scan history and project configuration remain. Results cannot be restored or exported after deletion.' : 'These storage items will be permanently deleted. Saved findings remain available, and generated reports can be created again.'} Source code and account data are preserved.</p>
          <ul>{pending.targets.map(target => <li key={target.runUuid + (target.id || '')}>{target.label} · {diskSize(target.bytes)}</li>)}</ul>
          <button ref={cancelRef} className="btn btn-ghost" disabled={deleting} onClick={() => setPending(null)}>Cancel</button> <button className="btn btn-danger" disabled={deleting} onClick={cleanup}>{deleting ? 'Deleting…' : `Confirm delete · ${diskSize(pending.targets.reduce((sum, target) => sum + target.bytes, 0))}`}</button>
        </div>}
        {!groups.length && <p>No projects have saved storage.</p>}
        {groups.map(group => <div className="disk-project disk-card" key={group.project_key}>
          <div className="disk-heading"><div><h3>{group.project_name}</h3><small>{group.project_key} · {group.scans.length} scans · {diskSize(group.bytes)}</small></div><button className="btn btn-danger btn-xs" disabled={deleting || loading || !group.scans.some(scan => scan.bytes > 0) || group.scans.some(scan => scan.active)} onClick={() => confirm(group.scans.filter(scan => scan.bytes > 0).map(scan => ({ runUuid: scan.run_uuid, bytes: scan.bytes, label: scan.run_uuid })), true)}>Delete project data</button></div>
          {group.scans.length === 0 && <p>No saved scan files.</p>}
          {[...group.scans].sort((a,b) => b.bytes - a.bytes).map(scan => <details className="disk-scan" key={scan.run_uuid}>
            <summary><span>{scan.run_uuid}</span><span>{diskSize(scan.bytes)} · {scan.status}{scan.active ? ' · Cleanup locked: active scan/report' : ''}</span><span className="disk-scan-totals">{Object.entries(categories).map(([category, label]) => {
              const bytes = scan.units.filter(unit => unit.kind === category).reduce((sum, unit) => sum + unit.bytes, 0)
              return bytes > 0 ? <span key={category}>{label} <strong>{diskSize(bytes)}</strong></span> : null
            })}</span></summary>
            <div className="disk-scan-body"><div className="disk-heading"><p>{scan.created_at ? new Date(scan.created_at).toLocaleString() : 'Date unavailable'}{scan.data_removed ? ' · Saved data removed' : ''}</p><button className="btn btn-danger btn-xs" disabled={scan.active || deleting || loading || scan.bytes === 0} onClick={() => confirm([{ runUuid: scan.run_uuid, bytes: scan.bytes, label: scan.run_uuid }], true)}>Delete scan data</button></div>
              {scan.active && <p className="disk-note">Wait for this scan and its report jobs to finish before cleanup.</p>}
              {scan.units.filter(unit => !kind || unit.kind === kind).map(unit => <div className="disk-unit" key={unit.id}>
                <div className="disk-unit-heading"><label className="disk-select"><input type="checkbox" aria-label={`Select ${unit.label} from ${scan.run_uuid}`} disabled={!unit.removable || deleting || loading} checked={Boolean(selection[unit.id])} onChange={e => setSelection(previous => { const next = {...previous}; if (e.target.checked) next[unit.id] = { ...unit, runUuid: scan.run_uuid }; else delete next[unit.id]; return next })}/><span><strong>{unit.label}</strong><small>{categories[unit.kind]} · {unit.file_count} files · {diskSize(unit.bytes)}{unit.metadata.status ? ` · ${unit.metadata.status}` : ''}</small></span></label><button className="btn btn-danger btn-xs" disabled={!unit.removable || deleting || loading} onClick={() => confirm([{ ...unit, runUuid: scan.run_uuid }])}>Delete</button></div>
                <code className="disk-path">{unit.path}</code>{unit.metadata.temporary_bytes > 0 && <small className="disk-note">Includes {diskSize(unit.metadata.temporary_bytes)} of report building files. Active scratch files are removed automatically when generation ends; interrupted scratch files are removed with this report item.</small>}<DiskFiles runUuid={scan.run_uuid} unit={unit}/>
                {!unit.removable && !scan.active && <small className="disk-note">Retained for scan results. Use Delete scan data to remove these files together.</small>}
              </div>)}
              {!scan.units.some(unit => !kind || unit.kind === kind) && <p>No files in this category.</p>}
            </div>
          </details>)}
        </div>)}
        {data.unassigned.length > 0 && <div className="disk-card"><h3>Unassigned application files</h3><p>These files have no matching retained scan. Listed for inspection; automatic cleanup is unavailable because ownership cannot be established.</p>{data.unassigned.map(item => <p className="disk-path" key={item.path}>{item.path} · {item.file_count} files · {diskSize(item.bytes)}</p>)}</div>}
      </>}
    </div>}
  </section>
}

const storageColors = { reports: '#356fe5', data: '#16877b', runtime: '#8563c2', temporary: '#bb6b22', logs: '#c04c70' }
function StorageDistribution({ filesystem, groups, kind, onFilter }) {
  const reserved = Math.max(0, filesystem.total - filesystem.used - filesystem.free)
  const capacity = [
    { label: 'Used', bytes: filesystem.used, color: '#356fe5' },
    { label: 'Free', bytes: filesystem.free, color: '#16877b' },
    { label: 'Reserved / unavailable', bytes: reserved, color: '#929aaa' },
  ]
  const amounts = Object.entries(categories).map(([key, label]) => ({ key, label, color: storageColors[key], bytes: groups.reduce((sum, group) => sum + group.scans.reduce((scanSum, scan) => scanSum + scan.units.reduce((unitSum, unit) => unitSum + (unit.kind === key ? unit.bytes : 0), 0), 0), 0) }))
  const total = amounts.reduce((sum, item) => sum + item.bytes, 0)
  const percentage = (bytes, whole) => whole > 0 ? Math.max(0, Math.min(100, bytes / whole * 100)) : 0
  return <div className="disk-distributions">
    <div className="disk-card"><h4>Filesystem space <small>{diskSize(filesystem.total)} total</small></h4>
      <div className="disk-distribution-bar" role="img" aria-label={capacity.map(item => `${item.label}: ${diskSize(item.bytes)}`).join(', ')}>{capacity.filter(item => item.bytes > 0).map(item => <span key={item.label} style={{ width: `${percentage(item.bytes, filesystem.total)}%`, background: item.color }} title={`${item.label}: ${diskSize(item.bytes)}`} />)}</div>
      <ul className="disk-distribution-legend">{capacity.filter(item => item.bytes > 0).map(item => <li key={item.label}><i style={{ background: item.color }} aria-hidden="true" />{item.label}<strong>{diskSize(item.bytes)}</strong></li>)}</ul>
      <p className="disk-note">Includes Docker images, build caches and other server storage. This is separate from the scan-file breakdown.</p>
    </div>
    <div className="disk-card"><h4>Saved scan files <small>{diskSize(total)}{groups.length === 1 ? ` · ${groups[0].project_name}` : ' · All projects'}</small></h4>
      {total > 0 ? <><div className="disk-distribution-bar" role="img" aria-label={amounts.filter(item => item.bytes > 0).map(item => `${item.label}: ${diskSize(item.bytes)}`).join(', ')}>{amounts.filter(item => item.bytes > 0).map(item => <span key={item.key} style={{ width: `${percentage(item.bytes, total)}%`, background: item.color }} title={`${item.label}: ${diskSize(item.bytes)}`} />)}</div>
      <div className="disk-distribution-filters">{amounts.filter(item => item.bytes > 0).map(item => <button key={item.key} type="button" aria-label={`Filter ${item.label}`} aria-pressed={kind === item.key} onClick={() => onFilter(item.key)}><i style={{ background: item.color }} aria-hidden="true" />{item.label}<strong>{diskSize(item.bytes)}</strong></button>)}</div>
      <p className="disk-note">Select a category to inspect its files below. Select it again to show all categories.</p></> : <p className="disk-note">No saved project files.</p>}
    </div>
  </div>
}

function DiskFiles({ runUuid, unit }) {
  const [open, setOpen] = useState(false), [page, setPage] = useState(null), [offset, setOffset] = useState(0), [error, setError] = useState(''), [loading, setLoading] = useState(false)
  useEffect(() => {
    if (!open) return
    let disposed = false; setLoading(true); setError('')
    getDiskFiles(runUuid, unit.id, offset).then(value => { if (!disposed) setPage(value) }).catch(err => { if (!disposed) setError(err.message) }).finally(() => { if (!disposed) setLoading(false) })
    return () => { disposed = true }
  }, [open, offset, runUuid, unit.id, unit.bytes, unit.file_count])
  return <div className="disk-file-list"><button className="link-btn" aria-expanded={open} onClick={() => setOpen(value => !value)}>{open ? 'Hide files' : 'View files'}</button>{open && <>
    {error && <p role="alert">{error}</p>}{loading && <p role="status">Loading files…</p>}
    {page && <><div className="disk-table-wrap"><table><thead><tr><th>File</th><th>Size</th><th>Modified</th></tr></thead><tbody>{page.files.map(file => <tr key={file.path}><td><code>{file.path}</code></td><td>{diskSize(file.bytes)}</td><td>{new Date(file.modified_at).toLocaleString()}</td></tr>)}</tbody></table></div><div className="disk-pagination"><span>{page.total ? `${offset + 1}–${Math.min(offset + page.limit, page.total)} of ${page.total} files` : 'No files'}</span><button className="btn btn-ghost btn-xs" disabled={loading || offset === 0} onClick={() => setOffset(Math.max(0, offset - 100))}>Previous</button><button className="btn btn-ghost btn-xs" disabled={loading || offset + 100 >= page.total} onClick={() => setOffset(offset + 100)}>Next</button></div></>}
  </>}</div>
}
