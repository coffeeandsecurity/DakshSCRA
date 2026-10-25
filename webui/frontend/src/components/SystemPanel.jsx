import { formatDateTime } from '../lib/datetime'
import { useEffect, useRef, useState } from 'react'
import { getDiskInfo, getDiskFiles, deleteDiskUnit, deleteDiskScan, deleteScanRecord, cleanupDiskAreas } from '../api'

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
  const [areaSelection, setAreaSelection] = useState({})
  const [pending, setPending] = useState(null)
  const [deleting, setDeleting] = useState(false)
  const cancelRef = useRef(null), triggerRef = useRef(null)
  async function refresh() {
    setPending(null)
    setLoading(true)
    try { setData(await getDiskInfo()); setSelection({}); setAreaSelection({}); setError('') }
    catch (err) { setError(err.message) }
    finally { setLoading(false) }
  }
  useEffect(() => {
    let disposed = false
    getDiskInfo().then(value => { if (!disposed) setData(value) }).catch(err => { if (!disposed) setError(err.message) }).finally(() => { if (!disposed) setLoading(false) })
    return () => { disposed = true }
  }, [])
  useEffect(() => { if (pending) cancelRef.current?.focus() }, [pending])
  function confirm(targets, wholeScan = false, scope = 'selection', event) {
    triggerRef.current = event?.currentTarget || null
    setPending({ targets, wholeScan, scope }); setError(''); setNotice('')
  }
  function cancel() { setPending(null); triggerRef.current?.focus() }
  function confirmation(scope) {
    if (pending?.scope !== scope) return null
    return <div className="disk-confirm" role="alertdialog" aria-labelledby="disk-confirm-title" aria-describedby="disk-confirm-description" onKeyDown={event => { if (event.key === 'Escape' && !deleting) cancel() }}>
      <div className="disk-confirm-copy">
        <div className="disk-confirm-heading"><h4 id="disk-confirm-title">{scope.startsWith('history:') ? 'Delete from history?' : scope.startsWith('project:') ? 'Delete project data?' : pending.wholeScan ? 'Delete saved scan data?' : scope === 'areas' ? 'Clean generated storage?' : 'Delete selected files?'}</h4><span hidden={scope.startsWith('history:')}>{pending.targets.length} {pending.wholeScan ? pending.targets.length === 1 ? 'scan' : 'scans' : pending.targets.length === 1 ? 'item' : 'items'} · {diskSize(pending.targets.reduce((sum,target) => sum + target.bytes,0))}</span></div>
        <p id="disk-confirm-description">{scope.startsWith('history:') ? 'This permanently removes the scan metadata and deletion timestamp from history. Saved scan data has already been deleted.' : pending.wholeScan ? 'Saved results, reports, logs and runtime files will be permanently deleted. Scan history, project settings, source code and accounts stay.' : scope === 'areas' ? 'Eligible generated files in the selected areas will be permanently deleted. Recent files, referenced fixtures and active scratch files stay. Saved scan findings are managed separately below.' : 'The selected files will be permanently deleted. Saved findings, source code and accounts stay.'}</p>
        <details className="disk-confirm-targets" hidden={scope.startsWith('history:')}><summary>View affected {pending.wholeScan ? 'scans' : 'files'}</summary><div>{pending.targets.map(target => <div key={target.area || target.runUuid + (target.id || '')}><code>{target.label}</code><span>{diskSize(target.bytes)}</span></div>)}</div></details>
      </div>
      <div className="disk-confirm-actions"><button ref={cancelRef} type="button" className="btn btn-secondary" disabled={deleting} onClick={cancel}>Cancel</button><button type="button" className="btn btn-danger delete-button" disabled={deleting} onClick={cleanup}>{deleting ? 'Deleting…' : 'Confirm delete'}</button></div>
    </div>
  }
  async function cleanup() {
    setDeleting(true)
    let freed = 0, completed = 0, failure = ''
    const targets = pending.scope === 'areas' ? [{ areas: pending.targets.map(target => target.area) }] : pending.targets
    for (const target of targets) {
      try {
        const result = pending.scope === 'areas' ? await cleanupDiskAreas(target.areas) : pending.scope.startsWith('history:') ? await deleteScanRecord(target.runUuid) : pending.wholeScan ? await deleteDiskScan(target.runUuid) : await deleteDiskUnit(target.runUuid, target.id)
        freed += result?.removed_bytes || 0; completed += target.areas?.length || 1
        if (result?.failed_files) { failure = `${result.failed_files} files could not be removed. Inspect refreshed sizes and retry.`; break }
      } catch (err) { failure = err.message; break }
    }
    setPending(null)
    await refresh()
    if (completed) { setNotice(pending.scope.startsWith('history:') ? 'Scan removed from deleted scan history.' : `Removed ${completed} ${pending.wholeScan ? 'scan data set(s)' : 'storage item(s)'} (${diskSize(freed)}). Disk usage has been refreshed.${pending.wholeScan ? ' Metadata and the deletion timestamp are retained in Deleted scan history.' : ''}`); onStorageChange?.() }
    if (failure) setError(`Cleanup stopped: ${failure}`)
    setDeleting(false)
  }
  const selected = Object.values(selection)
  const groups = (data?.projects || []).filter(group => !project || group.project_key === project)
  return <section className="system-panel">
    <div className="system-tabs" role="tablist" aria-label="System tabs" onKeyDown={event => {
      if (['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) {
        event.preventDefault()
        const tabs = ['disk', 'history', 'status']
        const next = event.key === 'Home' ? tabs[0] : event.key === 'End' ? tabs[2] : tabs[(tabs.indexOf(tab) + (event.key === 'ArrowRight' ? 1 : 2)) % tabs.length]
        setTab(next); document.getElementById(`${next}-tab`)?.focus()
      }
    }}>
      <button role="tab" tabIndex={tab === 'disk' ? 0 : -1} id="disk-tab" aria-selected={tab === 'disk'} aria-controls="disk-panel" onClick={() => setTab('disk')}>Disk info</button>
      <button role="tab" tabIndex={tab === 'history' ? 0 : -1} id="history-tab" aria-selected={tab === 'history'} aria-controls="history-panel" onClick={() => { setPending(null); setTab('history') }}>Deleted scan history</button>
      <button role="tab" tabIndex={tab === 'status' ? 0 : -1} id="status-tab" aria-selected={tab === 'status'} aria-controls="status-panel" onClick={() => setTab('status')}>System status</button>
    </div>
    {tab === 'history' ? <div role="tabpanel" id="history-panel" aria-labelledby="history-tab">
      <div className="disk-heading"><div><h3>Deleted scan history</h3><p>Metadata for scans whose saved data has been deleted. Results, reports, logs and runtime files are not retained here.</p></div><button className="btn btn-secondary" disabled={loading || deleting} onClick={refresh}>Refresh history</button></div>
      {error && <div className="error-banner" role="alert">{error}</div>}
      {notice && <p role="status">{notice}</p>}
      {loading && !data && <p role="status">Loading history…</p>}
      {data && !(data.deleted_scans || []).length && <p>No deleted scans in history.</p>}
      {(data?.deleted_scans || []).map(scan => <article className="disk-card disk-history" key={scan.run_uuid}>
        <div className="disk-heading"><div><h3>{scan.project_name}</h3><code>{scan.run_uuid}</code></div><button className="btn btn-danger delete-button" disabled={loading || deleting} onClick={event => confirm([{ runUuid: scan.run_uuid, label: scan.run_uuid, bytes: 0 }], false, `history:${scan.run_uuid}`, event)}>Delete from history</button></div>
        <p>Data deleted: <strong>{formatDateTime(scan.data_removed_at)}</strong></p>
        <small>Scan created: {scan.created_at ? formatDateTime(scan.created_at) : 'Not recorded'} · Status: {scan.status}</small>
        {confirmation(`history:${scan.run_uuid}`)}
      </article>)}
    </div> : tab === 'status' ? <div role="tabpanel" id="status-panel" aria-labelledby="status-tab" className="disk-card"><h3>System status</h3><p>API: {health || 'Unknown'}</p><p>Version: {version || 'Unknown'}</p><p>Use Disk info to inspect project storage and free disk space.</p></div> : <div role="tabpanel" id="disk-panel" aria-labelledby="disk-tab">
      <div className="disk-heading"><div><h3>Disk info</h3><p>Review application files by project and scan. Remove generated downloads or diagnostic scratch files, or delete all data for a finished scan.</p></div><button className="btn btn-secondary" disabled={loading || deleting} onClick={refresh}>{loading ? 'Measuring…' : 'Refresh disk usage'}</button></div>
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
        <StorageDistribution filesystem={data.filesystem} groups={groups} kind={kind} onFilter={category => { setKind(category === kind ? '' : category); setSelection({}); setPending(null) }} />
        <p className="disk-note">{data.note}</p>
        {data.cleanup && <div className="disk-card disk-accumulated">
          <div className="disk-heading"><div><h3>Accumulated generated files</h3><p>Inspect recurring storage outside saved scans. Select areas below, or clean all eligible areas.</p></div><strong>{diskSize(data.cleanup.reclaimable_bytes)} eligible</strong></div>
          <p className="disk-note">{data.cleanup.note}</p>
          {data.cleanup.ownership_warning && <p role="alert">{data.cleanup.ownership_warning}</p>}
          {data.cleanup.busy && <p role="status">Cleanup is locked while a scan or report is active.</p>}
          <div className="disk-toolbar">
            <button className="btn btn-danger delete-button" disabled={deleting || loading || data.cleanup.busy || !Object.values(areaSelection).length} onClick={event => confirm(Object.values(areaSelection), false, 'areas', event)}>Clean selected areas ({diskSize(Object.values(areaSelection).reduce((sum, area) => sum + area.bytes, 0))})</button>
            <button className="btn btn-secondary" disabled={deleting || loading || data.cleanup.busy || !data.cleanup.reclaimable_bytes} onClick={event => confirm(data.cleanup.areas.filter(area => area.reclaimable_bytes > 0).map(area => ({ area: area.id, label: area.label, bytes: area.reclaimable_bytes })), false, 'areas', event)}>Clean all eligible areas</button>
          </div>
          {confirmation('areas')}
          {data.cleanup.areas.map(area => <div className="disk-unit" key={area.id}>
            <div className="disk-unit-heading"><label className="disk-select"><input type="checkbox" aria-label={`Select cleanup area ${area.label}`} disabled={deleting || loading || data.cleanup.busy || !area.reclaimable_bytes} checked={Boolean(areaSelection[area.id])} onChange={event => setAreaSelection(previous => { const next = { ...previous }; if (event.target.checked) next[area.id] = { area: area.id, label: area.label, bytes: area.reclaimable_bytes }; else delete next[area.id]; return next })} /><span><strong>{area.label}</strong><small>{area.file_count} files · {area.eligible_files} eligible</small></span></label><div className="disk-area-sizes"><span>Used <strong>{diskSize(area.bytes)}</strong></span><span>Eligible <strong>{diskSize(area.reclaimable_bytes)}</strong></span></div></div>
            <p className="disk-note">{area.description}</p><code className="disk-path">{area.location}</code>
            {area.errors > 0 && <p role="alert">{area.errors} files could not be measured. These files will be retained.</p>}
            {area.samples.length > 0 && <details><summary>Example files</summary>{area.samples.map(path => <code className="disk-path" key={path}>{path}</code>)}</details>}
          </div>)}
          {data.cleanup.history.length > 0 && <details className="disk-cleanup-history"><summary>Previous cleanup activity</summary>{[...data.cleanup.history].reverse().slice(0, 5).map((entry, index) => <p key={`${entry.created_at}:${index}`}>{entry.created_at} · {entry.label || 'Generated storage cleanup'} · {diskSize(entry.removed_bytes)} removed{entry.failed_files ? ` · ${entry.failed_files} failed files` : ''}</p>)}</details>}
          <p className="disk-note">CLI preview: <code>python3 tools/cleanup_storage.py</code>. Add <code>--select area:ID --execute</code> for selective cleanup or <code>--all --execute --force</code> for noninteractive cleanup. Connect with <code>--url http://localhost:3030 --username USER</code> to manage the portal’s scan storage.</p>
        </div>}
        <div className="disk-toolbar"><label>Project<select value={project} onChange={e => { setProject(e.target.value); setSelection({}); setPending(null) }}><option value="">All projects</option>{data.projects.map(group => <option value={group.project_key} key={group.project_key}>{group.project_name}</option>)}</select></label><label>File category<select value={kind} onChange={e => { setKind(e.target.value); setSelection({}); setPending(null) }}><option value="">All categories</option>{Object.entries(categories).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></label><button className="btn btn-danger delete-button" disabled={!selected.length || deleting || loading} onClick={event => confirm(selected, false, 'selection', event)}>Delete selected ({selected.length})</button></div>
        {confirmation('selection')}
        {!groups.length && <p>No projects have saved storage.</p>}
        {groups.map(group => <div className="disk-project disk-card" key={group.project_key}>
          <div className="disk-heading"><div><h3>{group.project_name}</h3><small>{group.project_key} · {group.scans.length} scans · {diskSize(group.bytes)}</small></div><button className="btn btn-danger delete-button" disabled={deleting || loading || !group.scans.some(scan => scan.bytes > 0) || group.scans.some(scan => scan.active)} onClick={event => confirm(group.scans.filter(scan => scan.bytes > 0).map(scan => ({ runUuid: scan.run_uuid, bytes: scan.bytes, label: scan.run_uuid })), true, `project:${group.project_key}`, event)}>Delete project data</button></div>
          {confirmation(`project:${group.project_key}`)}
          {group.scans.length === 0 && <p>No saved scan files.</p>}
          {[...group.scans].sort((a,b) => b.bytes - a.bytes).map(scan => <details className="disk-scan" key={scan.run_uuid}>
            <summary><span>{scan.run_uuid}</span><span>{diskSize(scan.bytes)} · {scan.status}{scan.active ? ' · Cleanup locked: active scan/report' : ''}</span><span className="disk-scan-totals">{Object.entries(categories).map(([category, label]) => {
              const bytes = scan.units.filter(unit => unit.kind === category).reduce((sum, unit) => sum + unit.bytes, 0)
              return bytes > 0 ? <span key={category}>{label} <strong>{diskSize(bytes)}</strong></span> : null
            })}</span></summary>
            <div className="disk-scan-body"><div className="disk-heading"><p>{scan.created_at ? formatDateTime(scan.created_at) : 'Date unavailable'}{scan.data_removed ? ' · Saved data removed' : ''}</p><button className="btn btn-danger delete-button" disabled={scan.active || deleting || loading || scan.bytes === 0} onClick={event => confirm([{ runUuid: scan.run_uuid, bytes: scan.bytes, label: scan.run_uuid }], true, `scan:${scan.run_uuid}`, event)}>Delete scan data</button></div>
              {confirmation(`scan:${scan.run_uuid}`)}
              {scan.active && <p className="disk-note">Wait for this scan and its report jobs to finish before cleanup.</p>}
              {scan.units.filter(unit => !kind || unit.kind === kind).map(unit => <div className="disk-unit" key={unit.id}>
                <div className="disk-unit-heading"><label className="disk-select"><input type="checkbox" aria-label={`Select ${unit.label} from ${scan.run_uuid}`} disabled={!unit.removable || deleting || loading} checked={Boolean(selection[unit.id])} onChange={e => setSelection(previous => { const next = {...previous}; if (e.target.checked) next[unit.id] = { ...unit, runUuid: scan.run_uuid }; else delete next[unit.id]; return next })}/><span><strong>{unit.label}</strong><small>{categories[unit.kind]} · {unit.file_count} files · {diskSize(unit.bytes)}{unit.metadata.status ? ` · ${unit.metadata.status}` : ''}</small></span></label><button className="btn btn-danger delete-button" disabled={!unit.removable || deleting || loading} onClick={event => confirm([{ ...unit, runUuid: scan.run_uuid }], false, `unit:${scan.run_uuid}:${unit.id}`, event)}>Delete</button></div>
                {confirmation(`unit:${scan.run_uuid}:${unit.id}`)}
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
    {page && <><div className="disk-table-wrap"><table><thead><tr><th>File</th><th>Size</th><th>Modified</th></tr></thead><tbody>{page.files.map(file => <tr key={file.path}><td><code>{file.path}</code></td><td>{diskSize(file.bytes)}</td><td>{formatDateTime(file.modified_at)}</td></tr>)}</tbody></table></div><div className="disk-pagination"><span>{page.total ? `${offset + 1}–${Math.min(offset + page.limit, page.total)} of ${page.total} files` : 'No files'}</span><button className="btn btn-secondary" disabled={loading || offset === 0} onClick={() => setOffset(Math.max(0, offset - 100))}>Previous</button><button className="btn btn-secondary" disabled={loading || offset + 100 >= page.total} onClick={() => setOffset(offset + 100)}>Next</button></div></>}
  </>}</div>
}
