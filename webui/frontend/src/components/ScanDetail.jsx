import { useEffect, useMemo, useRef, useState } from 'react'
import { artifactUrl, getScanArtifacts, getScanFindings, getSuppressedFindings, listProjects, listScans, stopScan, streamScanLog } from '../api'
import FindingsReport from './FindingsReport'
import AdvancedAnalysis from './AdvancedAnalysis'
import InsightsPanel from './InsightsPanel'
import SuppressedPanel from './SuppressedPanel'
import VulnerabilitiesPanel from './VulnerabilitiesPanel'

function StatusBadge({ status }) {
  return (
    <span className={`badge ${status}`}>
      <span className={`badge-dot${status === 'running' ? ' pulse' : ''}`} />
      {status}
    </span>
  )
}

function niceDuration(sec) {
  if (sec == null) return '-'
  if (sec < 60) return `${Math.round(sec)}s`
  if (sec < 3600) return `${Math.floor(sec / 60)}m ${Math.round(sec % 60)}s`
  const hours = Math.floor(sec / 3600)
  const minutes = Math.floor((sec % 3600) / 60)
  const seconds = Math.round(sec % 60)
  return `${hours}h ${minutes}m ${seconds}s`
}

function niceDate(iso) {
  if (!iso) return '-'
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit'
  })
}

function ArtifactIcon({ name }) {
  const low = (name || '').toLowerCase()
  if (low.endsWith('.pdf')) return (
    <svg width="12" height="12" viewBox="0 0 20 20" fill="currentColor">
      <path fillRule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4zm2 6a1 1 0 011-1h6a1 1 0 110 2H7a1 1 0 01-1-1zm1 3a1 1 0 100 2h6a1 1 0 100-2H7z" clipRule="evenodd" />
    </svg>
  )
  if (low.endsWith('.json')) return (
    <svg width="12" height="12" viewBox="0 0 20 20" fill="currentColor">
      <path fillRule="evenodd" d="M12.316 3.051a1 1 0 01.633 1.265l-4 12a1 1 0 11-1.898-.632l4-12a1 1 0 011.265-.633zM5.707 6.293a1 1 0 010 1.414L3.414 10l2.293 2.293a1 1 0 11-1.414 1.414l-3-3a1 1 0 010-1.414l3-3a1 1 0 011.414 0zm8.586 0a1 1 0 011.414 0l3 3a1 1 0 010 1.414l-3 3a1 1 0 11-1.414-1.414L16.586 10l-2.293-2.293a1 1 0 010-1.414z" clipRule="evenodd" />
    </svg>
  )
  return (
    <svg width="12" height="12" viewBox="0 0 20 20" fill="currentColor">
      <path fillRule="evenodd" d="M4 4a2 2 0 012-2h8a2 2 0 012 2v12a2 2 0 01-2 2H6a2 2 0 01-2-2V4zm2 2v10h8V6H6z" clipRule="evenodd" />
    </svg>
  )
}

function shortName(path) {
  return (path || '').split('/').slice(-1)[0] || path
}

function pathToFileUrl(path) {
  if (!path) return ''
  const normalized = String(path).replace(/\\/g, '/')
  if (/^[a-zA-Z]:\//.test(normalized)) return `file:///${normalized}`
  return `file://${normalized}`
}

const SCAN_STAGES = [
  { id: 'initialization', label: 'Initialize' },
  { id: 'discovery', label: 'Discover' },
  { id: 'pattern_matching', label: 'Scan rules' },
  { id: 'path_analysis', label: 'Inspect paths' },
  { id: 'analysis', label: 'Analyze flows' },
  { id: 'reporting', label: 'Build reports' },
]

const STAGE_ALIASES = {
  queued: 'initialization',
  reconnaissance: 'discovery',
  completed: 'reporting',
}

function displayLabel(value) {
  return String(value || '')
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase())
}

function compactNumber(value) {
  const count = Number(value || 0)
  return new Intl.NumberFormat(undefined, { notation: count >= 10000 ? 'compact' : 'standard' }).format(count)
}

function initialProgressForRun(run) {
  if (!run || (run.status !== 'running' && run.status !== 'queued')) return null
  return {
    current_stage: run.status === 'queued' ? 'queued' : 'initialization',
    stage_status: run.status,
    message: run.status === 'queued'
      ? 'Scan queued - preparing isolated workspace'
      : 'Scan engine started - preparing repository',
    current_phase: run.status === 'queued' ? 'queued' : 'preparing_workspace',
    current_file: run.target_dir || '',
    current_index: 0,
    total_items: 0,
    elapsed_seconds: 0,
    directories_scanned: 0,
    files_discovered: 0,
    files_selected: 0,
    rules_match_count: 0,
    suppressed_count: 0,
    paths_match_count: 0,
    parse_error_count: 0,
  }
}

function ProgressCard({ progress, startedAt }) {
  const [clock, setClock] = useState(() => Date.now())

  useEffect(() => {
    const timer = window.setInterval(() => setClock(Date.now()), 1000)
    return () => window.clearInterval(timer)
  }, [])

  if (!progress) return null
  const hasPrimary = progress.message || progress.current_stage || progress.current_file || progress.rule_title
  if (!hasPrimary) return null

  const stageId = STAGE_ALIASES[progress.current_stage] || progress.current_stage || 'initialization'
  const activeStage = Math.max(0, SCAN_STAGES.findIndex((stage) => stage.id === stageId))
  const current = Number(progress.current_index || 0)
  const total = Number(progress.total_items || 0)
  const percent = total > 0 ? Math.min(100, Math.max(0, Math.round((current / total) * 100))) : null
  const startedMs = startedAt ? new Date(startedAt).getTime() : 0
  const clientElapsed = Number.isFinite(startedMs) && startedMs > 0 ? Math.max(0, Math.floor((clock - startedMs) / 1000)) : 0
  const elapsed = Math.max(Number(progress.elapsed_seconds || 0), clientElapsed)
  const rate = elapsed > 0 && progress.files_discovered > 0
    ? Math.round(Number(progress.files_discovered) / elapsed)
    : 0
  const details = [
    ['Platform', progress.platform],
    ['Phase', displayLabel(progress.current_phase)],
    ['Rule', progress.rule_title],
    ['Category', progress.category],
    ['Function', progress.current_function],
  ].filter(([, value]) => value)
  const metrics = [
    ['Files mapped', progress.files_discovered, 'files'],
    ['Scan candidates', progress.files_selected, 'selected'],
    ['Directories', progress.directories_scanned, 'visited'],
    ['Areas of interest', progress.rules_match_count, 'live findings'],
  ]

  return (
    <section className="live-scan-card" aria-live="polite" aria-label="Live scan telemetry">
      <div className="live-scan-glow" />
      <header className="live-scan-header">
        <div className="live-scan-title-wrap">
          <span className="live-scan-orbit" aria-hidden="true"><i /></span>
          <div>
            <div className="live-scan-eyebrow"><span className="live-dot" /> Live scan telemetry</div>
            <h3>{progress.message || 'Scan engine is working'}</h3>
          </div>
        </div>
        <div className="live-scan-time">
          <span>Elapsed</span>
          <strong>{niceDuration(elapsed)}</strong>
        </div>
      </header>

      <div className="live-stage-rail" aria-label={`Current stage: ${displayLabel(stageId)}`}>
        {SCAN_STAGES.map((stage, index) => (
          <div className={`live-stage${index < activeStage ? ' complete' : ''}${index === activeStage ? ' active' : ''}`} key={stage.id}>
            <span className="live-stage-node">{index < activeStage ? '✓' : index + 1}</span>
            <span>{stage.label}</span>
          </div>
        ))}
      </div>

      <div className="live-progress-row">
        <div className={`live-progress-track${percent == null ? ' indeterminate' : ''}`}>
          <span style={percent == null ? undefined : { width: `${percent}%` }} />
        </div>
        <strong>{percent == null ? 'LIVE' : `${percent}%`}</strong>
      </div>

      <div className="live-metric-grid">
        {metrics.map(([label, value, hint]) => (
          <div className="live-metric" key={label}>
            <span>{label}</span>
            <strong>{compactNumber(value)}</strong>
            <small>{hint}</small>
          </div>
        ))}
      </div>

      <div className="live-current-work">
        <span className="live-current-icon" aria-hidden="true">⌁</span>
        <div>
          <span>Current location</span>
          <strong title={progress.current_file || ''}>{progress.current_file || 'Preparing scan workspace…'}</strong>
        </div>
        {rate > 0 ? <span className="live-rate">{compactNumber(rate)} files/sec</span> : null}
      </div>

      {details.length > 0 ? (
        <div className="live-detail-chips">
          {details.map(([label, value]) => (
            <span key={label}><small>{label}</small>{value}</span>
          ))}
        </div>
      ) : null}

      <footer className="live-scan-footer">
        <span><b>{compactNumber(progress.suppressed_count)}</b> suppressed</span>
        <span><b>{compactNumber(progress.paths_match_count)}</b> path signals</span>
        <span className={progress.parse_error_count > 0 ? 'has-errors' : ''}><b>{compactNumber(progress.parse_error_count)}</b> parse errors</span>
        {total > 0 ? <span>{compactNumber(current)} of {compactNumber(total)} processed</span> : <span>Repository size is being measured</span>}
      </footer>
    </section>
  )
}

function dlChipClass(name) {
  const low = (name || '').toLowerCase()
  if (low.endsWith('.pdf')) return 'artifact-chip pdf'
  if (low.endsWith('.json')) return 'artifact-chip json'
  return 'artifact-chip'
}

function artifactLabel(path) {
  const normalized = String(path || '').replace(/\\/g, '/')
  const filename = shortName(normalized)
  const labels = {
    'report.html': 'Main consolidated report',
    'analysis.html': 'Taint analysis report',
    'analysis_xref.html': 'Cross-reference report',
    'analysis.json': 'Analysis data',
    'estimation.html': 'Review effort estimate',
    'reconnaissance.html': 'Reconnaissance report',
    'areas_of_interest.json': 'Areas of interest data',
    'filepaths_aoi.json': 'Path findings data',
    'summary.json': 'Scan summary data',
    'suppressed_findings.json': 'Suppressed findings data',
    'filepaths_all.html': 'Complete file-path inventory',
    'filepaths_aoi.html': 'Path areas of interest',
  }
  if (labels[filename]) return labels[filename]
  if (/\/multi-file\/index\.html$/i.test(normalized)) return 'Detailed reports index'
  if (/\/multi-file\/aoi\/index\.html$/i.test(normalized)) return 'Areas of interest index'
  if (/\/multi-file\/aoi\/[^/]+\.html$/i.test(normalized)) return `${displayLabel(filename.replace(/\.html$/i, ''))} findings report`
  if (/filepaths_[^.]+\.log$/i.test(filename)) return `${displayLabel(filename.replace(/^filepaths_|\.log$/gi, ''))} file inventory`
  return displayLabel(filename.replace(/\.[^.]+$/, '')) || filename
}

function artifactKind(path) {
  const filename = shortName(path).toLowerCase()
  if (filename === 'analysis.html') return 'Analyzer report'
  if (filename === 'analysis_xref.html') return 'Cross-references'
  if (filename.endsWith('.json')) return 'Structured data'
  if (filename.endsWith('.pdf')) return 'PDF report'
  if (filename.endsWith('.log')) return 'Diagnostic inventory'
  return 'HTML report'
}

function buildArtifactCatalog(paths) {
  const unique = Array.from(new Set(paths.filter(Boolean)))
  const catalog = {
    primary: null,
    scanReports: [],
    platformAnalysis: new Map(),
    platformFindings: [],
    data: [],
    runtime: [],
    other: [],
  }

  for (const path of unique) {
    const normalized = String(path).replace(/\\/g, '/')
    const analysisMatch = normalized.match(/\/analysis\/([^/]+)\/([^/]+)$/i)
    const findingsMatch = normalized.match(/\/scan\/html\/multi-file\/aoi\/([^/]+)\.html$/i)

    if (/\/scan\/html\/report\.html$/i.test(normalized)) {
      catalog.primary = path
    } else if (analysisMatch) {
      const platform = analysisMatch[1]
      if (!catalog.platformAnalysis.has(platform)) catalog.platformAnalysis.set(platform, [])
      catalog.platformAnalysis.get(platform).push(path)
    } else if (findingsMatch && findingsMatch[1].toLowerCase() !== 'index') {
      catalog.platformFindings.push({ platform: findingsMatch[1], path })
    } else if (/\/scan\/(?:html|pdf|estimate|recon)\//i.test(normalized)) {
      catalog.scanReports.push(path)
    } else if (/\/data\/[^/]+$/i.test(normalized)) {
      catalog.data.push(path)
    } else if (/\/runtime\/|\/web_runs_v2\//i.test(normalized) || /\.log$/i.test(normalized)) {
      catalog.runtime.push(path)
    } else {
      catalog.other.push(path)
    }
  }

  const byName = (a, b) => artifactLabel(a).localeCompare(artifactLabel(b))
  catalog.scanReports.sort(byName)
  catalog.platformFindings.sort((a, b) => a.platform.localeCompare(b.platform))
  catalog.data.sort(byName)
  catalog.runtime.sort(byName)
  catalog.other.sort(byName)
  for (const items of catalog.platformAnalysis.values()) items.sort(byName)
  return catalog
}

function ArtifactActions({ path }) {
  return (
    <div className="dl-actions">
      <a href={artifactUrl(path)} target="_blank" rel="noreferrer" className="btn btn-secondary btn-sm">Open ↗</a>
      <a href={artifactUrl(path)} download className="btn btn-ghost btn-sm">Download</a>
    </div>
  )
}

function ArtifactRow({ path, label, context }) {
  return (
    <div className="dl-row">
      <span className={dlChipClass(path)} aria-hidden="true"><ArtifactIcon name={path} /></span>
      <div className="dl-file-copy">
        <strong>{label || artifactLabel(path)}</strong>
        <span>{context || artifactKind(path)}</span>
        <code title={path}>{path}</code>
      </div>
      <ArtifactActions path={path} />
    </div>
  )
}

function ArtifactGroup({ title, description, paths, children, defaultOpen = true, tone = '' }) {
  const count = paths?.length || 0
  if (!count) return null
  return (
    <details className={`dl-group ${tone}`} open={defaultOpen}>
      <summary>
        <div><strong>{title}</strong><span>{description}</span></div>
        <span className="dl-group-count">{count || ''}{count ? ` file${count === 1 ? '' : 's'}` : ''}</span>
      </summary>
      <div className="dl-group-body">
        {children || paths.map((path) => <ArtifactRow key={path} path={path} />)}
      </div>
    </details>
  )
}

function projectDisplay(project) {
  return project ? `${project.project_name || project.project_key} · ${project.project_key}` : ''
}

function scanDisplay(scan) {
  return scan ? `Scan from ${niceDate(scan.created_at)} · ${displayLabel(scan.status)}` : ''
}

function DownloadScopePicker({ projects, scans, projectKey, runUuid, loading, onProjectSelect, onRunSelect }) {
  const selectedProject = projects.find((project) => project.project_key === projectKey)
  const selectedRun = scans.find((scan) => scan.run_uuid === runUuid)
  const [projectQuery, setProjectQuery] = useState('')
  const [scanQuery, setScanQuery] = useState('')
  const [projectOpen, setProjectOpen] = useState(false)
  const [scanOpen, setScanOpen] = useState(false)

  useEffect(() => setProjectQuery(projectDisplay(selectedProject)), [selectedProject?.project_key, selectedProject?.project_name])
  useEffect(() => setScanQuery(scanDisplay(selectedRun)), [selectedRun?.run_uuid, selectedRun?.status])

  const matchingProjects = useMemo(() => {
    const query = projectQuery.trim().toLowerCase()
    if (!query || projectDisplay(selectedProject).toLowerCase() === query) return projects
    return projects.filter((project) => `${project.project_name} ${project.project_key}`.toLowerCase().includes(query))
  }, [projects, projectQuery, selectedProject])

  const matchingScans = useMemo(() => {
    const query = scanQuery.trim().toLowerCase()
    if (!query || scanDisplay(selectedRun).toLowerCase() === query) return scans
    return scans.filter((scan) => `${scanDisplay(scan)} ${scan.run_uuid} ${scan.rules || ''}`.toLowerCase().includes(query))
  }, [scans, scanQuery, selectedRun])

  return (
    <section className="dl-scope" aria-label="Choose project and scan reports">
      <div className="dl-scope-heading">
        <div><span>Report browser</span><h3>Select a project and scan</h3></div>
        {loading ? <span className="dl-scope-loading"><i /> Loading reports…</span> : null}
      </div>
      <div className="dl-scope-grid">
        <div className="dl-combobox">
          <label htmlFor="download-project-search">Project</label>
          <div className="dl-search-input-wrap">
            <span aria-hidden="true">⌕</span>
            <input
              id="download-project-search"
              value={projectQuery}
              placeholder="Search project name or ID…"
              autoComplete="off"
              onFocus={() => setProjectOpen(true)}
              onBlur={() => setTimeout(() => setProjectOpen(false), 120)}
              onChange={(event) => { setProjectQuery(event.target.value); setProjectOpen(true) }}
              role="combobox"
              aria-expanded={projectOpen}
              aria-controls="download-project-options"
            />
          </div>
          {projectOpen ? (
            <div className="dl-options" id="download-project-options" role="listbox">
              {matchingProjects.length ? matchingProjects.map((project) => (
                <button
                  type="button"
                  role="option"
                  aria-selected={project.project_key === projectKey}
                  key={project.project_key}
                  onMouseDown={(event) => event.preventDefault()}
                  onClick={() => { onProjectSelect(project); setProjectOpen(false) }}
                >
                  <strong>{project.project_name || project.project_key}</strong>
                  <span>Project ID: {project.project_key}</span>
                  <small>{project.total_scans ?? 0} scan{project.total_scans === 1 ? '' : 's'}</small>
                </button>
              )) : <div className="dl-no-options">No projects match “{projectQuery}”.</div>}
            </div>
          ) : null}
        </div>

        <div className="dl-combobox">
          <label htmlFor="download-scan-search">Scan</label>
          <div className="dl-search-input-wrap">
            <span aria-hidden="true">⌕</span>
            <input
              id="download-scan-search"
              value={scanQuery}
              placeholder={projectKey ? 'Search date, status, or run ID…' : 'Select a project first'}
              disabled={!projectKey || loading}
              autoComplete="off"
              onFocus={() => setScanOpen(true)}
              onBlur={() => setTimeout(() => setScanOpen(false), 120)}
              onChange={(event) => { setScanQuery(event.target.value); setScanOpen(true) }}
              role="combobox"
              aria-expanded={scanOpen}
              aria-controls="download-scan-options"
            />
          </div>
          {scanOpen ? (
            <div className="dl-options" id="download-scan-options" role="listbox">
              {matchingScans.length ? matchingScans.map((scan) => (
                <button
                  type="button"
                  role="option"
                  aria-selected={scan.run_uuid === runUuid}
                  key={scan.run_uuid}
                  onMouseDown={(event) => event.preventDefault()}
                  onClick={() => { onRunSelect(scan); setScanOpen(false) }}
                >
                  <strong>{scanDisplay(scan)}</strong>
                  <span>Run ID: {scan.run_uuid}</span>
                  <small>{scan.rules || 'auto'} rules{scan.duration_sec != null ? ` · ${niceDuration(scan.duration_sec)}` : ''}</small>
                </button>
              )) : <div className="dl-no-options">No scans match “{scanQuery}”.</div>}
            </div>
          ) : null}
        </div>
      </div>
      {selectedProject && selectedRun ? (
        <div className="dl-scope-current">
          <span>{selectedProject.project_name || selectedProject.project_key}</span>
          <code>{selectedProject.project_key}</code>
          <i>→</i>
          <span>{niceDate(selectedRun.created_at)}</span>
          <code>{selectedRun.run_uuid}</code>
        </div>
      ) : null}
    </section>
  )
}

export default function ScanDetail({ run, log: logProp, artifactIndex, onStopped }) {
  const [tab, setTab] = useState('findings')
  const [liveLog, setLiveLog] = useState('')
  const [liveProgress, setLiveProgress] = useState(null)
  const [stopping, setStopping] = useState(false)
  const [findingsData, setFindingsData] = useState(null)
  const [findingsLoading, setFindingsLoading] = useState(false)
  const [suppressedCount, setSuppressedCount] = useState(null)
  const [downloadProjects, setDownloadProjects] = useState([])
  const [downloadRuns, setDownloadRuns] = useState([])
  const [downloadProjectKey, setDownloadProjectKey] = useState(run?.project_key || '')
  const [downloadRunUuid, setDownloadRunUuid] = useState(run?.run_uuid || '')
  const [downloadArtifacts, setDownloadArtifacts] = useState(artifactIndex)
  const [downloadsLoading, setDownloadsLoading] = useState(false)
  const [downloadsError, setDownloadsError] = useState('')
  const cancelSseRef = useRef(null)
  const logPaneRef = useRef(null)
  const downloadRequestRef = useRef(0)

  const isActive = run?.status === 'running' || run?.status === 'queued'

  // SSE live log - start when scan becomes active
  useEffect(() => {
    if (cancelSseRef.current) {
      cancelSseRef.current()
      cancelSseRef.current = null
    }
    setLiveLog('')
    setLiveProgress(initialProgressForRun(run))

    if (!run?.run_uuid || !isActive) return

    const cancel = streamScanLog(
      run.run_uuid,
      (chunk, _status, progress) => {
        if (chunk) {
          setLiveLog((prev) => prev + chunk)
        }
        if (progress) {
          setLiveProgress(progress)
        }
        if (logPaneRef.current) {
          logPaneRef.current.scrollTop = logPaneRef.current.scrollHeight
        }
      },
      () => {
        cancelSseRef.current = null
        if (onStopped) onStopped(run.run_uuid)
      }
    )
    cancelSseRef.current = cancel

    return () => {
      cancel()
      cancelSseRef.current = null
    }
  }, [run?.run_uuid, isActive])

  useEffect(() => {
    if (downloadRunUuid === run?.run_uuid && artifactIndex) setDownloadArtifacts(artifactIndex)
  }, [artifactIndex, downloadRunUuid, run?.run_uuid])

  useEffect(() => {
    if (tab !== 'downloads' || !run?.run_uuid) return
    const requestId = ++downloadRequestRef.current
    setDownloadProjectKey(run.project_key || '')
    setDownloadRunUuid(run.run_uuid)
    setDownloadArtifacts(artifactIndex)
    setDownloadsError('')
    setDownloadsLoading(true)

    Promise.all([
      listProjects(),
      listScans(200, run.project_key || ''),
    ]).then(([projects, scans]) => {
      if (requestId !== downloadRequestRef.current) return
      setDownloadProjects(projects)
      setDownloadRuns(scans)
    }).catch((error) => {
      if (requestId === downloadRequestRef.current) setDownloadsError(`Could not load report history: ${error.message}`)
    }).finally(() => {
      if (requestId === downloadRequestRef.current) setDownloadsLoading(false)
    })
  }, [tab, run?.run_uuid, run?.project_key])

  async function selectDownloadRun(scan) {
    const requestId = ++downloadRequestRef.current
    setDownloadRunUuid(scan.run_uuid)
    setDownloadArtifacts(null)
    setDownloadsError('')
    setDownloadsLoading(true)
    try {
      const artifacts = await getScanArtifacts(scan.run_uuid)
      if (requestId === downloadRequestRef.current) setDownloadArtifacts(artifacts)
    } catch (error) {
      if (requestId === downloadRequestRef.current) setDownloadsError(`Could not load reports for this scan: ${error.message}`)
    } finally {
      if (requestId === downloadRequestRef.current) setDownloadsLoading(false)
    }
  }

  async function selectDownloadProject(project) {
    const requestId = ++downloadRequestRef.current
    setDownloadProjectKey(project.project_key)
    setDownloadRunUuid('')
    setDownloadRuns([])
    setDownloadArtifacts(null)
    setDownloadsError('')
    setDownloadsLoading(true)
    try {
      const scans = await listScans(200, project.project_key)
      if (requestId !== downloadRequestRef.current) return
      setDownloadRuns(scans)
      const latest = scans[0]
      if (!latest) return
      setDownloadRunUuid(latest.run_uuid)
      const artifacts = await getScanArtifacts(latest.run_uuid)
      if (requestId === downloadRequestRef.current) setDownloadArtifacts(artifacts)
    } catch (error) {
      if (requestId === downloadRequestRef.current) setDownloadsError(`Could not load this project's reports: ${error.message}`)
    } finally {
      if (requestId === downloadRequestRef.current) setDownloadsLoading(false)
    }
  }

  // Reset state when selected scan changes, and (if it's already done) fetch
  // its findings/suppressed count immediately in the same commit - a
  // separate effect gating on a `findingsData`/`suppressedCount !== null`
  // check would still see the *previous* scan's non-null cached value here,
  // since those setters above haven't re-rendered yet, and would skip the
  // fetch entirely.
  useEffect(() => {
    setTab('findings')
    setStopping(false)
    setFindingsData(null)
    setSuppressedCount(null)
    setLiveProgress(initialProgressForRun(run))

    if (!run?.run_uuid || isActive) return

    setFindingsLoading(true)
    getScanFindings(run.run_uuid)
      .then((d) => setFindingsData(d))
      .catch(() => setFindingsData({}))
      .finally(() => setFindingsLoading(false))

    getSuppressedFindings(run.run_uuid)
      .then((d) => setSuppressedCount(d?.summary?.total_suppressed ?? 0))
      .catch(() => {})
  }, [run?.run_uuid])

  // Reload findings when scan transitions from running → done
  useEffect(() => {
    if (!run?.run_uuid || isActive) return
    getScanFindings(run.run_uuid)
      .then((d) => setFindingsData(d))
      .catch(() => {})
  }, [isActive])

  async function handleStop() {
    if (!run?.run_uuid) return
    setStopping(true)
    try {
      await stopScan(run.run_uuid)
    } catch {
      // ignore - status updates on next poll
    } finally {
      setStopping(false)
    }
  }

  const displayLog = isActive ? liveLog : (logProp || liveLog)

  const allArtifacts = useMemo(() => {
    if (!downloadArtifacts) return []
    return [
      ...(downloadArtifacts.report_html ? [downloadArtifacts.report_html] : []),
      ...(downloadArtifacts.xref_html ? [downloadArtifacts.xref_html] : []),
      ...(downloadArtifacts.other_html || []),
      ...(downloadArtifacts.json_files || []),
      ...(downloadArtifacts.pdf_files || []),
      ...(downloadArtifacts.logs || []),
    ]
  }, [downloadArtifacts])

  const artifactCatalog = useMemo(() => buildArtifactCatalog(allArtifacts), [allArtifacts])

  const findingsCount = findingsData?.findings?.length ?? 0
  const inputMeta = findingsData?.scan_meta?.inputs_received || {}
  const resolvedProjectId = inputMeta?.project_id || ''
  const resolvedRunId = inputMeta?.run_id || run?.run_uuid || ''
  const resolvedReportRoot = inputMeta?.report_root || ''
  const selectedArtifactRoot = useMemo(() => {
    if (downloadRunUuid === run?.run_uuid && resolvedReportRoot) return resolvedReportRoot
    const reportPath = allArtifacts.find((path) => /\/(?:scan|analysis|data)\//.test(String(path).replace(/\\/g, '/')))
    return reportPath ? String(reportPath).replace(/\\/g, '/').split(/\/(?:scan|analysis|data)\//)[0] : ''
  }, [allArtifacts, downloadRunUuid, resolvedReportRoot, run?.run_uuid])

  if (!run) {
    return (
      <div className="detail-panel">
        <div className="detail-header">
          <div className="detail-title">Areas of Interest Workspace</div>
        </div>
        <div className="detail-tab-content">
          <div className="empty-state">
            <svg className="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path strokeLinecap="round" strokeLinejoin="round" d="M15.042 21.672L13.684 16.6m0 0l-2.51 2.225.569-9.47 5.227 7.917-3.286-.672zm-7.518-.267A8.25 8.25 0 1120.25 10.5M8.288 14.212A5.25 5.25 0 1117.25 10.5" />
            </svg>
            <div className="empty-title">No scan selected</div>
            <div className="empty-msg">Select a scan from the list to view its areas of interest, artifacts, and execution log.</div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="detail-panel">
      {/* Header */}
      <div className="detail-header">
        <div className="detail-title">
          <span>{run.project_name || run.run_uuid}</span>
          <StatusBadge status={run.status} />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {isActive && (
            <button
              className="btn btn-sm"
              style={{ background: 'var(--danger-color)', color: '#fff', border: 'none' }}
              onClick={handleStop}
              disabled={stopping}
            >
              {stopping ? '…' : '⏹ Stop'}
            </button>
          )}
        </div>
        <div className="detail-meta">
          {run.run_uuid} · {niceDate(run.created_at)}
          {run.duration_sec != null && ` · ${niceDuration(run.duration_sec)}`}
        </div>
        {(resolvedProjectId || resolvedRunId) && (
          <div className="detail-meta">
            {resolvedProjectId ? `project-id: ${resolvedProjectId}` : ''}
            {resolvedProjectId && resolvedRunId ? ' · ' : ''}
            {resolvedRunId ? `run-id: ${resolvedRunId}` : ''}
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="detail-tabs">
        <button
          className={`detail-tab${tab === 'findings' ? ' active' : ''}`}
          onClick={() => setTab('findings')}
        >
          Areas of Interest{!isActive && findingsCount > 0 ? ` (${findingsCount})` : ''}
        </button>
        <button
          className={`detail-tab${tab === 'advanced-analysis' ? ' active' : ''}`}
          onClick={() => setTab('advanced-analysis')}
        >
          {(() => {
            const taintCount = findingsData?.analysis?.results
              ?.filter((r) => r.engine === 'dataflow_controlflow')
              ?.flatMap((r) => (r.findings || []).filter((f) => f.analysis_kind === 'taint_flow'))
              ?.length ?? 0
            return `Advanced Analysis${!isActive && taintCount > 0 ? ` (${taintCount})` : ''}`
          })()}
        </button>
        <button
          className={`detail-tab${tab === 'vulnerabilities' ? ' active' : ''}`}
          onClick={() => setTab('vulnerabilities')}
        >
          {(() => {
            const vulnCount = findingsData?.analysis?.summary?.confirmed_vulnerabilities ?? 0
            return `Vulnerabilities${!isActive && vulnCount > 0 ? ` (${vulnCount})` : ''}`
          })()}
        </button>
        <button
          className={`detail-tab${tab === 'insights' ? ' active' : ''}`}
          onClick={() => setTab('insights')}
        >
          {(() => {
            const fpCount = findingsData?.filepaths?.length ?? 0
            const hasRecon = !!findingsData?.recon
            const hasEstimate = run?.estimate
            const total = fpCount + (hasRecon ? 1 : 0) + (hasEstimate ? 1 : 0)
            return `Insights${!isActive && total > 0 ? ` (${fpCount > 0 ? fpCount + ' paths' : hasRecon ? 'recon' : 'estimate'})` : ''}`
          })()}
        </button>
        <button
          className={`detail-tab${tab === 'downloads' ? ' active' : ''}`}
          onClick={() => setTab('downloads')}
        >
          Downloads{allArtifacts.length > 0 ? ` (${allArtifacts.length})` : ''}
        </button>
        <button
          className={`detail-tab${tab === 'summary' ? ' active' : ''}`}
          onClick={() => setTab('summary')}
        >
          Summary
        </button>
        <button
          className={`detail-tab${tab === 'log' ? ' active' : ''}`}
          onClick={() => setTab('log')}
        >
          Log
        </button>
        <button
          className={`detail-tab${tab === 'suppressed' ? ' active' : ''}`}
          onClick={() => setTab('suppressed')}
        >
          {`Suppressed FPs${!isActive && suppressedCount != null && suppressedCount > 0 ? ` (${suppressedCount})` : ''}`}
        </button>
      </div>

      {isActive ? (
        <div className="live-scan-shell">
          <ProgressCard progress={liveProgress} startedAt={run.started_at || run.created_at} />
        </div>
      ) : null}

      {/* Tab: Areas of Interest */}
      {tab === 'findings' && (
        <div className="detail-tab-content findings-tab-content">
          {isActive ? (
            <div className="empty-state" style={{ padding: '40px 20px' }}>
              <svg className="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path strokeLinecap="round" strokeLinejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99" />
              </svg>
              <div className="empty-title">Scan in progress…</div>
              <div className="empty-msg">Areas of interest will appear here once the scan completes. Check the Log tab for live output.</div>
            </div>
          ) : findingsLoading ? (
            <div className="fr-loading">
              <div className="fr-spinner" />
              <span>Loading areas of interest…</span>
            </div>
          ) : (
            <FindingsReport
              data={findingsData}
              status={run.status}
              onViewAnalysis={() => setTab('vulnerabilities')}
            />
          )}
        </div>
      )}

      {tab === 'advanced-analysis' && (
        <div className="detail-tab-content findings-tab-content">
          {isActive ? (
            <div className="empty-state" style={{ padding: '40px 20px' }}>
              <svg className="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path strokeLinecap="round" strokeLinejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99" />
              </svg>
              <div className="empty-title">Scan in progress…</div>
              <div className="empty-msg">Advanced Analysis will appear here once the scan completes.</div>
            </div>
          ) : findingsLoading ? (
            <div className="fr-loading">
              <div className="fr-spinner" />
              <span>Loading advanced analysis…</span>
            </div>
          ) : (
            <AdvancedAnalysis analysis={findingsData?.analysis} artifactIndex={artifactIndex} />
          )}
        </div>
      )}

      {tab === 'vulnerabilities' && (
        <div className="detail-tab-content findings-tab-content">
          {isActive ? (
            <div className="empty-state" style={{ padding: '40px 20px' }}>
              <div className="empty-title">Scan in progress…</div>
              <div className="empty-msg">Confirmed vulnerabilities and mitigated implementations will appear here once the scan completes.</div>
            </div>
          ) : findingsLoading ? (
            <div className="fr-loading">
              <div className="fr-spinner" />
              <span>Loading vulnerability confirmation…</span>
            </div>
          ) : (
            <VulnerabilitiesPanel analysis={findingsData?.analysis} />
          )}
        </div>
      )}

      {/* Tab: Insights */}
      {tab === 'insights' && (
        <div className="detail-tab-content findings-tab-content">
          {isActive ? (
            <div className="empty-state" style={{ padding: '40px 20px' }}>
              <div className="empty-title">Scan in progress…</div>
              <div className="empty-msg">Insights will appear once the scan completes.</div>
            </div>
          ) : findingsLoading ? (
            <div className="fr-loading"><div className="fr-spinner" /><span>Loading insights…</span></div>
          ) : (
            <InsightsPanel findingsData={findingsData} artifactIndex={artifactIndex} run={run} />
          )}
        </div>
      )}

      {/* Tab: Downloads */}
      {tab === 'downloads' && (
        <div className="detail-tab-content">
          <DownloadScopePicker
            projects={downloadProjects}
            scans={downloadRuns}
            projectKey={downloadProjectKey}
            runUuid={downloadRunUuid}
            loading={downloadsLoading}
            onProjectSelect={selectDownloadProject}
            onRunSelect={selectDownloadRun}
          />
          {downloadsError ? <div className="error-banner dl-error">{downloadsError}</div> : null}
          {selectedArtifactRoot && (
            <div className="info-item" style={{ marginBottom: 14 }}>
              <div className="info-label">Artifact Root</div>
              <div className="info-value" style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                <span style={{ wordBreak: 'break-all' }}>{selectedArtifactRoot}</span>
                <a className="link-btn" href={pathToFileUrl(selectedArtifactRoot)} target="_blank" rel="noreferrer">Open Folder</a>
              </div>
            </div>
          )}
          {allArtifacts.length === 0 ? (
            <div className="empty-state" style={{ padding: '30px 20px' }}>
              <div className="empty-title">{downloadsLoading ? 'Loading reports…' : 'No downloads available'}</div>
              <div className="empty-msg">
                {downloadsLoading
                  ? 'Retrieving the selected scan artifact index.'
                  : !downloadRunUuid
                    ? 'This project does not have any scans yet.'
                    : isActive && downloadRunUuid === run.run_uuid
                  ? 'Artifacts will appear here when the scan completes.'
                  : 'No artifacts were generated for this scan.'}
              </div>
            </div>
          ) : (
            <div className="dl-catalog">
              {artifactCatalog.primary ? (
                <div className="dl-primary">
                  <div className="dl-primary-icon"><ArtifactIcon name={artifactCatalog.primary} /></div>
                  <div className="dl-primary-copy">
                    <span>Start here</span>
                    <h3>Main consolidated scan report</h3>
                    <p>The primary <code>report.html</code> overview linking the detailed platform and path reports generated for this scan.</p>
                    <code title={artifactCatalog.primary}>{artifactCatalog.primary}</code>
                  </div>
                  <ArtifactActions path={artifactCatalog.primary} />
                </div>
              ) : null}

              <ArtifactGroup
                title="Scan overview reports"
                description="Navigation, reconnaissance, estimation, and cross-platform report indexes."
                paths={artifactCatalog.scanReports}
              />

              <ArtifactGroup
                title="Platform findings reports"
                description="Areas of interest separated by the rule platform that produced them."
                paths={artifactCatalog.platformFindings.map((item) => item.path)}
              >
                <div className="dl-platform-grid">
                  {artifactCatalog.platformFindings.map(({ platform, path }) => (
                    <div className="dl-platform-card" key={path}>
                      <span className="dl-platform-badge">{displayLabel(platform)}</span>
                      <ArtifactRow path={path} label="Areas of interest" context="Platform findings report" />
                    </div>
                  ))}
                </div>
              </ArtifactGroup>

              <ArtifactGroup
                title="Platform advanced analysis"
                description="Taint analysis, cross-references, and machine-readable results grouped by platform."
                paths={Array.from(artifactCatalog.platformAnalysis.values()).flat()}
              >
                <div className="dl-platform-grid">
                  {Array.from(artifactCatalog.platformAnalysis.entries())
                    .sort(([a], [b]) => a.localeCompare(b))
                    .map(([platform, paths]) => (
                      <div className="dl-platform-card" key={platform}>
                        <div className="dl-platform-head">
                          <span className="dl-platform-badge">{displayLabel(platform)}</span>
                          <span>{paths.length} file{paths.length === 1 ? '' : 's'}</span>
                        </div>
                        {paths.map((path) => <ArtifactRow key={path} path={path} />)}
                      </div>
                    ))}
                </div>
              </ArtifactGroup>

              <ArtifactGroup
                title="Structured scan data"
                description="JSON exports intended for integrations, automation, and detailed inspection."
                paths={artifactCatalog.data}
                defaultOpen={false}
                tone="technical"
              />

              <ArtifactGroup
                title="Runtime diagnostics"
                description="Internal inventories and scan-state files useful for troubleshooting or audit evidence."
                paths={artifactCatalog.runtime}
                defaultOpen={false}
                tone="technical"
              />

              <ArtifactGroup
                title="Other generated files"
                description="Additional outputs that do not belong to one of the report families above."
                paths={artifactCatalog.other}
                defaultOpen={false}
              />
            </div>
          )}
        </div>
      )}

      {/* Tab: Summary */}
      {tab === 'summary' && (
        <div className="detail-tab-content">
          <div className="info-grid">
            <div className="info-item">
              <div className="info-label">Project</div>
              <div className="info-value">{run.project_name || '-'}</div>
            </div>
            <div className="info-item">
              <div className="info-label">Project ID</div>
              <div className="info-value">{resolvedProjectId || '-'}</div>
            </div>
            <div className="info-item">
              <div className="info-label">Run ID</div>
              <div className="info-value">{resolvedRunId || '-'}</div>
            </div>
            <div className="info-item">
              <div className="info-label">Status</div>
              <div className="info-value">{run.status}</div>
            </div>
            <div className="info-item">
              <div className="info-label">Rules</div>
              <div className="info-value">{run.rules || '-'}</div>
            </div>
            <div className="info-item">
              <div className="info-label">Report Format</div>
              <div className="info-value">{run.report_format || '-'}</div>
            </div>
            <div className="info-item" style={{ gridColumn: '1 / -1' }}>
              <div className="info-label">Target Directory</div>
              <div className="info-value">{run.target_dir}</div>
            </div>
            <div className="info-item" style={{ gridColumn: '1 / -1' }}>
              <div className="info-label">Report Root</div>
              <div className="info-value" style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                <span style={{ wordBreak: 'break-all' }}>{resolvedReportRoot || '-'}</span>
                {resolvedReportRoot && (
                  <a className="link-btn" href={pathToFileUrl(resolvedReportRoot)} target="_blank" rel="noreferrer">Open Folder</a>
                )}
              </div>
            </div>
            {run.file_types && (
              <div className="info-item">
                <div className="info-label">File Types</div>
                <div className="info-value">{run.file_types}</div>
              </div>
            )}
            <div className="info-item">
              <div className="info-label">Duration</div>
              <div className="info-value">{niceDuration(run.duration_sec)}</div>
            </div>
            {(() => {
              const det = findingsData?.scan_meta?.detection_summary
              const totalFiles = det?.total_files_scanned ?? det?.total_files_identified
              const totalLoc = det?.total_loc
              return (
                <>
                  {totalFiles != null && (
                    <div className="info-item">
                      <div className="info-label">Total Files Scanned</div>
                      <div className="info-value">{Number(totalFiles).toLocaleString()}</div>
                    </div>
                  )}
                  {totalLoc != null && (
                    <div className="info-item">
                      <div className="info-label">Total Lines of Code</div>
                      <div className="info-value">{Number(totalLoc).toLocaleString()}</div>
                    </div>
                  )}
                </>
              )
            })()}
          </div>

          <div className="info-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
            {[
              { label: 'Recon', val: run.recon },
              { label: 'Estimate', val: run.estimate },
              { label: 'Analysis', val: run.analysis },
              { label: 'Count LoC', val: run.loc },
            ].map(({ label, val }) => (
              <div key={label} className="info-item" style={{ textAlign: 'center' }}>
                <div className="info-label" style={{ textAlign: 'center' }}>{label}</div>
                <div style={{ fontSize: 18, marginTop: 4 }}>{val ? '✓' : '-'}</div>
              </div>
            ))}
          </div>

          {run.command && (
            <>
              <div className="divider" />
              <div className="info-label" style={{ marginBottom: 8 }}>Command</div>
              <pre className="log-pane" style={{ minHeight: 'unset', maxHeight: 80 }}>{run.command}</pre>
            </>
          )}
        </div>
      )}

      {/* Tab: Log */}
      {tab === 'log' && (
        <div className="detail-tab-content">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
            <span className="text-sm text-muted">Execution output</span>
            {isActive && (
              <span className="badge running">
                <span className="badge-dot pulse" />
                Live
              </span>
            )}
          </div>
          <pre className="log-pane" ref={logPaneRef}>
            {displayLog ? displayLog : <span className="log-empty">No log output yet.</span>}
          </pre>
        </div>
      )}

      {/* Tab: Suppressed FPs */}
      {tab === 'suppressed' && (
        <div className="detail-tab-content findings-tab-content">
          {isActive ? (
            <div className="empty-state" style={{ padding: '40px 20px' }}>
              <div className="empty-title">Scan in progress…</div>
              <div className="empty-msg">Suppressed areas of interest will appear once the scan completes.</div>
            </div>
          ) : (
            <SuppressedPanel runUuid={run.run_uuid} onLoaded={setSuppressedCount} />
          )}
        </div>
      )}
    </div>
  )
}
