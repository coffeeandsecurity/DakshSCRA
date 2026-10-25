import { setDisplayPreferences } from './lib/datetime'
import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  createScan,
  deleteScanData,
  deleteScanRecord,
  deleteProject,
  getHealth,
  getLatestGithubRelease,
  getMe,
  getMetrics,
  getScan,
  getScanArtifacts,
  getScanLog,
  getSettings,
  getVersion,
  listProjects,
  listScans,
  logout as apiLogout,
  setUnauthorizedHandler,
} from './api'
import Dashboard from './components/Dashboard'
import DirectoryBrowserModal from './components/DirectoryBrowserModal'
import AboutPanel from './components/AboutPanel'
import HelpPanel from './components/HelpPanel'
import ChangePasswordGate from './components/ChangePasswordGate'
import CompletedScans from './components/CompletedScans'
import LoginPage from './components/LoginPage'
import SettingsPanel from './components/SettingsPanel'
import ProjectsPanel from './components/ProjectsPanel'
import ScanDetail from './components/ScanDetail'
import QueuedScanDetail from './components/QueuedScanDetail'
import ScanForm from './components/ScanForm'
import ScanTable from './components/ScanTable'
import Sidebar from './components/Sidebar'

const SystemPanel = lazy(() => import('./components/SystemPanel'))

const ACTIVE_SCAN_STATUSES = new Set(['running', 'queued', 'stopping'])

const EMPTY_FORM = {
  rdl_engine: 'both',
  rule_mode: 'both',
  custom_rdl: [],
  exclude_checks: [],
  exclude_paths: [],
  exclude_types: [],
  exclude_keywords: [],
  recon_strict: false,
  baseline_mode: 'default',
  baseline_file: '',
  review_config: '',
  state_mode: 'default',
  project_name: '',
  rules: 'auto',
  target_dir: '',
  file_types: 'auto',
  report_format: 'web',
  report_audience: 'both',
  verbosity: 1,
  recon: true,
  estimate: false,
  estimate_assumptions: {},
  analysis: false,
  loc: true,
}

/* ─── Toast ──────────────────────────────────────────────────── */
function Toast({ toast, onDismiss }) {
  useEffect(() => {
    const t = setTimeout(() => onDismiss(toast.id), toast.duration || 4000)
    return () => clearTimeout(t)
  }, [toast.id])

  const icons = {
    success: (
      <svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor" className="toast-icon success">
        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
      </svg>
    ),
    error: (
      <svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor" className="toast-icon error">
        <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
      </svg>
    ),
    info: (
      <svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor" className="toast-icon info">
        <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
      </svg>
    ),
    warning: (
      <svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor" className="toast-icon warning">
        <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
      </svg>
    ),
  }

  return (
    <div className={`toast ${toast.level || 'info'}`}>
      {icons[toast.level] || icons.info}
      <div>
        {toast.title && <div className="toast-title">{toast.title}</div>}
        <div className="toast-msg">{toast.message}</div>
      </div>
    </div>
  )
}

function AccountMenu({ user, version, onChangePassword, onLogout }) {
  const [open, setOpen] = useState(false)
  const menuRef = useRef(null)
  const initial = String(user?.username || '?').trim().charAt(0).toUpperCase()

  useEffect(() => {
    if (!open) return
    const closeMenu = (event) => {
      if (!menuRef.current?.contains(event.target)) setOpen(false)
    }
    const closeOnEscape = (event) => {
      if (event.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', closeMenu)
    document.addEventListener('keydown', closeOnEscape)
    return () => {
      document.removeEventListener('mousedown', closeMenu)
      document.removeEventListener('keydown', closeOnEscape)
    }
  }, [open])

  return (
    <div className="account-menu" ref={menuRef}>
      <button
        type="button"
        className="account-trigger"
        onClick={() => setOpen((current) => !current)}
        aria-haspopup="menu"
        aria-expanded={open}
      >
        <span className="account-avatar">{initial}</span>
        <span className="account-trigger-name">{user?.username}</span>
        <span className="account-caret" aria-hidden="true">⌄</span>
      </button>
      {open ? (
        <div className="account-dropdown" role="menu">
          <div className="account-dropdown-head">
            <span>Signed in as</span>
            <strong>{user?.username}</strong>
          </div>
          <button type="button" role="menuitem" onClick={() => { setOpen(false); onChangePassword() }}>
            <span className="account-menu-icon">⌁</span>
            Change password
          </button>
          <button type="button" role="menuitem" className="account-logout" onClick={() => { setOpen(false); onLogout() }}>
            <span className="account-menu-icon">↪</span>
            Log out
          </button>
          <div className="account-dropdown-version">Daksh SCRA{version ? ` v${String(version).trim().replace(/^v+/i, '')}` : ''}</div>
        </div>
      ) : null}
    </div>
  )
}

/* ─── Main App ───────────────────────────────────────────────── */
let toastCounter = 0

export default function App() {
  const [, refreshDisplay] = useState(0)
  useEffect(() => {
    const refresh = () => refreshDisplay(value => value + 1)
    window.addEventListener('display-preferences-changed', refresh)
    return () => window.removeEventListener('display-preferences-changed', refresh)
  }, [])
  const [user, setUser] = useState(null)
  const [authChecked, setAuthChecked] = useState(false)

  const [health, setHealth] = useState('checking')
  const [section, setSection] = useState('dashboard')

  const [metrics, setMetrics] = useState(null)
  const [projects, setProjects] = useState([])
  const [selectedProject, setSelectedProject] = useState('')
  const [viewedProject, setViewedProject] = useState('')

  const [runs, setRuns] = useState([])
  const [queuedRuns, setQueuedRuns] = useState([])
  const [selected, setSelected] = useState(null)
  const [selectedDetail, setSelectedDetail] = useState(null)
  const [selectedArtifacts, setSelectedArtifacts] = useState(null)
  const [selectedLog, setSelectedLog] = useState('')
  const [submittedQueuedRun, setSubmittedQueuedRun] = useState(null)

  const [form, setForm] = useState(EMPTY_FORM)
  const [creating, setCreating] = useState(false)
  const [browserOpen, setBrowserOpen] = useState(false)
  const [error, setError] = useState('')

  const [toasts, setToasts] = useState([])
  const [versionInfo, setVersionInfo] = useState(null)      // { version, release_date, github_repo }
  const [latestRelease, setLatestRelease] = useState(null)  // { tag, url, name } | null
  const [githubChecked, setGithubChecked] = useState(false) // true once GitHub check resolves (ok or failed)
  const [passwordDialogOpen, setPasswordDialogOpen] = useState(false)

  const addToast = useCallback((message, level = 'info', title = '') => {
    const id = ++toastCounter
    setToasts((prev) => [...prev, { id, message, level, title }])
  }, [])

  const dismissToast = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  const runningCount = useMemo(
    () => runs.filter((r) => ['running', 'stopping'].includes(r.status)).length,
    [runs]
  )

  const hasActiveRun = useMemo(
    () => !!submittedQueuedRun || runs.some((r) => ACTIVE_SCAN_STATUSES.has(r.status)) || ACTIVE_SCAN_STATUSES.has(selectedDetail?.status),
    [runs, selectedDetail?.status, submittedQueuedRun]
  )

  /* ── Data Fetchers ── */
  // These three poll on an interval (see "Auto-refresh polling" below), so a
  // failure toasts once per outage (edge-triggered via these refs) rather
  // than re-toasting on every failed tick - a backend outage would otherwise
  // spam a new toast every few seconds.
  const overviewFailedRef = useRef(false)
  const runsFailedRef = useRef(false)
  const selectedFailedRef = useRef(false)
  const sessionGeneration = useRef(0)
  const selectedRequest = useRef(0)
  const navigationGeneration = useRef(0)

  function clearSelectedScan() {
    navigationGeneration.current++
    setSubmittedQueuedRun(null)
    selectedRequest.current++
    setSelected(null)
    setSelectedDetail(null)
    setSelectedArtifacts(null)
    setSelectedLog('')
  }

  function endSession() {
    sessionGeneration.current++
    clearSelectedScan()
    setUser(null)
    setMetrics(null)
    setProjects([])
    setRuns([])
    setQueuedRuns([])
    setSelectedProject('')
    setViewedProject('')
    setSection('dashboard')
    setError('')
    setToasts([])
    setPasswordDialogOpen(false)
    setForm(EMPTY_FORM)
    overviewFailedRef.current = runsFailedRef.current = selectedFailedRef.current = false
  }

  async function refreshOverview() {
    const generation = sessionGeneration.current
    try {
      const [m, p] = await Promise.all([getMetrics(), listProjects()])
      if (generation !== sessionGeneration.current) return
      setMetrics(m)
      setProjects(p)
      if (!selectedProject && p.length > 0) setSelectedProject(p[0].project_key)
      overviewFailedRef.current = false
    } catch {
      if (generation !== sessionGeneration.current) return
      if (!overviewFailedRef.current) {
        overviewFailedRef.current = true
        addToast('Unable to refresh dashboard data - check your connection.', 'error', 'Refresh Failed')
      }
    }
  }

  async function refreshRuns() {
    const generation = sessionGeneration.current
    try {
      const [data, running, stopping, waiting] = await Promise.all([
        listScans(200),
        listScans(200, '', { status: 'running' }),
        listScans(200, '', { status: 'stopping' }),
        (async () => {
          const rows = []
          let page
          do {
            page = await listScans(200, '', { status: 'queued', offset: rows.length })
            rows.push(...page)
          } while (page.length === 200)
          // The API returns newest first, including its ID tie-breaker.
          // Reversing preserves the dispatcher's created_at/ID FIFO order.
          return [...new Map(rows.map(row => [row.run_uuid, row])).values()].reverse()
        })(),
      ])
      if (generation !== sessionGeneration.current) return
      setQueuedRuns(waiting.filter(run => !run.data_removed))
      setRuns([...new Map([...data, ...waiting, ...running, ...stopping].map(run => [run.run_uuid, run])).values()])
      runsFailedRef.current = false
    } catch {
      if (generation !== sessionGeneration.current) return
      if (!runsFailedRef.current) {
        runsFailedRef.current = true
        addToast('Unable to refresh scan list - check your connection.', 'error', 'Refresh Failed')
      }
    }
  }

  async function refreshSelected(runUuid, includeEvidence = true) {
    if (!runUuid) return
    const requestId = ++selectedRequest.current
    const generation = sessionGeneration.current
    const [detailResult, artifactsResult, logResult] = await Promise.allSettled([
      getScan(runUuid), includeEvidence ? getScanArtifacts(runUuid) : Promise.resolve(null), includeEvidence ? getScanLog(runUuid) : Promise.resolve(null),
    ])
    if (generation !== sessionGeneration.current || requestId !== selectedRequest.current) return
    if (detailResult.status === 'rejected') {
      if (detailResult.reason?.message === 'run_not_found') {
        clearSelectedScan()
        setSection('completed')
        refreshRuns()
        refreshOverview()
        addToast('This scan is no longer in the current scan history. The scan list has been refreshed.', 'warning', 'Scan unavailable')
      } else if (!selectedFailedRef.current) {
        selectedFailedRef.current = true
        addToast('Unable to refresh scan details - check your connection.', 'error', 'Refresh Failed')
      }
      return
    }
    setSelectedDetail(detailResult.value)
    selectedFailedRef.current = false
    if (includeEvidence) {
      setSelectedArtifacts(artifactsResult.status === 'fulfilled' ? artifactsResult.value : null)
      setSelectedLog(logResult.status === 'fulfilled' ? logResult.value.log_tail || '' : '')
    }
  }

  async function submitScan() {
    if (!form.target_dir.trim()) {
      setError('Target directory is required.')
      addToast('Target directory is required.', 'error', 'Validation Error')
      return
    }
    setCreating(true)
    setError('')
    const generation = sessionGeneration.current
    const navigation = navigationGeneration.current
    try {
      const created = await createScan({ ...form, custom_rdl: (form.custom_rdl || []).map((p) => p.trim()).filter(Boolean) })
      // Creation records a queued job before the dispatcher can claim it.
      // Resolve its current state after refreshing instead of routing from
      // that initial response, which may already be out of date.
      const [, , current] = await Promise.all([
        refreshOverview(), refreshRuns(), getScan(created.run_uuid).catch(() => created),
      ])
      if (generation !== sessionGeneration.current || navigation !== navigationGeneration.current) return
      const queued = current.status === 'queued'
      const active = ACTIVE_SCAN_STATUSES.has(current.status)
      setSection(queued ? 'queued' : active ? 'scans' : 'completed')
      setSubmittedQueuedRun(queued ? current.run_uuid : null)
      setSelected(queued ? null : current)
      setSelectedDetail(queued ? null : current)
      setSelectedArtifacts(null)
      setSelectedLog('')
      addToast(queued
        ? `${current.project_name || current.run_uuid} is queued and will start when its turn comes. Scans are listed next to run first.`
        : `Scan ${active ? 'started' : 'finished'}: ${current.project_name || current.run_uuid}`,
      current.status === 'failed' ? 'error' : 'success', queued ? 'Scan Queued' : active ? 'Scan Started' : 'Scan Finished')
    } catch (e) {
      const msg = `Failed to queue scan: ${e.message}`
      setError(msg)
      addToast(e.message, 'error', 'Scan Failed')
    } finally {
      setCreating(false)
    }
  }

  async function handleDeleteProject(projectKey) {
    try {
      await deleteProject(projectKey)
      if (selectedProject === projectKey) setSelectedProject('')
      await Promise.all([refreshOverview(), refreshRuns()])
      addToast('Project and scan data deleted. Scan history records remain in Recent Scans.', 'success', 'Data Deleted')
    } catch (e) {
      addToast(e.message === 'project_has_active_scans' ? 'Cannot delete - scan is running' : e.message, 'error', 'Delete Failed')
    }
  }

  async function handleDeleteScanData(run) {
    try {
      await deleteScanData(run.run_uuid)
      if (selected?.run_uuid === run.run_uuid) handleBackToScans()
      await Promise.all([refreshOverview(), refreshRuns()])
      addToast(run.status === 'queued' ? 'The queued scan was deleted and will not run.' : 'Reports, findings, logs, and runtime data were deleted. The Recent Scans record was retained.', 'success', run.status === 'queued' ? 'Queued Scan Deleted' : 'Scan Data Deleted')
    } catch (e) {
      addToast(e.message === 'scan_is_active' ? 'Stop the scan before deleting its data.' : e.message, 'error', 'Delete Failed')
      throw e
    }
  }

  async function handleDeleteScanRecord(run) {
    try {
      await deleteScanRecord(run.run_uuid)
      if (selected?.run_uuid === run.run_uuid) handleBackToScans()
      await Promise.all([refreshOverview(), refreshRuns()])
      addToast('The scan history record was permanently removed.', 'success', 'Record Cleared')
    } catch (e) {
      addToast(e.message, 'error', 'Clear Failed')
      throw e
    }
  }

  function handleOpenProject(project) {
    const key = typeof project === 'string' ? project : project.project_key
    clearSelectedScan()
    setSelectedProject(key)
    setViewedProject(key)
    setSection('projects')
    setError('')
  }

  function handleOpenProjectScan(run) {
    clearSelectedScan()
    setSelectedProject(run.project_key)
    setViewedProject(run.project_key)
    setSection(run.status === 'queued' ? 'queued' : ACTIVE_SCAN_STATUSES.has(run.status) ? 'scans' : 'completed')
    setSelected(run)
    setError('')
  }

  /* ── Navigation handler (from child components) ── */
  function handleNavigate(dest, run = null) {
    navigationGeneration.current++
    setSubmittedQueuedRun(null)
    if (dest === 'scans' && run) handleOpenProjectScan(run)
    else { setSection(dest); if (run) setSelected(run) }
  }

  /* ── Auth check (runs once, before anything else) ── */
  useEffect(() => {
    setUnauthorizedHandler(endSession)
    getMe()
      .then((me) => setUser(me))
      .catch(endSession)
      .finally(() => setAuthChecked(true))
    return () => setUnauthorizedHandler(null)
  }, [])

  async function handleLogout() {
    try {
      await apiLogout()
    } catch {
      // clear local state regardless of whether the network call succeeded
    }
    endSession()
  }

  /* ── Initial load (only once authenticated) ── */
  useEffect(() => {
    if (!user || user.must_change_password) return
    getHealth().then(() => setHealth('online')).catch(() => setHealth('offline'))
    refreshOverview()

    // EMPTY_FORM.analysis defaults to false only as a synchronous placeholder;
    // align the scan form's default with the backend's actual configured
    // default once it's known. Only applies while the form is still
    // untouched (reference-equal to EMPTY_FORM) so it never clobbers an
    // in-progress edit.
    getSettings().then((data) => {
      setDisplayPreferences(data.display)
      const runByDefault = data?.analysis?.run_by_default
      if (typeof runByDefault !== 'boolean') return
      setForm((prev) => (prev === EMPTY_FORM ? { ...prev, analysis: runByDefault } : prev))
    }).catch(() => {})

    // Fetch current version then check GitHub for latest release
    getVersion().then((info) => {
      setVersionInfo(info)
      getLatestGithubRelease(info.github_repo)
        .then((rel) => { setLatestRelease(rel); setGithubChecked(true) })
        .catch(() => setGithubChecked(true))   // failed = still "checked" (offline)
    }).catch(() => setGithubChecked(true))
  }, [user])

  useEffect(() => {
    if (!user || user.must_change_password) return
    refreshRuns()
  }, [user, selectedProject])

  useEffect(() => {
    if (!user || user.must_change_password || !selected?.run_uuid) return
    if (section === 'scans' || section === 'queued' || section === 'completed') refreshSelected(selected.run_uuid)
  }, [user, section, selected?.run_uuid])

  const previousSelectedStatusRef = useRef(null)
  useEffect(() => {
    if (!submittedQueuedRun || section !== 'queued') return
    const current = runs.find(run => run.run_uuid === submittedQueuedRun)
    if (!current || current.status === 'queued') return
    setSubmittedQueuedRun(null)
    setSection(ACTIVE_SCAN_STATUSES.has(current.status) ? 'scans' : 'completed')
    setSelected(current)
    setSelectedDetail(null)
    setSelectedArtifacts(null)
    setSelectedLog('')
  }, [runs, section, submittedQueuedRun])

  useEffect(() => {
    const currentStatus = selectedDetail?.status || null
    const previousStatus = previousSelectedStatusRef.current
    previousSelectedStatusRef.current = currentStatus
    if (currentStatus && currentStatus !== 'queued' && section === 'queued' && selectedDetail?.run_uuid) {
      setSection(ACTIVE_SCAN_STATUSES.has(currentStatus) ? 'scans' : 'completed')
    }
    if (ACTIVE_SCAN_STATUSES.has(previousStatus) && currentStatus && !ACTIVE_SCAN_STATUSES.has(currentStatus)) {
      setSection('completed')
      refreshRuns()
      refreshOverview()
      addToast('Scan completed. Full results are now available under Completed.', 'success', 'Scan Complete')
    }
  }, [selectedDetail?.status])

  /* ── Auto-refresh polling ── */
  useEffect(() => {
    if (!user || user.must_change_password) return
    const intervalMs = hasActiveRun ? 3000 : 12000
    const timer = setInterval(() => {
      refreshRuns()
      refreshOverview()
      if (selected?.run_uuid) {
        const visible = section === 'scans' || section === 'queued' || section === 'completed'
        if (visible || ACTIVE_SCAN_STATUSES.has(selectedDetail?.status || selected.status)) refreshSelected(selected.run_uuid, visible)
      }
    }, intervalMs)
    return () => clearInterval(timer)
  }, [user, hasActiveRun, selected?.run_uuid, selected?.status, selectedDetail?.status, selectedProject, section])

  /* ── Page title mapping ── */
  const pageTitles = {
    dashboard: 'Dashboard',
    projects: 'Projects',
    newScan: 'New scan',
    scans: 'Active scans',
    queued: 'Queued scans',
    completed: 'Completed scans',
    system: 'System',
    settings: 'Settings',
    help: 'Help & Documentation',
    about: 'About DakshSCRA',
  }

  const showingScanWorkspace = ['scans', 'queued', 'completed'].includes(section) && !!selectedDetail?.run_uuid
  const activeRuns = useMemo(() => runs.filter((run) => ['running', 'stopping'].includes(run.status)), [runs])
  const completedRuns = useMemo(() => runs.filter((run) => !ACTIVE_SCAN_STATUSES.has(run.status)), [runs])

  function handleNewScan() {
    setSection('newScan')
    clearSelectedScan()
    setError('')
  }

  function handleBackToScans() {
    clearSelectedScan()
  }

  function handleOpenCompleted(run) {
    handleOpenProjectScan(run)
  }

  if (!authChecked) {
    return null
  }

  if (!user) {
    return <LoginPage onLoggedIn={setUser} />
  }

  if (user.must_change_password) {
    return <ChangePasswordGate user={user} onChanged={setUser} onLogout={handleLogout} />
  }

  return (
    <div className="app-shell">
      {/* Sidebar */}
      <Sidebar
        active={section}
        onChange={(s) => {
          navigationGeneration.current++
          setSubmittedQueuedRun(null)
          if (s === 'scans' || s === 'queued' || s === 'completed' || s === 'newScan' || s === 'projects') handleBackToScans()
          if (s === 'projects') setViewedProject('')
          setSection(s)
          setError('')
        }}
        health={health}
        runningCount={runningCount}
        queuedCount={queuedRuns.length}
        completedCount={completedRuns.length}
        user={user}
        version={versionInfo?.version}
        onLogout={handleLogout}
      />

      {/* Main */}
      <div className="main-wrapper">
        {/* Topbar */}
        <header className="topbar">
          <div>
            <div className="topbar-title">{pageTitles[section] || 'DakshSCRA'}</div>
          </div>
          <div className="topbar-right">
            {section === 'projects' && (
              <>
                <button className="btn btn-primary scan-create-button" onClick={handleNewScan}>
                  + New Scan
                </button>
                <button className="btn btn-ghost btn-sm" onClick={() => setSection('scans')}>
                  View Scans
                </button>
              </>
            )}
            {(section === 'scans' || section === 'completed') && selectedProject && (
              <>
                {showingScanWorkspace && viewedProject && <button className="btn btn-ghost btn-sm" onClick={() => handleOpenProject(viewedProject)}>Project scans</button>}
                {showingScanWorkspace && (
                  <button className="btn btn-ghost btn-sm" onClick={handleBackToScans}>
                    {section === 'completed' ? 'Completed scans' : 'Active scans'}
                  </button>
                )}
                {showingScanWorkspace && (
                  <button className="btn btn-ghost btn-sm" onClick={handleNewScan}>
                    + New Scan
                  </button>
                )}
                <span className="text-sm text-muted">
                  Project: <strong>{projects.find((p) => p.project_key === selectedProject)?.project_name || selectedProject}</strong>
                </span>
              </>
            )}
            <AccountMenu
              user={user}
              version={versionInfo?.version}
              onChangePassword={() => setPasswordDialogOpen(true)}
              onLogout={handleLogout}
            />
          </div>
        </header>

        {/* Content */}
        <div className="content">
          {error && (
            <div className="error-banner">
              <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
              </svg>
              {error}
              <button className="btn-icon btn-sm" onClick={() => setError('')} style={{ marginLeft: 'auto' }}>✕</button>
            </div>
          )}

          {/* ── Dashboard ── */}
          {section === 'dashboard' && (
            <Dashboard
              metrics={metrics}
              projects={projects}
              runs={runs}
              onNavigate={handleNavigate}
              onOpenProject={handleOpenProject}
              onDeleteProject={handleDeleteProject}
              onDeleteScanData={handleDeleteScanData}
              onDeleteScanRecord={handleDeleteScanRecord}
              versionInfo={versionInfo}
              latestRelease={latestRelease}
              githubChecked={githubChecked}
            />
          )}

          {/* ── Projects ── */}
          {section === 'projects' && (
            <ProjectsPanel
              projects={projects}
              projectKey={viewedProject}
              onSelectProject={handleOpenProject}
              onBack={() => setViewedProject('')}
              onOpenScan={handleOpenProjectScan}
              onDeleteData={handleDeleteScanData}
              onDeleteRecord={handleDeleteScanRecord}
              onNewScan={handleNewScan}
              onDeleteProject={handleDeleteProject}
            />
          )}

          {/* ── Scans ── */}
          {section === 'newScan' && (
            <div className="new-scan-page">
              <ScanForm
                values={form}
                setValues={setForm}
                creating={creating}
                onSubmit={submitScan}
                onBrowse={() => setBrowserOpen(true)}
              />
            </div>
          )}
          {(section === 'scans' || section === 'queued') && (
            <div className="scans-layout workspace">
              {!showingScanWorkspace ? (
                <>
                  <div className="scans-main">
                    <div className="scans-panel-head">
                      <div>
                        <div className="scans-panel-title">{section === 'queued' ? 'Queued scans' : 'Active scans'}</div>
                        <div className="scans-panel-copy">{section === 'queued' ? 'Next to run is at the top; the most recently queued scan is at the bottom. Scans move to Active Scans automatically when their turn comes.' : 'Running and stopping scans appear here. Scans waiting to start are listed under Queued Scans.'}</div>
                      </div>
                      <button className="btn btn-primary scan-create-button" onClick={handleNewScan}>+ New Scan</button>
                    </div>
                    <ScanTable
                      key={section}
                      queuedOnly={section === 'queued'}
                      runs={section === 'queued' ? queuedRuns : activeRuns}
                      selected={selected}
                      onSelect={(r) => {
                        navigationGeneration.current++
                        setSubmittedQueuedRun(null)
                        setSection(r.status === 'queued' ? 'queued' : 'scans')
                        setSelectedDetail(null)
                        setSelectedArtifacts(null)
                        setSelectedLog('')
                        setSelected(r)
                      }}
                      onDeleteData={handleDeleteScanData}
                      onDeleteRecord={handleDeleteScanRecord}
                    />
                  </div>
                </>
              ) : (
                <>
                  <div className="scans-main scans-main-detail scans-main-detail-full">
                    {selectedDetail.status === 'queued' ? <QueuedScanDetail
                      key={selectedDetail.run_uuid}
                      run={selectedDetail}
                      position={queuedRuns.findIndex(run => run.run_uuid === selectedDetail.run_uuid) + 1}
                      defaults={EMPTY_FORM}
                      onBack={handleBackToScans}
                      onChanged={(includeDetail = true) => { refreshRuns(); if (includeDetail) refreshSelected(selectedDetail.run_uuid, false) }}
                      onDeleteData={handleDeleteScanData}
                      onDeleteRecord={handleDeleteScanRecord}
                    /> : <ScanDetail
                      key={selectedDetail.run_uuid}
                      run={selectedDetail}
                      log={selectedLog}
                      artifactIndex={selectedArtifacts}
                      onStopped={refreshSelected}
                    />}
                  </div>
                </>
              )}
            </div>
          )}
          {/* ── Completed scans ── */}
          {section === 'completed' && (
            <div className={`scans-layout ${showingScanWorkspace ? 'workspace' : ''}`}>
              <div className="scans-main scans-main-detail scans-main-detail-full">
                {showingScanWorkspace ? (
                  <ScanDetail
                    key={selectedDetail.run_uuid}
                      run={selectedDetail}
                    log={selectedLog}
                    artifactIndex={selectedArtifacts}
                    onStopped={refreshSelected}
                  />
                ) : (
                  <CompletedScans
                    runs={completedRuns}
                    selected={selected}
                    onView={handleOpenCompleted}
                    onDeleteData={handleDeleteScanData}
                    onDeleteRecord={handleDeleteScanRecord}
                  />
                )}
              </div>
            </div>
          )}
          {section === 'system' && <Suspense fallback={<p role="status">Loading System…</p>}><SystemPanel health={health} version={versionInfo?.version} onStorageChange={() => { refreshOverview(); refreshRuns(); if (selected?.run_uuid) refreshSelected(selected.run_uuid) }} /></Suspense>}
          {/* ── Settings ── */}
          {section === 'settings' && (
            <SettingsPanel onToast={addToast} />
          )}

          {/* ── Help ── */}
          {section === 'help' && <HelpPanel />}

          {/* ── About ── */}
          {section === 'about' && <AboutPanel />}
        </div>
      </div>

      {/* Directory browser modal */}
      <DirectoryBrowserModal
        open={browserOpen}
        initialPath={form.target_dir}
        onClose={() => setBrowserOpen(false)}
        onSelect={(path) => {
          setForm((p) => ({ ...p, target_dir: path }))
          setBrowserOpen(false)
        }}
      />

      {/* Toasts */}
      <div className="toast-container">
        {toasts.map((t) => (
          <Toast key={t.id} toast={t} onDismiss={dismissToast} />
        ))}
      </div>

      {passwordDialogOpen ? (
        <ChangePasswordGate
          user={user}
          voluntary
          onChanged={(updated) => { setUser(updated); setPasswordDialogOpen(false) }}
          onCancel={() => setPasswordDialogOpen(false)}
        />
      ) : null}
    </div>
  )
}
