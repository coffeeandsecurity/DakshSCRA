import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  createScan,
  deleteProject,
  getHealth,
  getLatestGithubRelease,
  getMetrics,
  getScan,
  getScanArtifacts,
  getScanLog,
  getVersion,
  listProjects,
  listScans,
} from './api'
import Dashboard from './components/Dashboard'
import DirectoryBrowserModal from './components/DirectoryBrowserModal'
import AboutPanel from './components/AboutPanel'
import HelpPanel from './components/HelpPanel'
import SettingsPanel from './components/SettingsPanel'
import ProjectsPanel from './components/ProjectsPanel'
import ScanDetail from './components/ScanDetail'
import ScanForm from './components/ScanForm'
import ScanTable from './components/ScanTable'
import Sidebar from './components/Sidebar'

const EMPTY_FORM = {
  project_name: '',
  rules: 'auto',
  target_dir: '',
  file_types: 'auto',
  report_format: 'html',
  verbosity: 1,
  recon: false,
  estimate: false,
  analysis: false,
  loc: false,
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

/* ─── Main App ───────────────────────────────────────────────── */
let toastCounter = 0

export default function App() {
  const [health, setHealth] = useState('checking')
  const [section, setSection] = useState('dashboard')

  const [metrics, setMetrics] = useState(null)
  const [projects, setProjects] = useState([])
  const [selectedProject, setSelectedProject] = useState('')

  const [runs, setRuns] = useState([])
  const [selected, setSelected] = useState(null)
  const [selectedDetail, setSelectedDetail] = useState(null)
  const [selectedArtifacts, setSelectedArtifacts] = useState(null)
  const [selectedLog, setSelectedLog] = useState('')

  const [form, setForm] = useState(EMPTY_FORM)
  const [creating, setCreating] = useState(false)
  const [browserOpen, setBrowserOpen] = useState(false)
  const [error, setError] = useState('')

  const [toasts, setToasts] = useState([])
  const [versionInfo, setVersionInfo] = useState(null)      // { version, release_date, github_repo }
  const [latestRelease, setLatestRelease] = useState(null)  // { tag, url, name } | null
  const [githubChecked, setGithubChecked] = useState(false) // true once GitHub check resolves (ok or failed)

  const addToast = useCallback((message, level = 'info', title = '') => {
    const id = ++toastCounter
    setToasts((prev) => [...prev, { id, message, level, title }])
  }, [])

  const dismissToast = useCallback((id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  const runningCount = useMemo(
    () => runs.filter((r) => r.status === 'running' || r.status === 'queued').length,
    [runs]
  )

  const hasActiveRun = useMemo(
    () => runs.some((r) => r.status === 'running' || r.status === 'queued') || selectedDetail?.status === 'running',
    [runs, selectedDetail?.status]
  )

  /* ── Data Fetchers ── */
  async function refreshOverview() {
    try {
      const [m, p] = await Promise.all([getMetrics(), listProjects()])
      setMetrics(m)
      setProjects(p)
      if (!selectedProject && p.length > 0) setSelectedProject(p[0].project_key)
    } catch {
      // fail silently for background refresh
    }
  }

  async function refreshRuns() {
    try {
      const data = await listScans(80, selectedProject || undefined)
      setRuns(data)
    } catch {
      // fail silently
    }
  }

  async function refreshSelected(runUuid) {
    if (!runUuid) return
    try {
      const [detail, artifacts, logRes] = await Promise.all([
        getScan(runUuid),
        getScanArtifacts(runUuid),
        getScanLog(runUuid),
      ])
      setSelectedDetail(detail)
      setSelectedArtifacts(artifacts)
      setSelectedLog(logRes.log_tail || '')
    } catch {
      // fail silently
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
    try {
      const created = await createScan(form)
      await Promise.all([refreshOverview(), refreshRuns()])
      setSection('scans')
      setSelected(created)
      setSelectedDetail(created)
      setSelectedArtifacts(null)
      setSelectedLog('')
      addToast(`Scan queued: ${created.project_name || created.run_uuid}`, 'success', 'Scan Started')
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
      await refreshOverview()
      addToast('Project deleted', 'success')
    } catch (e) {
      addToast(e.message === 'project_has_active_scans' ? 'Cannot delete — scan is running' : e.message, 'error', 'Delete Failed')
    }
  }

  async function handleOpenProject(project) {
    setSelectedProject(project.project_key)
    setSection('scans')
    setError('')
    setSelected(null)
    setSelectedDetail(null)
    setSelectedArtifacts(null)
    setSelectedLog('')

    if (!project.latest_run_uuid) {
      return
    }

    try {
      const [detail, artifacts, logRes] = await Promise.all([
        getScan(project.latest_run_uuid),
        getScanArtifacts(project.latest_run_uuid),
        getScanLog(project.latest_run_uuid),
      ])
      setSelected(detail)
      setSelectedDetail(detail)
      setSelectedArtifacts(artifacts)
      setSelectedLog(logRes.log_tail || '')
    } catch (e) {
      setSelected(null)
      setSelectedDetail(null)
      setSelectedArtifacts(null)
      setSelectedLog('')
      addToast(`Failed to open latest scan for ${project.project_name}: ${e.message}`, 'error', 'Open Project Failed')
    }
  }

  /* ── Navigation handler (from child components) ── */
  function handleNavigate(dest, run = null) {
    setSection(dest)
    if (run) setSelected(run)
  }

  /* ── Initial load ── */
  useEffect(() => {
    getHealth().then(() => setHealth('online')).catch(() => setHealth('offline'))
    refreshOverview()

    // Fetch current version then check GitHub for latest release
    getVersion().then((info) => {
      setVersionInfo(info)
      getLatestGithubRelease(info.github_repo)
        .then((rel) => { setLatestRelease(rel); setGithubChecked(true) })
        .catch(() => setGithubChecked(true))   // failed = still "checked" (offline)
    }).catch(() => setGithubChecked(true))
  }, [])

  useEffect(() => {
    refreshRuns()
  }, [selectedProject])

  useEffect(() => {
    if (selected?.run_uuid) {
      refreshSelected(selected.run_uuid)
    }
  }, [selected?.run_uuid])

  // Re-fetch detail when user navigates back to the scans section
  useEffect(() => {
    if (section === 'scans' && selected?.run_uuid) {
      refreshSelected(selected.run_uuid)
    }
  }, [section])

  /* ── Auto-refresh polling ── */
  useEffect(() => {
    const intervalMs = hasActiveRun ? 3000 : 12000
    const timer = setInterval(() => {
      refreshRuns()
      refreshOverview()
      if (selected?.run_uuid) refreshSelected(selected.run_uuid)
    }, intervalMs)
    return () => clearInterval(timer)
  }, [hasActiveRun, selected?.run_uuid, selected?.status, selectedProject])

  /* ── Page title mapping ── */
  const pageTitles = {
    dashboard: 'Dashboard',
    projects: 'Projects',
    scans: 'Scans',
    settings: 'Settings',
    help: 'Help & Documentation',
    about: 'About DakshSCRA',
  }

  const showingScanWorkspace = section === 'scans' && !!selectedDetail?.run_uuid

  function handleNewScan() {
    setSection('scans')
    setSelected(null)
    setSelectedDetail(null)
    setSelectedArtifacts(null)
    setSelectedLog('')
    setError('')
  }

  function handleBackToScans() {
    setSelected(null)
    setSelectedDetail(null)
    setSelectedArtifacts(null)
    setSelectedLog('')
  }

  return (
    <div className="app-shell">
      {/* Sidebar */}
      <Sidebar
        active={section}
        onChange={(s) => { setSection(s); setError('') }}
        health={health}
        runningCount={runningCount}
        version={versionInfo?.version}
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
                <button className="btn btn-primary btn-sm" onClick={handleNewScan}>
                  + New Scan
                </button>
                <button className="btn btn-ghost btn-sm" onClick={() => setSection('scans')}>
                  View Scans
                </button>
              </>
            )}
            {section === 'scans' && selectedProject && (
              <>
                {showingScanWorkspace && (
                  <button className="btn btn-ghost btn-sm" onClick={handleBackToScans}>
                    View Scans
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
              versionInfo={versionInfo}
              latestRelease={latestRelease}
              githubChecked={githubChecked}
            />
          )}

          {/* ── Projects ── */}
          {section === 'projects' && (
            <ProjectsPanel
              projects={projects}
              selectedProject={selectedProject}
              onSelectProject={(key) => {
                setSelectedProject(key)
                setSection('scans')
              }}
              onNewScan={handleNewScan}
              onDeleteProject={handleDeleteProject}
            />
          )}

          {/* ── Scans ── */}
          {section === 'scans' && (
            <div className={`scans-layout ${showingScanWorkspace ? 'workspace' : 'setup'}`}>
              {!showingScanWorkspace ? (
                <>
                  <div className="scans-side">
                    <ScanForm
                      values={form}
                      setValues={setForm}
                      creating={creating}
                      onSubmit={submitScan}
                      onBrowse={() => setBrowserOpen(true)}
                    />
                  </div>
                  <div className="scans-main">
                    <div className="scans-panel-head">
                      <div>
                        <div className="scans-panel-title">Recent Scans</div>
                        <div className="scans-panel-copy">Browse current and saved runs, then open one into the workspace.</div>
                      </div>
                    </div>
                    <ScanTable
                      runs={runs}
                      selected={selected}
                      onSelect={(r) => {
                        setSelected(r)
                      }}
                    />
                  </div>
                </>
              ) : (
                <>
                  <div className="scans-main scans-main-detail scans-main-detail-full">
                    <ScanDetail
                      run={selectedDetail}
                      log={selectedLog}
                      artifactIndex={selectedArtifacts}
                      onStopped={refreshSelected}
                    />
                  </div>
                </>
              )}
            </div>
          )}
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
    </div>
  )
}
