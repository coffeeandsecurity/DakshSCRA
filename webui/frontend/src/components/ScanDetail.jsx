import { useEffect, useMemo, useRef, useState } from 'react'
import { artifactUrl, getScanFindings, stopScan, streamScanLog } from '../api'
import FindingsReport from './FindingsReport'
import TaintAnalysis from './TaintAnalysis'
import InsightsPanel from './InsightsPanel'

function StatusBadge({ status }) {
  return (
    <span className={`badge ${status}`}>
      <span className={`badge-dot${status === 'running' ? ' pulse' : ''}`} />
      {status}
    </span>
  )
}

function niceDuration(sec) {
  if (sec == null) return '—'
  if (sec < 60) return `${Math.round(sec)}s`
  return `${Math.floor(sec / 60)}m ${Math.round(sec % 60)}s`
}

function niceDate(iso) {
  if (!iso) return '—'
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

function dlChipClass(name) {
  const low = (name || '').toLowerCase()
  if (low.endsWith('.pdf')) return 'artifact-chip pdf'
  if (low.endsWith('.json')) return 'artifact-chip json'
  return 'artifact-chip'
}

export default function ScanDetail({ run, log: logProp, artifactIndex, onStopped }) {
  const [tab, setTab] = useState('findings')
  const [liveLog, setLiveLog] = useState('')
  const [stopping, setStopping] = useState(false)
  const [findingsData, setFindingsData] = useState(null)
  const [findingsLoading, setFindingsLoading] = useState(false)
  const cancelSseRef = useRef(null)
  const logPaneRef = useRef(null)

  const isActive = run?.status === 'running' || run?.status === 'queued'

  // SSE live log — start when scan becomes active
  useEffect(() => {
    if (cancelSseRef.current) {
      cancelSseRef.current()
      cancelSseRef.current = null
    }
    setLiveLog('')

    if (!run?.run_uuid || !isActive) return

    const cancel = streamScanLog(
      run.run_uuid,
      (chunk) => {
        setLiveLog((prev) => prev + chunk)
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

  // Reset state when selected scan changes
  useEffect(() => {
    setTab('findings')
    setStopping(false)
    setFindingsData(null)
  }, [run?.run_uuid])

  // Load findings when scan is done and findings tab is active
  useEffect(() => {
    if (!run?.run_uuid || isActive || findingsData !== null) return
    if (tab !== 'findings') return
    setFindingsLoading(true)
    getScanFindings(run.run_uuid)
      .then((d) => setFindingsData(d))
      .catch(() => setFindingsData({}))
      .finally(() => setFindingsLoading(false))
  }, [run?.run_uuid, tab, isActive])

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
      // ignore — status updates on next poll
    } finally {
      setStopping(false)
    }
  }

  const displayLog = isActive ? liveLog : (logProp || liveLog)

  const allArtifacts = useMemo(() => {
    if (!artifactIndex) return []
    return [
      ...(artifactIndex.report_html ? [artifactIndex.report_html] : []),
      ...(artifactIndex.xref_html ? [artifactIndex.xref_html] : []),
      ...(artifactIndex.other_html || []),
      ...(artifactIndex.json_files || []),
      ...(artifactIndex.pdf_files || []),
      ...(artifactIndex.logs || []),
    ]
  }, [artifactIndex])

  const findingsCount = findingsData?.findings?.length ?? 0

  if (!run) {
    return (
      <div className="detail-panel">
        <div className="detail-header">
          <div className="detail-title">Findings Workspace</div>
        </div>
        <div className="detail-tab-content">
          <div className="empty-state">
            <svg className="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path strokeLinecap="round" strokeLinejoin="round" d="M15.042 21.672L13.684 16.6m0 0l-2.51 2.225.569-9.47 5.227 7.917-3.286-.672zm-7.518-.267A8.25 8.25 0 1120.25 10.5M8.288 14.212A5.25 5.25 0 1117.25 10.5" />
            </svg>
            <div className="empty-title">No scan selected</div>
            <div className="empty-msg">Select a scan from the list to view its findings, artifacts, and execution log.</div>
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
      </div>

      {/* Tabs */}
      <div className="detail-tabs">
        <button
          className={`detail-tab${tab === 'findings' ? ' active' : ''}`}
          onClick={() => setTab('findings')}
        >
          Findings{!isActive && findingsCount > 0 ? ` (${findingsCount})` : ''}
        </button>
        <button
          className={`detail-tab${tab === 'taint' ? ' active' : ''}`}
          onClick={() => setTab('taint')}
        >
          {(() => {
            const taintCount = findingsData?.analysis?.results?.flatMap((r) => r.findings || []).length ?? 0
            return `Taint Flows${!isActive && taintCount > 0 ? ` (${taintCount})` : ''}`
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
      </div>

      {/* Tab: Findings */}
      {tab === 'findings' && (
        <div className="detail-tab-content findings-tab-content">
          {isActive ? (
            <div className="empty-state" style={{ padding: '40px 20px' }}>
              <svg className="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path strokeLinecap="round" strokeLinejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99" />
              </svg>
              <div className="empty-title">Scan in progress…</div>
              <div className="empty-msg">Findings will appear here once the scan completes. Check the Log tab for live output.</div>
            </div>
          ) : findingsLoading ? (
            <div className="fr-loading">
              <div className="fr-spinner" />
              <span>Loading findings…</span>
            </div>
          ) : (
            <FindingsReport data={findingsData} status={run.status} />
          )}
        </div>
      )}

      {/* Tab: Taint Flows */}
      {tab === 'taint' && (
        <div className="detail-tab-content findings-tab-content">
          {isActive ? (
            <div className="empty-state" style={{ padding: '40px 20px' }}>
              <svg className="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path strokeLinecap="round" strokeLinejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99" />
              </svg>
              <div className="empty-title">Scan in progress…</div>
              <div className="empty-msg">Taint flows will appear here once the scan completes.</div>
            </div>
          ) : findingsLoading ? (
            <div className="fr-loading">
              <div className="fr-spinner" />
              <span>Loading taint analysis…</span>
            </div>
          ) : (
            <TaintAnalysis analysis={findingsData?.analysis} />
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
          {allArtifacts.length === 0 ? (
            <div className="empty-state" style={{ padding: '30px 20px' }}>
              <div className="empty-title">No downloads yet</div>
              <div className="empty-msg">
                {isActive
                  ? 'Artifacts will appear here when the scan completes.'
                  : 'No artifacts were generated for this scan.'}
              </div>
            </div>
          ) : (
            <div className="dl-list">
              {allArtifacts.map((a) => (
                <div key={a} className="dl-row">
                  <span className={dlChipClass(a)} style={{ cursor: 'default', pointerEvents: 'none' }}>
                    <ArtifactIcon name={a} />
                    {shortName(a)}
                  </span>
                  <span className="dl-path text-sm text-muted">{a}</span>
                  <div className="dl-actions">
                    <a
                      href={artifactUrl(a)}
                      target="_blank"
                      rel="noreferrer"
                      className="btn btn-secondary btn-sm"
                    >
                      Open ↗
                    </a>
                    <a
                      href={artifactUrl(a)}
                      download
                      className="btn btn-ghost btn-sm"
                    >
                      Download
                    </a>
                  </div>
                </div>
              ))}
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
              <div className="info-value">{run.project_name || '—'}</div>
            </div>
            <div className="info-item">
              <div className="info-label">Status</div>
              <div className="info-value">{run.status}</div>
            </div>
            <div className="info-item">
              <div className="info-label">Rules</div>
              <div className="info-value">{run.rules || '—'}</div>
            </div>
            <div className="info-item">
              <div className="info-label">Report Format</div>
              <div className="info-value">{run.report_format || '—'}</div>
            </div>
            <div className="info-item" style={{ gridColumn: '1 / -1' }}>
              <div className="info-label">Target Directory</div>
              <div className="info-value">{run.target_dir}</div>
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
                <div style={{ fontSize: 18, marginTop: 4 }}>{val ? '✓' : '—'}</div>
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
    </div>
  )
}
