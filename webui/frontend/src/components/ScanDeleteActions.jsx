import { useState } from 'react'

export default function ScanDeleteActions({ run, onDeleteData, onDeleteRecord, compact = false }) {
  const [confirming, setConfirming] = useState(false)
  const [busy, setBusy] = useState(false)
  const isActive = ['running', 'queued', 'stopping'].includes(run.status)
  const dataRemoved = Boolean(run.data_removed)

  async function confirmDelete(event) {
    event.stopPropagation()
    setBusy(true)
    try {
      if (dataRemoved) await onDeleteRecord(run)
      else await onDeleteData(run)
      setConfirming(false)
    } catch {
      // The parent displays the API error as a toast; keep confirmation open
      // so the user can retry or cancel without an unhandled rejection.
    } finally {
      setBusy(false)
    }
  }

  if (confirming) {
    return (
      <div className={`scan-delete-confirm${compact ? ' compact' : ''}`} onClick={(event) => event.stopPropagation()}>
        <span>{dataRemoved ? 'Clear this history record?' : 'Delete all scan data?'}</span>
        <button type="button" className="btn btn-danger btn-xs" disabled={busy} onClick={confirmDelete}>
          {busy ? 'Deleting…' : dataRemoved ? 'Clear record' : 'Delete data'}
        </button>
        <button type="button" className="btn btn-ghost btn-xs" disabled={busy} onClick={() => setConfirming(false)}>
          Cancel
        </button>
      </div>
    )
  }

  return (
    <button
      type="button"
      className={`btn scan-delete-action ${dataRemoved ? 'btn-ghost' : 'btn-danger'} btn-xs`}
      disabled={isActive}
      title={isActive ? 'Stop this scan before deleting its data' : dataRemoved ? 'Permanently remove this history record' : 'Delete reports, findings, logs, and runtime data'}
      onClick={(event) => { event.stopPropagation(); setConfirming(true) }}
    >
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M3 6h18M9 6V4h6v2M5 6l1 14h12l1-14M10 10v6M14 10v6" /></svg>
      <span>{dataRemoved ? 'Clear record' : 'Delete scan'}</span>
    </button>
  )
}
