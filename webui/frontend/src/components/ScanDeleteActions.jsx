import DeleteButton from './DeleteButton'
import { useState } from 'react'

export default function ScanDeleteActions({ run, onDeleteData, onDeleteRecord, compact = false }) {
  const [confirming, setConfirming] = useState(false)
  const [busy, setBusy] = useState(false)
  const isActive = ['running', 'stopping'].includes(run.status)
  const isQueued = run.status === 'queued'
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
        <span>{isQueued ? 'Delete this queued scan? It will not run.' : dataRemoved ? 'Clear this history record?' : 'Delete all scan data?'}</span>
        <DeleteButton disabled={busy} onClick={confirmDelete}>
          {busy ? 'Deleting…' : isQueued ? 'Delete queued scan' : dataRemoved ? 'Clear record' : 'Delete data'}
        </DeleteButton>
        <button type="button" className="btn btn-secondary" disabled={busy} onClick={() => setConfirming(false)}>
          Cancel
        </button>
      </div>
    )
  }

  return (
    <DeleteButton
      className="scan-delete-action"
      disabled={isActive}
      title={isActive ? 'Stop this scan before deleting its data' : isQueued ? 'Remove this scan from the queue and delete its record' : dataRemoved ? 'Permanently remove this history record' : 'Delete reports, findings, logs, and runtime data'}
      onClick={(event) => { event.stopPropagation(); setConfirming(true) }}
    >
      {dataRemoved ? 'Clear record' : 'Delete scan'}
    </DeleteButton>
  )
}
