import { useEffect, useRef, useState } from 'react'
import { beginQueueEdit, updateQueueEdit } from '../api'
import ScanForm from './ScanForm'
import ScanDeleteActions from './ScanDeleteActions'
import DirectoryBrowserModal from './DirectoryBrowserModal'

export default function QueuedScanDetail({ run, position, defaults, onBack, onChanged, onDeleteData, onDeleteRecord }) {
  const [draft, setDraft] = useState(null)
  const [busy, setBusy] = useState(false)
  const [lost, setLost] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [browse, setBrowse] = useState(false)
  const token = useRef(null)
  const mounted = useRef(false)

  useEffect(() => {
    mounted.current = true
    const timer = setInterval(async () => {
      if (!token.current) return
      try { await updateQueueEdit(run.run_uuid, token.current, 'renew') }
      catch {
        if (mounted.current) {
          setLost(true)
          setError('The edit reservation could not be renewed. This scan remains paused. Your draft is kept here; reserve it again before saving.')
        }
      }
    }, 20000)
    const beforeUnload = event => {
      if (token.current) { event.preventDefault(); event.returnValue = '' }
    }
    window.addEventListener('beforeunload', beforeUnload)
    return () => {
      mounted.current = false
      clearInterval(timer)
      window.removeEventListener('beforeunload', beforeUnload)
      if (token.current) updateQueueEdit(run.run_uuid, token.current, 'cancel').catch(() => {})
      token.current = null
    }
  }, [run.run_uuid])

  async function reserve() {
    setBusy(true); setError('')
    try {
      if (token.current) {
        try {
          await updateQueueEdit(run.run_uuid, token.current, 'renew')
          setLost(false)
          return
        } catch { /* Acquire a new reservation if the old one expired. */ }
      }
      const result = await beginQueueEdit(run.run_uuid)
      if (!mounted.current) {
        await updateQueueEdit(run.run_uuid, result.token, 'cancel')
        return
      }
      token.current = result.token
      setLost(false)
      setDraft(current => current || { ...defaults, ...result.scan })
      onChanged()
    } catch (e) { if (mounted.current) setError(e.message) }
    finally { if (mounted.current) setBusy(false) }
  }

  async function action(kind) {
    if (!token.current) return
    setBusy(true); setError(''); setNotice('')
    try {
      await updateQueueEdit(run.run_uuid, token.current, kind, kind === 'save' ? {
        ...draft, custom_rdl: (draft.custom_rdl || []).map(path => path.trim()).filter(Boolean),
      } : undefined)
      if (kind === 'move-back') setNotice('Moved to the back of the queue. Your scan remains reserved while you edit; the next scan can proceed.')
      else {
        token.current = null
        setDraft(null)
        onChanged(false)
        onBack()
        return
      }
      onChanged()
    } catch (e) { setError(e.message) }
    finally { if (mounted.current) setBusy(false) }
  }

  return <div className="queued-scan-detail">
    <section className="card queue-waiting-card" aria-label="Queued scan waiting">
      <span className="queue-waiting-icon" aria-hidden="true">⌛</span>
      <div>
        <h2>{run.project_name || 'Queued scan'}</h2>
        <strong>{draft ? 'Reserved for editing — scanning has not started' : 'Queued — waiting for its turn'}</strong>
        <p>{position > 0 ? `Queue position ${position}${position === 1 ? ' · Next in line' : ''}. ` : ''}This scan will start only when its turn comes and editing is complete.</p>
        {run.queue_editing && !draft && <p role="status">This scan is currently reserved by another editor.</p>}
        {run.queue_reserved && !run.queue_editing && !draft && <p role="status">Editing is paused. Resume editing to save or cancel the changes before this scan can start.</p>}
        <div className="queue-detail-actions">
          <button className="btn btn-ghost" onClick={onBack} disabled={busy}>Back to queue</button>
          {!draft && <button className="btn btn-primary" disabled={busy || run.queue_editing} onClick={reserve}>{run.queue_reserved && !run.queue_editing ? 'Resume editing' : 'Edit settings'}</button>}
          <ScanDeleteActions run={run} onDeleteData={onDeleteData} onDeleteRecord={onDeleteRecord} />
        </div>
      </div>
    </section>
    {error && <div className="rdl-shadow-callout warning" role="alert">{error}</div>}
    {notice && <div className="card card-body" role="status">{notice}</div>}
    {draft && <>
      <section className="card card-body" aria-label="Queue edit reservation">
        <p role={position === 1 ? 'alert' : 'status'}>{position === 1
          ? 'Your scan is next in line. The queue will wait until you finish editing. Move it to the back to let the next scan continue.'
          : 'Your queue position is held while you edit. If your turn arrives, the queue waits for you. You can move this scan to the back at any time.'}</p>
        <p>If this tab closes or loses its connection, the scan stays paused. After two minutes you can reopen it and resume or cancel editing. Leaving this view normally discards unsaved edits and releases the reservation.</p>
        <div className="queue-detail-actions">
          <button className="btn btn-secondary" disabled={busy || lost} onClick={() => action('move-back')}>Move to back and keep editing</button>
          <button className="btn btn-ghost" disabled={busy} onClick={() => action('cancel')}>Cancel edits</button>
          {lost && <button className="btn btn-primary" disabled={busy} onClick={reserve}>Reserve again</button>}
        </div>
      </section>
      <ScanForm values={draft} setValues={setDraft} onSubmit={() => action('save')} onBrowse={() => setBrowse(true)} creating={busy || lost} editing />
      <DirectoryBrowserModal open={browse} onClose={() => setBrowse(false)} initialPath={draft.target_dir} onSelect={path => { setDraft(current => ({ ...current, target_dir: path })); setBrowse(false) }} />
    </>}
  </div>
}
