export function formatDuration(seconds) {
  if (seconds == null || seconds === '' || !Number.isFinite(Number(seconds))) return '—'
  const total = Math.max(0, Math.round(Number(seconds)))
  const hours = Math.floor(total / 3600)
  const minutes = Math.floor((total % 3600) / 60)
  return `${hours}h ${minutes}m ${total % 60}s`
}

function timestampMs(value) {
  if (typeof value !== 'string' || !value.trim()) return NaN
  let input = value.trim().replace(' ', 'T')
  // Historical API timestamps without an offset are stored in UTC.
  if (/^\d{4}-\d\d-\d\dT/.test(input) && !/(Z|[+-]\d\d:\d\d)$/i.test(input)) input += 'Z'
  return Date.parse(input)
}

export function scanDurationSeconds(run, now = Date.now()) {
  if (run.status === 'queued') return null
  const started = timestampMs(run.started_at)
  if (['running', 'stopping'].includes(run.status)) {
    return Number.isFinite(started) ? Math.max(0, Math.floor((now - started) / 1000)) : null
  }
  if (run.duration_sec != null && run.duration_sec !== '' && Number.isFinite(Number(run.duration_sec))) return Number(run.duration_sec)
  const ended = timestampMs(run.ended_at)
  return Number.isFinite(started) && Number.isFinite(ended) ? Math.max(0, (ended - started) / 1000) : null
}
