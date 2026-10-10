export function formatDuration(seconds) {
  if (seconds == null || seconds === '' || !Number.isFinite(Number(seconds))) return '—'
  const total = Math.max(0, Math.round(Number(seconds)))
  const hours = Math.floor(total / 3600)
  const minutes = Math.floor((total % 3600) / 60)
  return `${hours}h ${minutes}m ${total % 60}s`
}
