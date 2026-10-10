export function reportProgress(item) {
  const active = ['queued', 'running'].includes(item.status)
  const progress = active ? item.progress || {} : {}
  const message = item.status === 'complete' ? 'Ready to download' : item.status === 'failed' ? 'Generation failed' : progress.message || (item.status === 'queued' ? 'Waiting for the report worker' : `Generating ${item.format.toUpperCase()} report`)
  const total = progress.total
  const completed = progress.completed
  const counted = active && Number.isFinite(total) && total > 0 && Number.isFinite(completed) && completed >= 0
  return { active, message, counted, total, completed: counted ? Math.min(completed, total) : 0, unit: progress.unit || 'items', phase: progress.phase || item.status }
}
