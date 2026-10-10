export default function ProjectMetrics({ project }) {
  const metrics = [
    ['Scans', project.total_scans], ['Completed', project.success_scans],
    ['Active', (project.running_scans || 0) + (project.stopping_scans || 0)],
    ['Queued', project.queued_scans], ['Failed', project.failed_scans], ['Stopped', project.stopped_scans],
  ]
  return <dl className="project-row-metrics">{metrics.map(([label, value]) => <div key={label}><dt>{label}</dt><dd>{value ?? 0}</dd></div>)}</dl>
}

