export default function MetricsPanel({ metrics }) {
  const cards = [
    ['Projects', metrics?.total_projects || 0],
    ['Scans', metrics?.total_scans || 0],
    ['Running', metrics?.running_scans || 0],
    ['Failed', metrics?.failed_scans || 0],
    ['Success %', `${metrics?.success_rate || 0}%`],
    ['Avg Duration', `${metrics?.avg_duration_sec || 0}s`]
  ]

  const max = Math.max(...(metrics?.recent_daily || []).map((x) => x.count), 1)

  return (
    <section className="panel">
      <div className="panel-head"><h2>Portfolio Metrics</h2></div>
      <div className="metric-grid">
        {cards.map(([k, v]) => (
          <div className="metric-card" key={k}>
            <span>{k}</span>
            <strong>{v}</strong>
          </div>
        ))}
      </div>
      <div className="sparkline-wrap">
        {(metrics?.recent_daily || []).map((d) => (
          <div key={d.date} className="spark-item" title={`${d.date}: ${d.count}`}>
            <b style={{ height: `${Math.max(8, (d.count / max) * 78)}px` }}></b>
            <small>{d.date.slice(5)}</small>
          </div>
        ))}
      </div>
    </section>
  )
}
