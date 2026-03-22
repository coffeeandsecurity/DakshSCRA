const ITEMS = [
  { id: 'overview', label: 'Overview' },
  { id: 'projects', label: 'Projects' },
  { id: 'scans', label: 'Scans & Areas of Interest' }
]

export default function LeftNav({ active, onChange, health }) {
  return (
    <aside className="left-nav panel">
      <p className="eyebrow">DakshSCRA</p>
      <h2 className="nav-title">Control Plane</h2>
      <div className="nav-items">
        {ITEMS.map((item) => (
          <button
            key={item.id}
            className={`nav-item ${active === item.id ? 'active' : ''}`}
            onClick={() => onChange(item.id)}
          >
            {item.label}
          </button>
        ))}
      </div>
      <div className="nav-health">
        <span className={`dot ${health}`}></span>
        API {health}
      </div>
    </aside>
  )
}
