const NAV_ITEMS = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    icon: (
      <svg className="nav-icon" viewBox="0 0 20 20" fill="currentColor">
        <path d="M2 10a8 8 0 018-8v8h8a8 8 0 11-16 0z" />
        <path d="M12 2.252A8.014 8.014 0 0117.748 8H12V2.252z" />
      </svg>
    ),
  },
  {
    id: 'projects',
    label: 'Projects',
    icon: (
      <svg className="nav-icon" viewBox="0 0 20 20" fill="currentColor">
        <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
      </svg>
    ),
  },
  {
    id: 'scans',
    label: 'Scans',
    icon: (
      <svg className="nav-icon" viewBox="0 0 20 20" fill="currentColor">
        <path fillRule="evenodd" d="M3 4a1 1 0 011-1h3a1 1 0 011 1v3a1 1 0 01-1 1H4a1 1 0 01-1-1V4zm2 2V5h1v1H5zM3 13a1 1 0 011-1h3a1 1 0 011 1v3a1 1 0 01-1 1H4a1 1 0 01-1-1v-3zm2 2v-1h1v1H5zM13 3a1 1 0 00-1 1v3a1 1 0 001 1h3a1 1 0 001-1V4a1 1 0 00-1-1h-3zm1 2v1h1V5h-1zM11 13a1 1 0 011-1h3a1 1 0 011 1v3a1 1 0 01-1 1h-3a1 1 0 01-1-1v-3zm2 2v-1h1v1h-1z" clipRule="evenodd" />
      </svg>
    ),
  },
  {
    id: 'settings',
    label: 'Settings',
    icon: (
      <svg className="nav-icon" viewBox="0 0 20 20" fill="currentColor">
        <path fillRule="evenodd" d="M11.49 3.17c-.38-1.56-2.6-1.56-2.98 0a1.532 1.532 0 01-2.286.948c-1.372-.836-2.942.734-2.106 2.106.54.886.061 2.042-.947 2.287-1.561.379-1.561 2.6 0 2.978a1.532 1.532 0 01.947 2.287c-.836 1.372.734 2.942 2.106 2.106a1.532 1.532 0 012.287.947c.379 1.561 2.6 1.561 2.978 0a1.533 1.533 0 012.287-.947c1.372.836 2.942-.734 2.106-2.106a1.533 1.533 0 01.947-2.287c1.561-.379 1.561-2.6 0-2.978a1.532 1.532 0 01-.947-2.287c.836-1.372-.734-2.942-2.106-2.106a1.532 1.532 0 01-2.287-.947zM10 13a3 3 0 100-6 3 3 0 000 6z" clipRule="evenodd" />
      </svg>
    ),
  },
  {
    id: 'help',
    label: 'Help',
    icon: (
      <svg className="nav-icon" viewBox="0 0 20 20" fill="currentColor">
        <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-8-3a1 1 0 00-.867.5 1 1 0 11-1.731-1A3 3 0 0113 8a3.001 3.001 0 01-2 2.83V11a1 1 0 11-2 0v-1a1 1 0 011-1 1 1 0 100-2zm0 8a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
      </svg>
    ),
  },
  {
    id: 'about',
    label: 'About',
    icon: (
      <svg className="nav-icon" viewBox="0 0 20 20" fill="currentColor">
        <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm0-11a1 1 0 100-2 1 1 0 000 2zM8.75 9a.75.75 0 000 1.5h.5v3h-.5a.75.75 0 000 1.5h2.5a.75.75 0 000-1.5h-.5V9.75A.75.75 0 0010 9H8.75z" clipRule="evenodd" />
      </svg>
    ),
  },
]

export default function Sidebar({ active, onChange, health, runningCount = 0, version }) {
  return (
    <aside className="sidebar">
      {/* Brand */}
      <div className="sidebar-brand">
        <div className="brand-logo">
          <svg viewBox="0 0 400 400" width="36" height="36" xmlns="http://www.w3.org/2000/svg">
            <g transform="rotate(144, 200, 200)">
              <path d="M 200,200 C 244,188 255,115 215,72 Q 200,52 185,72 C 145,115 156,188 200,200 Z" fill="#9d52de"/>
              <circle cx="200" cy="90" r="11" fill="#141414"/>
              <circle cx="191" cy="122" r="11" fill="#141414"/>
              <circle cx="209" cy="152" r="11" fill="#141414"/>
            </g>
            <g transform="rotate(216, 200, 200)">
              <path d="M 200,200 C 244,188 255,115 215,72 Q 200,52 185,72 C 145,115 156,188 200,200 Z" fill="#2dc98a"/>
              <circle cx="200" cy="90" r="11" fill="#141414"/>
              <circle cx="191" cy="122" r="11" fill="#141414"/>
              <circle cx="209" cy="152" r="11" fill="#141414"/>
            </g>
            <g transform="rotate(288, 200, 200)">
              <path d="M 200,200 C 244,188 255,115 215,72 Q 200,52 185,72 C 145,115 156,188 200,200 Z" fill="#f5bf1e"/>
              <circle cx="200" cy="90" r="11" fill="#141414"/>
              <circle cx="191" cy="122" r="11" fill="#141414"/>
              <circle cx="209" cy="152" r="11" fill="#141414"/>
            </g>
            <g transform="rotate(72, 200, 200)">
              <path d="M 200,200 C 244,188 255,115 215,72 Q 200,52 185,72 C 145,115 156,188 200,200 Z" fill="#17b2f0"/>
              <circle cx="200" cy="90" r="11" fill="#141414"/>
              <circle cx="191" cy="122" r="11" fill="#141414"/>
              <circle cx="209" cy="152" r="11" fill="#141414"/>
            </g>
            <g transform="rotate(0, 200, 200)">
              <path d="M 200,200 C 244,188 255,115 215,72 Q 200,52 185,72 C 145,115 156,188 200,200 Z" fill="#f0357a"/>
              <circle cx="200" cy="90" r="11" fill="#141414"/>
              <circle cx="191" cy="122" r="11" fill="#141414"/>
              <circle cx="209" cy="152" r="11" fill="#141414"/>
            </g>
          </svg>
        </div>
        <div>
          <span className="brand-name">DAKSH SCRA</span>
          <span className="brand-sub">Code Security Review</span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="sidebar-nav">
        {NAV_ITEMS.map((item) => (
          <button
            key={item.id}
            className={`nav-item${active === item.id ? ' active' : ''}`}
            onClick={() => onChange(item.id)}
          >
            {item.icon}
            {item.label}
            {item.id === 'scans' && runningCount > 0 && (
              <span className="nav-badge">{runningCount}</span>
            )}
          </button>
        ))}
      </nav>

      {/* Footer */}
      <div className="sidebar-footer">
        <div className={`api-status ${health}`}>
          <span className="dot" />
          API {health}
        </div>
        <span className="sidebar-version">{version ? `v${version}` : 'v1.1.0'}</span>
      </div>
    </aside>
  )
}
