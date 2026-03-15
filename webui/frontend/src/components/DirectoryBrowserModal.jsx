import { useEffect, useMemo, useState } from 'react'
import { listDirectories } from '../api'

function FolderIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 20 20" fill="currentColor" className="dir-icon">
      <path d="M2 6a2 2 0 012-2h5l2 2h5a2 2 0 012 2v6a2 2 0 01-2 2H4a2 2 0 01-2-2V6z" />
    </svg>
  )
}

export default function DirectoryBrowserModal({ open, onClose, onSelect }) {
  const [current, setCurrent] = useState('')
  const [roots, setRoots] = useState([])
  const [dirs, setDirs] = useState([])
  const [parent, setParent] = useState(null)
  const [query, setQuery] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return dirs
    return dirs.filter((d) => d.name.toLowerCase().includes(q))
  }, [query, dirs])

  async function load(path = '') {
    setLoading(true)
    setError('')
    try {
      const data = await listDirectories(path)
      setCurrent(data.current)
      setParent(data.parent)
      setRoots(data.roots)
      setDirs(data.directories)
      setQuery('')
    } catch {
      setError('Unable to browse this directory. Check path permissions.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (open) load(current || '')
  }, [open])

  if (!open) return null

  return (
    <div className="modal-shell" onClick={onClose}>
      <div className="modal-card lg" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <h3>Select Target Directory</h3>
          <button className="btn-icon" onClick={onClose}>
            <svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
            </svg>
          </button>
        </div>

        <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {/* Root shortcuts */}
          {roots.length > 0 && (
            <div>
              <div className="form-label" style={{ marginBottom: 6 }}>Quick Access</div>
              <div className="root-tabs">
                {roots.map((r) => (
                  <button key={r} className="root-chip" onClick={() => load(r)}>
                    {r.split('/').slice(-1)[0] || r}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Path navigator */}
          <div>
            <div className="form-label" style={{ marginBottom: 6 }}>Current Path</div>
            <div className="path-navigator">
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => parent && load(parent)}
                disabled={!parent}
                title="Go up"
              >
                <svg width="14" height="14" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M14.707 12.707a1 1 0 01-1.414 0L10 9.414l-3.293 3.293a1 1 0 01-1.414-1.414l4-4a1 1 0 011.414 0l4 4a1 1 0 010 1.414z" clipRule="evenodd" />
                </svg>
                Up
              </button>
              <div
                className="path-display"
                title={current}
              >
                {current || '(root)'}
              </div>
              <button className="btn btn-secondary btn-sm" onClick={() => load(current)}>
                <svg width="14" height="14" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M4 2a1 1 0 011 1v2.101a7.002 7.002 0 0111.601 2.566 1 1 0 11-1.885.666A5.002 5.002 0 005.999 7H9a1 1 0 010 2H4a1 1 0 01-1-1V3a1 1 0 011-1zm.008 9.057a1 1 0 011.276.61A5.002 5.002 0 0014.001 13H11a1 1 0 110-2h5a1 1 0 011 1v5a1 1 0 11-2 0v-2.101a7.002 7.002 0 01-11.601-2.566 1 1 0 01.61-1.276z" clipRule="evenodd" />
                </svg>
                Refresh
              </button>
            </div>
          </div>

          {/* Filter */}
          <input
            className="form-input"
            type="search"
            placeholder="Filter folders…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />

          {error && <div className="error-banner">{error}</div>}

          {/* Directory list */}
          <div className="dir-list">
            {loading && (
              <div style={{ padding: 16, display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-3)' }}>
                <span className="spinner" />
                Loading…
              </div>
            )}
            {!loading && visible.length === 0 && (
              <div style={{ padding: 16, color: 'var(--text-3)', fontSize: 13 }}>
                {query ? 'No matching directories.' : 'No subdirectories found.'}
              </div>
            )}
            {!loading && visible.map((d) => (
              <button
                key={d.path}
                className={`dir-item${current === d.path ? ' active' : ''}`}
                onDoubleClick={() => load(d.path)}
                onClick={() => setCurrent(d.path)}
              >
                <div className="dir-item-name">
                  <FolderIcon />
                  {d.name}
                </div>
                <div className="dir-item-path">{d.path}</div>
              </button>
            ))}
          </div>

          <div style={{ fontSize: 12, color: 'var(--text-3)' }}>
            Double-click to navigate into a folder. Single-click to select it.
          </div>
        </div>

        <div className="modal-actions">
          <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn btn-secondary" onClick={() => onSelect(current)}>
            Use Current Path
          </button>
          <button className="btn btn-primary" disabled={!current} onClick={() => onSelect(current)}>
            <svg width="14" height="14" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
            </svg>
            Select This Path
          </button>
        </div>
      </div>
    </div>
  )
}
