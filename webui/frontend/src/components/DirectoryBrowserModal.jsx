import { useEffect, useMemo, useRef, useState } from 'react'
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
  const [pathInput, setPathInput] = useState('')
  const requestId = useRef(0)

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return dirs
    return dirs.filter((d) => d.name.toLowerCase().includes(q))
  }, [query, dirs])

  async function load(path = '') {
    const id = ++requestId.current
    setLoading(true)
    setError('')
    try {
      const data = await listDirectories(path)
      if (id !== requestId.current) return
      setCurrent(data.current)
      setPathInput(data.current)
      setParent(data.parent)
      setRoots(data.shortcuts?.length ? data.shortcuts : data.roots.map((path) => ({ path, name: path })))
      setDirs(data.directories)
      setQuery('')
    } catch (err) {
      if (id !== requestId.current) return
      setPathInput(current)
      setError(err.message || 'Unable to browse this directory. Check path permissions.')
    } finally {
      if (id === requestId.current) setLoading(false)
    }
  }

  useEffect(() => {
    if (open) load(current || '')
    return () => { requestId.current += 1 }
  }, [open])

  useEffect(() => {
    if (!open) return undefined
    const onKey = (event) => { if (event.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  if (!open) return null

  return (
    <div className="modal-shell directory-browser-shell" onClick={onClose}>
      <div className="modal-card lg directory-browser" role="dialog" aria-modal="true" aria-labelledby="directory-browser-title" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <h3 id="directory-browser-title">Select Target Directory</h3>
          <button className="btn-icon" aria-label="Close directory browser" onClick={onClose}>
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
                  <button key={r.path} className="root-chip" title={r.path} onClick={() => load(r.path)}>
                    {r.name}
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
                disabled={!parent || loading}
                title="Go up"
              >
                <svg width="14" height="14" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M14.707 12.707a1 1 0 01-1.414 0L10 9.414l-3.293 3.293a1 1 0 01-1.414-1.414l4-4a1 1 0 011.414 0l4 4a1 1 0 010 1.414z" clipRule="evenodd" />
                </svg>
                Up
              </button>
              <input
                className="path-display"
                aria-label="Directory path"
                value={pathInput}
                onChange={(e) => setPathInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') load(pathInput) }}
                title="Enter a path and press Enter"
              />
              <button className="btn btn-secondary btn-sm" onClick={() => load(pathInput)} disabled={loading}>
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
            aria-label="Filter folders"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />

          {error && <div className="error-banner" role="alert">{error}</div>}

          {/* Directory list */}
          <div className="dir-list" aria-busy={loading}>
            {loading && (
              <div style={{ padding: 16, display: 'flex', alignItems: 'center', gap: 8, color: 'var(--text-3)' }}>
                <span className="spinner" />
                Loading…
              </div>
            )}
            {!loading && !error && visible.length === 0 && (
              <div style={{ padding: 16, color: 'var(--text-3)', fontSize: 13 }}>
                {query ? 'No matching directories.' : 'This folder has no subfolders. You can select it for scanning.'}
              </div>
            )}
            {!loading && visible.map((d) => (
              <button
                key={d.path}
                className="dir-item"
                onClick={() => load(d.path)}
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
            Click a folder to open it, then select the current folder. Paths refer to the computer running Docker.
          </div>
        </div>

        <div className="modal-actions">
          <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" disabled={!current || loading || !!error || pathInput !== current} onClick={() => onSelect(current)}>
            <svg width="14" height="14" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
            </svg>
            Select This Folder
          </button>
        </div>
      </div>
    </div>
  )
}
