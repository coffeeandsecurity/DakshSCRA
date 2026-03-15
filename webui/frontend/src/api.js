const API_BASE = import.meta.env.VITE_API_BASE || ''

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options
  })

  if (!res.ok) {
    let message = `HTTP ${res.status}`
    try {
      const data = await res.json()
      if (data?.detail) message = String(data.detail)
    } catch {
      const txt = await res.text()
      if (txt) message = txt
    }
    throw new Error(message)
  }

  if (res.status === 204 || res.headers.get('content-length') === '0') return null
  return res.headers.get('content-type')?.includes('application/json') ? res.json() : res.text()
}

export function getHealth() {
  return request('/api/v1/health')
}

export function getMetrics() {
  return request('/api/v1/dashboard/metrics')
}

export function listProjects() {
  return request('/api/v1/projects')
}

export function createScan(payload) {
  return request('/api/v1/scans', { method: 'POST', body: JSON.stringify(payload) })
}

export function listScans(limit = 50, projectKey = '') {
  const qp = new URLSearchParams({ limit: String(limit) })
  if (projectKey) qp.set('project_key', projectKey)
  return request(`/api/v1/scans?${qp.toString()}`)
}

export function getScan(runUuid) {
  return request(`/api/v1/scans/${encodeURIComponent(runUuid)}`)
}

export function getScanArtifacts(runUuid) {
  return request(`/api/v1/scans/${encodeURIComponent(runUuid)}/artifacts`)
}

export function getScanLog(runUuid) {
  return request(`/api/v1/scans/${encodeURIComponent(runUuid)}/log`)
}

export function listDirectories(path = '') {
  return request(`/api/v1/fs/list?path=${encodeURIComponent(path)}`)
}

export function stopScan(runUuid) {
  return request(`/api/v1/scans/${encodeURIComponent(runUuid)}/stop`, { method: 'POST' })
}

export function streamScanLog(runUuid, onChunk, onDone) {
  const url = `${API_BASE}/api/v1/scans/${encodeURIComponent(runUuid)}/stream`
  const es = new EventSource(url)
  es.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data)
      if (data.log) onChunk(data.log, data.status)
      if (data.done) {
        onDone(data.status)
        es.close()
      }
    } catch {
      // ignore parse errors
    }
  }
  es.onerror = () => {
    onDone('unknown')
    es.close()
  }
  return () => es.close()  // returns cancel fn
}

export function getScanFindings(runUuid) {
  return request(`/api/v1/scans/${encodeURIComponent(runUuid)}/findings`)
}

export function deleteProject(projectKey) {
  return request(`/api/v1/projects/${encodeURIComponent(projectKey)}`, { method: 'DELETE' })
}

export function artifactUrl(path) {
  return `${API_BASE}/api/v1/artifacts?path=${encodeURIComponent(path)}`
}

export function getSettings() {
  return request('/api/v1/settings')
}

export function saveSettings(payload) {
  return request('/api/v1/settings', { method: 'PUT', body: JSON.stringify(payload) })
}
