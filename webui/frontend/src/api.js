const API_BASE = import.meta.env.VITE_API_BASE || ''

// Registered by App.jsx so a session that expires mid-use (401 from any
// call, not just the initial /auth/me check) bounces back to the login
// screen instead of failing silently or showing a confusing error.
let onUnauthorized = null
export function setUnauthorizedHandler(fn) {
  onUnauthorized = fn
}

async function request(path, options = {}) {
  const headers = { ...(options.headers || {}) }
  const hasBody = options.body !== undefined && options.body !== null
  const isFormData = typeof FormData !== 'undefined' && options.body instanceof FormData
  if (hasBody && !isFormData && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json'
  }

  const res = await fetch(`${API_BASE}${path}`, {
    credentials: 'include',
    headers,
    ...options
  })

  // A 401 from /auth/login or /auth/change-password means "wrong password
  // entered", not "your session expired" - those should show an inline
  // error, not force a bounce back to the login screen.
  const isCredentialCheck = path === '/api/v1/auth/login' || path === '/api/v1/auth/change-password'
  if (res.status === 401 && !isCredentialCheck) {
    if (typeof onUnauthorized === 'function') onUnauthorized()
  }

  if (!res.ok) {
    let message = `HTTP ${res.status}`
    try {
      const data = await res.clone().json()
      if (data?.detail) message = String(data.detail)
    } catch {
      try {
        const txt = await res.text()
        if (txt) message = txt
      } catch {
        // response body unreadable - fall back to the HTTP status message
      }
    }
    throw new Error(message)
  }

  if (res.status === 204 || res.headers.get('content-length') === '0') return null
  return res.headers.get('content-type')?.includes('application/json') ? res.json() : res.text()
}

export function getHealth() {
  return request('/api/v1/health')
}

export function getBootstrapInfo() {
  return request('/api/v1/auth/bootstrap-info')
}

export function login(username, password) {
  return request('/api/v1/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) })
}

export function logout() {
  return request('/api/v1/auth/logout', { method: 'POST' })
}

export function getMe() {
  return request('/api/v1/auth/me')
}

export function changePassword(currentPassword, newPassword, newUsername) {
  return request('/api/v1/auth/change-password', {
    method: 'POST',
    body: JSON.stringify({
      ...(currentPassword ? { current_password: currentPassword } : {}),
      new_password: newPassword,
      ...(newUsername ? { new_username: newUsername } : {}),
    }),
  })
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
  const MAX_RETRIES = 3
  const RETRY_DELAY_MS = 1000
  let es = null
  let retryCount = 0
  let retryTimer = null
  let cancelled = false

  function connect() {
    // withCredentials so the session cookie rides along - EventSource can't
    // set an Authorization header, which is why this endpoint relies on
    // cookie-based auth rather than a bearer token.
    es = new EventSource(url, { withCredentials: true })
    es.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data)
        retryCount = 0
        onChunk(data.log || '', data.status, data.progress || null)
        if (data.done) {
          onDone(data.status)
          es.close()
        }
      } catch {
        // ignore parse errors
      }
    }
    es.onerror = () => {
      es.close()
      if (cancelled) return
      if (retryCount >= MAX_RETRIES) {
        onDone('unknown')
        return
      }
      retryCount += 1
      retryTimer = setTimeout(connect, RETRY_DELAY_MS * retryCount)
    }
  }

  connect()

  return () => {  // returns cancel fn
    cancelled = true
    if (retryTimer) clearTimeout(retryTimer)
    if (es) es.close()
  }
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

export function getVersion() {
  return request('/api/v1/version')
}

export function getSuppressedFindings(runUuid) {
  return request(`/api/v1/scans/${encodeURIComponent(runUuid)}/suppressed`)
}

export function updateSuppressedItem(runUuid, itemId, payload) {
  return request(`/api/v1/scans/${encodeURIComponent(runUuid)}/suppressed/${encodeURIComponent(itemId)}`, {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}

export function promoteSuppressedItem(runUuid, itemId, payload) {
  return request(`/api/v1/scans/${encodeURIComponent(runUuid)}/suppressed/${encodeURIComponent(itemId)}/promote`, {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function getSuppressedReportUrl(runUuid, format = 'json') {
  const API_BASE = import.meta.env.VITE_API_BASE || ''
  return `${API_BASE}/api/v1/scans/${encodeURIComponent(runUuid)}/suppressed-report?format=${format}`
}

export function regenerateReports(runUuid) {
  return request(`/api/v1/scans/${encodeURIComponent(runUuid)}/regenerate-reports`, { method: 'POST' })
}

/** Check GitHub for the latest release tag. Cached in sessionStorage for the session. */
export async function getLatestGithubRelease(repo) {
  const cacheKey = `gh_latest_${repo}`
  const cached = sessionStorage.getItem(cacheKey)
  if (cached) return JSON.parse(cached)
  try {
    const res = await fetch(`https://api.github.com/repos/${repo}/releases/latest`, {
      headers: { Accept: 'application/vnd.github+json' }
    })
    if (!res.ok) return null
    const data = await res.json()
    const result = { tag: data.tag_name, url: data.html_url, name: data.name }
    sessionStorage.setItem(cacheKey, JSON.stringify(result))
    return result
  } catch {
    return null
  }
}
