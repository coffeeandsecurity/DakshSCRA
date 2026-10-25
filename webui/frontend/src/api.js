import { referenceCode, validReference, friendlyError } from './lib/apiErrors'
const API_BASE = import.meta.env.VITE_API_BASE || ''

// Registered by App.jsx so a session that expires mid-use (401 from any
// call, not just the initial /auth/me check) bounces back to the login
// screen instead of failing silently or showing a confusing error.
let onUnauthorized = null
export function setUnauthorizedHandler(fn) {
  onUnauthorized = fn
}

const pendingKey = 'daksh.pending-api-errors'
let reporting = false, lastReport = 0
function pendingErrors() {
  try { return JSON.parse(sessionStorage.getItem(pendingKey) || '[]').filter(item => Date.now() - item.time < 86400000).slice(-20) } catch { return [] }
}
function queueClientError(code, path, method, detail) {
  console.error('Backend request failed', { error_code: code, path: path.split('?')[0], method, detail })
  try { sessionStorage.setItem(pendingKey, JSON.stringify([...pendingErrors(), { error_code: code, path: path.split('?')[0], method, detail: String(detail).slice(0, 1000), time: Date.now() }].slice(-20))) } catch { /* Storage may be unavailable. */ }
}
async function flushClientErrors() {
  if (reporting || Date.now() - lastReport < 10000) return
  const pending = pendingErrors()
  if (!pending.length) return
  reporting = true; lastReport = Date.now()
  try {
    for (const item of pending) {
      const response = await fetch(`${API_BASE}/api/v1/client-errors`, { method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json', 'X-Request-ID': item.error_code }, body: JSON.stringify(item) })
      if (!response.ok) break
      try { sessionStorage.setItem(pendingKey, JSON.stringify(pendingErrors().filter(entry => entry.error_code !== item.error_code))) } catch { /* Storage unavailable. */ }
    }
  } catch { /* Keep pending diagnostics until a later successful request. */ }
  finally { reporting = false }
}

async function request(path, options = {}) {
  const code = referenceCode()
  const headers = { ...(options.headers || {}), 'X-Request-ID': code }
  const hasBody = options.body !== undefined && options.body !== null
  const isFormData = typeof FormData !== 'undefined' && options.body instanceof FormData
  if (hasBody && !isFormData && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json'
  }

  let res
  try {
    res = await fetch(`${API_BASE}${path}`, { ...options, credentials: 'include', headers })
  } catch (error) {
    if (error.name === 'AbortError') throw error
    queueClientError(code, path, options.method || 'GET', `${error.name}: ${error.message}`)
    throw friendlyError(0, code)
  }

  // A 401 from /auth/login or /auth/change-password means "wrong password
  // entered", not "your session expired" - those should show an inline
  // error, not force a bounce back to the login screen.
  const isCredentialCheck = path === '/api/v1/auth/login' || path === '/api/v1/auth/change-password'
  if (res.status === 401 && !isCredentialCheck) {
    if (typeof onUnauthorized === 'function') onUnauthorized()
  }

  const headerCode = res.headers.get('x-request-id')
  let responseCode = validReference(headerCode) ? headerCode : code
  if (!res.ok) {
    let detail
    try {
      const data = await res.json()
      if (validReference(data?.error_code)) {
        responseCode = data.error_code
        detail = data.detail
      }
    } catch { /* Non-JSON proxy errors use the friendly status message. */ }
    throw friendlyError(res.status, responseCode, detail)
  }
  if (res.status === 204 || res.headers.get('content-length') === '0') {
    void flushClientErrors()
    return null
  }
  try {
    const data = res.headers.get('content-type')?.includes('application/json') ? await res.json() : await res.text()
    void flushClientErrors()
    return data
  } catch (error) {
    if (error.name === 'AbortError') throw error
    queueClientError(responseCode, path, options.method || 'GET', `${error.name}: Invalid response body`)
    throw friendlyError(500, responseCode)
  }
}

export function getHealth() {
  return request('/api/v1/health')
}

export function getCheckCatalog(refresh = false) {
  return request('/api/v1/check-catalog' + (refresh ? '?refresh=true' : ''))
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

export function listScans(limit = 50, projectKey = '', options = {}) {
  const qp = new URLSearchParams({ limit: String(limit) })
  if (projectKey) qp.set('project_key', projectKey)
  for (const key of ['offset', 'status', 'search']) {
    if (options[key] != null && options[key] !== '') qp.set(key, String(options[key]))
  }
  return request(`/api/v1/scans?${qp.toString()}`)
}

export function getScan(runUuid) {
  return request(`/api/v1/scans/${encodeURIComponent(runUuid)}`)
}

export function beginQueueEdit(runUuid) {
  return request(`/api/v1/scans/${encodeURIComponent(runUuid)}/queue-edit`, { method: 'POST' })
}

export function updateQueueEdit(runUuid, token, action, settings) {
  const suffix = action === 'move-back' ? '/move-back' : ''
  const method = { renew: 'PATCH', cancel: 'DELETE', save: 'PUT', 'move-back': 'POST' }[action]
  return request(`/api/v1/scans/${encodeURIComponent(runUuid)}/queue-edit${suffix}`, {
    method, body: JSON.stringify({ token, ...(settings ? { settings } : {}) }),
  })
}

export function getScanArtifacts(runUuid) {
  return request(`/api/v1/scans/${encodeURIComponent(runUuid)}/artifacts`)
}

export function getScanLog(runUuid) {
  return request(`/api/v1/scans/${encodeURIComponent(runUuid)}/log`)
}

export function listDirectories(path = '', options = {}) {
  return request(`/api/v1/fs/list?path=${encodeURIComponent(path)}`, options)
}

export function stopScan(runUuid) {
  return request(`/api/v1/scans/${encodeURIComponent(runUuid)}/stop`, { method: 'POST' })
}

export function deleteScanData(runUuid) {
  return request(`/api/v1/scans/${encodeURIComponent(runUuid)}`, { method: 'DELETE' })
}

export function deleteScanRecord(runUuid) {
  return request(`/api/v1/scans/${encodeURIComponent(runUuid)}/record`, { method: 'DELETE' })
}

export function streamScanLog(runUuid, onChunk, onDone) {
  const code = referenceCode()
  const streamPath = `/api/v1/scans/${encodeURIComponent(runUuid)}/stream`
  const url = `${API_BASE}${streamPath}?request_id=${code}`
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
        queueClientError(code, streamPath, 'GET', 'EventSource connection failed after three retries')
        onChunk(`\nLive updates could not connect. Refresh the page to try again. Reference: ${code}\n`, 'unknown', null)
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

export function getScanFindings(runUuid, options = {}) {
  return request(`/api/v1/scans/${encodeURIComponent(runUuid)}/findings`, options)
}

export function getEffortPlan(runUuid) {
  return request(`/api/v1/scans/${encodeURIComponent(runUuid)}/effort-plan`)
}

export function createEffortPlan(runUuid, options, report = false) {
  return request(`/api/v1/scans/${encodeURIComponent(runUuid)}/${report ? 'effort-report' : 'effort-plan'}`, {
    method: 'POST', body: JSON.stringify(options),
  })
}

export function getScanAnalysis(runUuid) {
  return request(`/api/v1/scans/${encodeURIComponent(runUuid)}/analysis`)
}

export function getProgramGraphs(runUuid, options = {}) {
  return request(`/api/v1/scans/${encodeURIComponent(runUuid)}/program-graphs?${new URLSearchParams(options)}`)
}

export function buildProgramGraphs(runUuid) {
  return request(`/api/v1/scans/${encodeURIComponent(runUuid)}/program-graphs`, { method: 'POST' })
}

export function getRdlShadowResults(runUuid, limit = 50, options = {}) {
  const query = new URLSearchParams({ limit, ...options })
  return request(`/api/v1/scans/${encodeURIComponent(runUuid)}/rdl-shadow?${query}`)
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

export function getSuppressedFindings(runUuid, summaryOnly = false, options = {}) {
  const suffix = summaryOnly ? '?summary_only=true' : ''
  return request(`/api/v1/scans/${encodeURIComponent(runUuid)}/suppressed${suffix}`, options)
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

/** Numeric parts of a release tag. v0.41-beta -> [0, 41], v1.0 -> [1, 0]. */
function releaseNumbers(tag) {
  const m = String(tag).replace(/^v/i, '').match(/^[\d.]+/)
  return m ? m[0].split('.').map(Number) : [0]
}

function compareReleaseNumbers(a, b) {
  const len = Math.max(a.length, b.length)
  for (let i = 0; i < len; i++) {
    const diff = (a[i] ?? 0) - (b[i] ?? 0)
    if (diff) return diff
  }
  return 0
}

/**
 * Check GitHub for the highest published release, beta or stable. The `releases/latest`
 * endpoint skips pre-releases, so a beta such as v0.41 or a first v1.0 could be missed.
 * Cached in sessionStorage for the session.
 */
export async function getLatestGithubRelease(repo) {
  const cacheKey = `gh_latest_v2_${repo}`
  const cached = sessionStorage.getItem(cacheKey)
  if (cached) return JSON.parse(cached)
  try {
    const res = await fetch(`https://api.github.com/repos/${repo}/releases?per_page=30`, {
      headers: { Accept: 'application/vnd.github+json' }
    })
    if (!res.ok) return null
    const releases = (await res.json()).filter(r => r && !r.draft && r.tag_name)
    if (!releases.length) return null
    const best = releases.reduce((top, r) =>
      compareReleaseNumbers(releaseNumbers(r.tag_name), releaseNumbers(top.tag_name)) > 0 ? r : top)
    const result = { tag: best.tag_name, url: best.html_url, name: best.name, prerelease: !!best.prerelease }
    sessionStorage.setItem(cacheKey, JSON.stringify(result))
    return result
  } catch {
    return null
  }
}

export function getRdlXref(runUuid, options = {}) {
  return request(`/api/v1/scans/${encodeURIComponent(runUuid)}/rdl-xref?${new URLSearchParams(options)}`)
}

export function buildRdlXref(runUuid) {
  return request(`/api/v1/scans/${encodeURIComponent(runUuid)}/rdl-xref`, { method: 'POST' })
}

export const listReports = runUuid => request(`/api/v1/scans/${encodeURIComponent(runUuid)}/reports`)
export const generateReport = (runUuid, options) => request(`/api/v1/scans/${encodeURIComponent(runUuid)}/reports`, { method: 'POST', body: JSON.stringify(options) })
export const reportDownloadUrl = (runUuid, reportId) => `${API_BASE}/api/v1/scans/${encodeURIComponent(runUuid)}/reports/${encodeURIComponent(reportId)}/download`

export const getDiskInfo = () => request('/api/v1/system/disk')
export const cleanupDiskAreas = areas => request('/api/v1/system/disk/cleanup', { method: 'POST', body: JSON.stringify({ areas }) })
export const getDiskFiles = (runUuid, unitId, offset = 0) => request(`/api/v1/system/disk/scans/${encodeURIComponent(runUuid)}/units/${encodeURIComponent(unitId)}/files?offset=${offset}&limit=100`)
export const deleteDiskUnit = (runUuid, unitId) => request(`/api/v1/system/disk/scans/${encodeURIComponent(runUuid)}/units/${encodeURIComponent(unitId)}`, { method: 'DELETE' })
export const deleteDiskScan = runUuid => request(`/api/v1/system/disk/scans/${encodeURIComponent(runUuid)}`, { method: 'DELETE' })

export function getRdlAdvancedResults(runUuid, limit = 50, options = {}) {
  return getRdlShadowResults(runUuid, limit, { ...options, advanced: true })
}
