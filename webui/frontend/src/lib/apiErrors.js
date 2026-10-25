const messages = {
  400: 'The request could not be accepted. Check your selections and try again.',
  401: 'Your session has expired. Sign in again.',
  403: 'You do not have permission to perform this action.',
  404: 'The requested item could not be found. Refresh the page and try again.',
  409: 'This action is not available in the current state. Refresh the page and try again.',
  410: 'The saved data is no longer available.',
  413: 'The upload is too large. Choose a smaller file.',
  422: 'Some settings are invalid. Check the fields and try again.',
  429: 'Too many requests. Wait a moment and try again.',
  500: 'Something went wrong while processing the request. Please try again.',
  502: 'The backend is temporarily unavailable. Please try again shortly.',
  503: 'The backend is temporarily unavailable. Please try again shortly.',
  504: 'The backend took too long to respond. Please try again.',
}
export function referenceCode() {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('')
}
export function validReference(value) { return /^[a-f0-9]{32}$/.test(String(value || '')) }
export function friendlyError(status, code, detail) {
  // Only server-controlled friendly responses may supply their own message.
  // Raw HTML, exception strings and legacy error bodies are never displayed.
  const message = typeof detail === 'string' && detail.length <= 500 && !/[<>\n]/.test(detail)
    ? detail : messages[status] || 'Unable to reach the backend. Check your connection and try again.'
  const error = new Error(`${message} Reference: ${code}`)
  error.errorCode = code
  error.status = status
  return error
}
