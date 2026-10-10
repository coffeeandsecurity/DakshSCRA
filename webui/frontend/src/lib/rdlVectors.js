import { flowEvidence, sourceKey } from './rdlReviewModels.js'

// Categories describe recorded input APIs, not verified external reachability.
export const VECTOR_CATEGORIES = [
  { key: 'request', label: 'Request data', description: 'Query strings, form fields and request bodies', mark: 'HTTP' },
  { key: 'uploads', label: 'File uploads', description: 'Uploaded files and multipart input', mark: 'FILE' },
  { key: 'state', label: 'Cookies & session', description: 'Cookie values and recorded session input', mark: 'STATE' },
  { key: 'headers', label: 'Request headers', description: 'Header values and request metadata', mark: 'HDR' },
  { key: 'process', label: 'Process & environment', description: 'Command-line, standard input and environment values', mark: 'ENV' },
  { key: 'data', label: 'File & data reads', description: 'Recorded filesystem and datastore input', mark: 'DATA' },
  { key: 'other', label: 'Other inputs', description: 'Parameters or symbols whose input origin is unresolved', mark: '?' },
]

export function classifyVector(source) {
  const symbol = String(source.symbol || source.explanation || '').trim()
  if (/^\$_FILES\b/i.test(symbol) || /\b(?:request|req)\.(?:files?|formfiles)\b|->(?:file|files)\b|\bIFormFile\b/i.test(symbol)) return { category: 'uploads', label: 'Upload' }
  if (/^\$_COOKIE\b|\b(?:request|req)\.cookies?\b|->cookie\b/i.test(symbol)) return { category: 'state', label: 'Cookie' }
  if (/^\$_SESSION\b|^(?:session|HttpContext\.Session)\b|\b(?:request|req)\.session\b/i.test(symbol)) return { category: 'state', label: 'Session' }
  if (/\b(?:request|req)\.headers?\b|->(?:header|getHeader|request_headers)\b|^\$_SERVER\[\s*['"]?HTTP_/i.test(symbol)) return { category: 'headers', label: 'Header' }
  if (/^\$_POST\b|^\$this->input->(?:post|post_get)\b|\b(?:request|req)\.(?:POST|form)\b/i.test(symbol)) return { category: 'request', label: 'Form / POST' }
  if (/^\$_GET\b|^\$this->input->(?:get|get_post)\b|\b(?:request|req)\.(?:GET|args|query|query_params)\b/i.test(symbol)) return { category: 'request', label: 'Query / GET' }
  if (/\b(?:request|req)\.(?:body|data|json|get_json)\b|->(?:getContent|json|raw_input_stream)\b/i.test(symbol)) return { category: 'request', label: 'Request body' }
  if (/\b(?:request|req)\.(?:params|path_params|route_params)\b/i.test(symbol)) return { category: 'request', label: 'Route parameter' }
  if (/^\$_REQUEST\b|^(?:request|req)\.(?:values|get|input|getParameter|getQueryString)\b|^\$request->(?:input|get|query|post|all|param)\b|^\$this->input->/i.test(symbol)) return { category: 'request', label: 'Request input' }
  if (/^\$_ENV\b|^(?:getenv|input|raw_input)\b|^(?:process\.(?:env|argv|stdin)|sys\.(?:argv|stdin)|os\.(?:environ|getenv)|System\.getenv)\b/i.test(symbol)) return { category: 'process', label: 'Process input' }
  if (/^(?:file_get_contents|fread|readfile)\b|\b(?:fs\.readFile|Files\.read|File\.Read)\w*/i.test(symbol)) return { category: 'data', label: 'File read' }
  return { category: 'other', label: 'Origin unresolved' }
}

export function collectVectors(items) {
  const groups = new Map()
  for (const item of items) {
    for (const source of flowEvidence(item.finding)) {
      if (source.predicate !== 'SOURCE' || source.matched === false) continue
      const key = sourceKey(source)
      if (!groups.has(key)) groups.set(key, { key, source, ...classifyVector(source), items: [] })
      const group = groups.get(key)
      if (!group.items.some(entry => entry.id === item.id)) group.items.push(item)
    }
  }
  return [...groups.values()].sort((a, b) => String(a.source.location?.path || '').localeCompare(String(b.source.location?.path || '')) || (a.source.location?.line || 0) - (b.source.location?.line || 0) || String(a.source.symbol || '').localeCompare(String(b.source.symbol || '')))
}
