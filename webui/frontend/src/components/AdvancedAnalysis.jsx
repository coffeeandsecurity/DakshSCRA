import { useEffect, useMemo, useRef, useState } from 'react'
import { artifactUrl } from '../api'

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low']
const SEVERITY_COLORS = {
  critical: '#f85149',
  high: '#e3842a',
  medium: '#d29922',
  low: '#3fb950',
}

function SummaryTabIcon() {
  return (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
      <path d="M3 4.75A1.75 1.75 0 0 1 4.75 3h10.5A1.75 1.75 0 0 1 17 4.75v10.5A1.75 1.75 0 0 1 15.25 17H4.75A1.75 1.75 0 0 1 3 15.25V4.75Zm3 .25a.75.75 0 0 0-.75.75v1.5c0 .414.336.75.75.75h1.5a.75.75 0 0 0 .75-.75v-1.5A.75.75 0 0 0 7.5 5H6Zm0 4a.75.75 0 0 0-.75.75v4.25c0 .414.336.75.75.75h1.5a.75.75 0 0 0 .75-.75V9.75A.75.75 0 0 0 7.5 9H6Zm4-3.25a.75.75 0 0 1 .75-.75h3.25a.75.75 0 0 1 0 1.5H10.75a.75.75 0 0 1-.75-.75Zm0 4a.75.75 0 0 1 .75-.75h3.25a.75.75 0 0 1 0 1.5H10.75a.75.75 0 0 1-.75-.75Zm0 4a.75.75 0 0 1 .75-.75h3.25a.75.75 0 0 1 0 1.5H10.75a.75.75 0 0 1-.75-.75Z" />
    </svg>
  )
}

function TaintTabIcon() {
  return (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
      <path fillRule="evenodd" d="M10 1.944A11.954 11.954 0 0 1 17.834 5C17.944 5.649 18 6.319 18 7c0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001A11.954 11.954 0 0 1 10 1.944Zm0 3.806a1 1 0 0 0-1 1V10a1 1 0 1 0 2 0V6.75a1 1 0 0 0-1-1Zm1 7.25a1 1 0 1 1-2 0 1 1 0 0 1 2 0Z" clipRule="evenodd" />
    </svg>
  )
}

function XrefTabIcon() {
  return (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
      <path fillRule="evenodd" d="M12.586 4.586a2 2 0 1 1 2.828 2.828l-3 3a2 2 0 0 1-2.828 0 1 1 0 0 0-1.414 1.414 4 4 0 0 0 5.656 0l3-3a4 4 0 1 0-5.656-5.656l-1.5 1.5a1 1 0 1 0 1.414 1.414l1.5-1.5Zm-5 5a2 2 0 0 1 2.828 0 1 1 0 1 0 1.414-1.414 4 4 0 0 0-5.656 0l-3 3a4 4 0 1 0 5.656 5.656l1.5-1.5a1 1 0 0 0-1.414-1.414l-1.5 1.5a2 2 0 1 1-2.828-2.828l3-3Z" clipRule="evenodd" />
    </svg>
  )
}

function VectorsTabIcon() {
  return (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
      <path fillRule="evenodd" d="M3.25 4A1.75 1.75 0 0 1 5 2.25h3A1.75 1.75 0 0 1 9.75 4v3A1.75 1.75 0 0 1 8 8.75H5A1.75 1.75 0 0 1 3.25 7V4ZM11.25 5.5a.75.75 0 0 1 .75-.75H16a.75.75 0 0 1 0 1.5H12a.75.75 0 0 1-.75-.75Zm.75 5.75a1.75 1.75 0 0 0-1.75 1.75v3A1.75 1.75 0 0 0 12 17.75h3A1.75 1.75 0 0 0 16.75 16v-3A1.75 1.75 0 0 0 15 11.25h-3ZM4 11.25a.75.75 0 0 0 0 1.5h4a.75.75 0 0 0 0-1.5H4Zm0 3.5a.75.75 0 0 0 0 1.5h4a.75.75 0 0 0 0-1.5H4Z" clipRule="evenodd" />
    </svg>
  )
}

function ReportTabIcon() {
  return (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
      <path fillRule="evenodd" d="M5.75 2.5A1.75 1.75 0 0 0 4 4.25v11.5c0 .966.784 1.75 1.75 1.75h8.5A1.75 1.75 0 0 0 16 15.75V7.56a1.75 1.75 0 0 0-.513-1.237l-2.81-2.81A1.75 1.75 0 0 0 11.44 3H5.75ZM7 8.25a.75.75 0 0 1 .75-.75h4.5a.75.75 0 0 1 0 1.5h-4.5A.75.75 0 0 1 7 8.25Zm0 3.5a.75.75 0 0 1 .75-.75h4.5a.75.75 0 0 1 0 1.5h-4.5a.75.75 0 0 1-.75-.75Zm0 3.5a.75.75 0 0 1 .75-.75h3a.75.75 0 0 1 0 1.5h-3a.75.75 0 0 1-.75-.75Z" clipRule="evenodd" />
    </svg>
  )
}

const GROUPS = [
  { id: 'external', label: 'External Inputs', match: /(request|query|params|body|form|cookie|header|stdin|argv|user_input)/i },
  { id: 'service', label: 'Service Boundaries', match: /(http|axios|fetch|curl|grpc|queue|kafka|socket|webhook|remote|service)/i },
  { id: 'datastore', label: 'Data Layer', match: /(sql|query|database|redis|mongo|file|serialize|deserialize|path traversal|storage)/i },
  { id: 'auth', label: 'Identity & Auth', match: /(auth|token|jwt|session|password|credential|oauth|role|permission)/i },
  { id: 'config', label: 'Environment', match: /(env|getenv|process\.env|config|settings|vault|secret_manager|dotenv|environment)/i },
]

const VECTOR_GROUPS = [
  { id: 'external', label: 'External Inputs', sublabel: 'User-Controlled', color: '#f85149' },
  { id: 'datastore', label: 'Data Layer', sublabel: 'Storage & Persistence', color: '#e3842a' },
  { id: 'service', label: 'Service Calls', sublabel: 'APIs & Integrations', color: '#d29922' },
  { id: 'auth', label: 'Identity & Auth', sublabel: 'Authentication & Sessions', color: '#a371f7' },
  { id: 'config', label: 'Environment', sublabel: 'Config & Secrets', color: '#58a6ff' },
  { id: 'code-path', label: 'Other Inputs', sublabel: 'Internal & Indirect', color: '#8b949e' },
]

const SOURCE_GROUPS = [
  { id: 'external', label: 'External Taints', sublabel: 'GET, POST, files, cookies, request data' },
  { id: 'internal', label: 'Internal Taints', sublabel: 'Session, DB, file, persisted state' },
  { id: 'service', label: 'Upstream Taints', sublabel: 'Service calls, remote responses, messages' },
  { id: 'config', label: 'Operator Taints', sublabel: 'Config, environment, secrets' },
]

const XREF_KIND_LABELS = {
  definition: 'Definition',
  callsite: 'Callsite',
  related: 'Related',
  xref: 'Reference',
  derived: 'Derived',
}

const NOISE_TOKENS = new Set([
  'this', 'self', 'true', 'false', 'null', 'none', 'undefined', 'class', 'public',
  'private', 'protected', 'static', 'return', 'const', 'let', 'var', 'function',
  'string', 'int', 'bool', 'void', 'object', 'array', 'dict', 'list', 'json',
])

const TOKEN_RE = /[$@]?[A-Za-z_][A-Za-z0-9_]{2,}/g
const INPUT_NOISE_TOKENS = new Set([
  'source', 'sink', 'direct', 'expression', 'reaches', 'assigned', 'value', 'input',
  'request', 'parameter', 'argument', 'tainted', 'received', 'unknown', 'location',
  'move_uploaded_file', 'mysqli_query', 'echo', 'print', 'query', 'call', 'boundary',
])
const ROLE_LABELS = {
  source: 'Tainted input received',
  param: 'Parameter carrying taint',
  assign: 'Assigned or reassigned',
  call: 'Passed into call',
  handoff: 'Cross-file handoff',
  sink: 'Final sink reached',
  termination: 'Trace stopped',
}

function shortPath(value) {
  if (!value) return ''
  const text = String(value).replace(/\\/g, '/')
  const parts = text.split('/').filter(Boolean)
  return parts.slice(-2).join('/') || text
}

function shortLocation(file, line) {
  const base = shortPath(file)
  if (!base) return line ? `line ${line}` : 'Unknown location'
  return line ? `${base}:${line}` : base
}

function normalizeTraceStatus(flow) {
  return String(flow?.trace_status || '').toLowerCase() === 'partial' ? 'partial' : 'complete'
}

function extractTaintSymbol(flow, path) {
  const candidates = []
  const externalCandidates = []
  for (const step of path || []) {
    for (const value of [step?.source_symbol, step?.symbol, ...(step?.variables || [])]) {
      const cleaned = String(value || '').trim().replace(/^[$@]/, '')
      if (!cleaned || cleaned === 'source') continue
      if (!candidates.includes(cleaned)) candidates.push(cleaned)
      if (String(step?.code || '').includes(`[source]`) && !externalCandidates.includes(cleaned)) externalCandidates.push(cleaned)
    }
  }
  const quoted = String(flow?.description || '').match(/`([^`]+)`/g) || []
  for (const raw of quoted) {
    const cleaned = raw.replace(/`/g, '').trim().replace(/^[$@]/, '')
    if (cleaned && !candidates.includes(cleaned)) candidates.push(cleaned)
  }
  return externalCandidates[0] || candidates[0] || 'tainted input'
}

function ensureSourceStep(flow) {
  let path = Array.isArray(flow?.path) ? [...flow.path] : []
  const primarySymbol = extractTaintSymbol(flow, path)

  if (!path.some((step) => String(step?.role || '').toLowerCase() === 'source')) {
    const first = path[0]
    const inferredCode = String(first?.role || '').toLowerCase() === 'param'
      ? `[inferred] The analyzer sees taint arriving at parameter \`${first?.code || primarySymbol}\`, but the exact framework receive step was not resolved statically.`
      : `[inferred] The analyzer sees \`${primarySymbol}\` as tainted at this boundary, but the original receive step was not resolved statically.`
    path = [{
      file: flow.source || first?.file || flow.file || '',
      line: first?.line || flow.source_line || '',
      role: 'source',
      code: inferredCode,
      inferred: true,
      source_symbol: primarySymbol,
      variables: [primarySymbol],
    }, ...path]
  }

  if (!path.some((step) => String(step?.role || '').toLowerCase() === 'sink')) {
    path = [...path, {
      file: flow.file || flow.sink_file || '',
      line: flow.line || flow.sink_line || '',
      role: 'sink',
      code: flow.sink || flow.title || '[resolved sink]',
    }]
  }

  return path
}

function summarizeTrace(flow, path) {
  const taintedInput = extractTaintSymbol(flow, path)
  const files = Array.from(new Set((path || []).map((step) => step.file).filter(Boolean)))
  const inferredSource = (path || []).some((step) => step.inferred)
  const termination = (flow.termination_nodes || [])[0] || null
  const firstStep = path?.[0] || null
  const sinkStep = [...(path || [])].reverse().find((step) => String(step?.role || '').toLowerCase() === 'sink') || path?.[path.length - 1] || null
  const assignments = (path || []).filter((step) => ['assign', 'param'].includes(String(step?.role || '').toLowerCase()))
  const calls = (path || []).filter((step) => ['call', 'handoff'].includes(String(step?.role || '').toLowerCase()))

  let inputSummary = `Tainted input: \`${taintedInput}\``
  if (inferredSource) inputSummary += '. The original receive point is inferred from downstream propagation.'

  const receiveSummary = firstStep
    ? `Received or first observed at ${shortLocation(firstStep.file, firstStep.line)}.`
    : 'The first receive step could not be resolved.'

  const propagationSummary = files.length > 1
    ? `Propagation crosses ${files.length} file(s): ${files.map((file) => shortPath(file)).join(' -> ')}.`
    : `Propagation remains within ${shortPath(files[0] || flow.file) || 'the current file'}.`

  const reassignmentSummary = assignments.length > 1
    ? `${assignments.length - 1} assignment or parameter handoff stage(s) were observed before the sink.`
    : 'No explicit reassignment stage was resolved before the sink.'

  const callSummary = calls.length
    ? `${calls.length} call or inter-file handoff stage(s) were resolved.`
    : 'No explicit call handoff stage was resolved.'

  const gapSummary = termination
    ? `Trace gap: ${String(termination.reason || 'unresolved').replace(/_/g, ' ')} at ${shortLocation(termination.file, termination.line)}.`
    : inferredSource
      ? 'Trace gap: the receive step is inferred because the framework or upstream caller could not be resolved statically.'
      : 'No unresolved trace gap is recorded for this flow.'

  const sinkSummary = sinkStep
    ? `Final sink reached at ${shortLocation(sinkStep.file, sinkStep.line)}.`
    : 'Final sink location could not be resolved.'

  return {
    taintedInput,
    inputSummary,
    receiveSummary,
    propagationSummary,
    reassignmentSummary,
    callSummary,
    gapSummary,
    sinkSummary,
    multiFile: files.length > 1,
    inferredSource,
  }
}

function extractSecurityTokens(text) {
  return (String(text || '').match(TOKEN_RE) || [])
    .map((token) => token.replace(/^[$@]/, '').toLowerCase())
    .filter((token) => token.length >= 3 && !NOISE_TOKENS.has(token) && !/^\d+$/.test(token))
}

function extractCallName(code) {
  const match = String(code || '').match(/([A-Za-z_$][A-Za-z0-9_$]*(?:(?:->|::|\.)[A-Za-z_$][A-Za-z0-9_$]*)*)\s*\(/)
  if (!match) return ''
  const raw = match[1] || ''
  return raw.split(/->|::|\./).filter(Boolean).pop() || ''
}

function inferInputSurface(flow) {
  const text = [
    flow.file,
    flow.function,
    flow.description,
    flow.explanation,
    ...(flow.path || []).map((step) => `${step.role || ''} ${step.code || ''} ${step.file || ''}`),
  ].join('\n')
  const pathText = (flow.path || []).map((step) => String(step.code || '')).join('\n')

  let channel = 'code-path'
  if (/(router\.|request|express|restcontroller|endpoint|@requestmapping|@getmapping|@postmapping)/i.test(text)) channel = 'web-app'
  if (channel === 'web-app' && (/\/api\//i.test(text) || /restcontroller/i.test(text))) channel = 'api'
  if (/(socket|listen\(|accept\(|recv\(|websocket|grpc|amqp|kafka)/i.test(text)) channel = 'network-app'
  if (/(getenv|process\.env|configuration|appsettings|vault|secret_manager|dotenv)/i.test(text)) channel = 'environment'
  if (/(\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|\$_FILES|\$this\s*->\s*input\s*->\s*(get|post)|request\s*\(\s*\)\s*->\s*(get|post|input|query)|Request\s*::\s*(get|post|input|query))/i.test(text)) {
    channel = 'web-app'
  }

  const methods = Array.from(new Set((text.match(/\b(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\b/gi) || []).map((m) => m.toUpperCase())))
  const params = []
  const addParam = (value) => {
    const cleaned = String(value || '').trim().replace(/^[$@]/, '')
    if (cleaned && !params.includes(cleaned)) params.push(cleaned)
  }
  for (const match of String(pathText).matchAll(/\$_(GET|POST|REQUEST|COOKIE|FILES)\s*\[\s*['"]([^'"]+)['"]\s*\]/gi)) addParam(match[2])
  for (const match of String(pathText).matchAll(/\$this\s*->\s*input\s*->\s*(get|post|cookie|get_post|post_get)\s*\(\s*['"]([^'"]+)['"]/gi)) addParam(match[2])
  for (const match of String(pathText).matchAll(/(?:request\s*\(\s*\)|Request)\s*(?:::\s*|->\s*)(input|get|post|query|cookie|header|route)\s*\(\s*['"]([^'"]+)['"]/gi)) addParam(match[2])

  const examples = []
  if (/\$_GET\s*\[\s*['"]/i.test(pathText)) methods.push('GET')
  if (/\$_POST\s*\[\s*['"]/i.test(pathText) || /\bmethod\s*=\s*["']post["']/i.test(text)) methods.push('POST')
  const methodList = Array.from(new Set(methods)).slice(0, 4)
  if (channel === 'api' || channel === 'web-app') {
    const fileStem = String(flow.file || '').split(/[\\/]/).pop()?.replace(/\.[^.]+$/, '') || 'endpoint'
    const fn = String(flow.function || 'action').toLowerCase()
    const uri = `/${fileStem}/${fn}`
    for (const method of (methodList.length ? methodList : ['GET', 'POST']).slice(0, 2)) {
      if (method === 'GET') examples.push(`${method} ${uri}?${params[0] || 'input'}=<PAYLOAD>`)
      else examples.push(`${method} ${uri} body: {"${params[0] || 'input'}":"<PAYLOAD>"}`)
    }
  } else if (channel === 'network-app') {
    examples.push(`Remote payload influences ${params[0] || 'input'} before the sink`)
  } else if (channel === 'environment') {
    examples.push(`Environment/config value influences ${params[0] || 'input'} before the sink`)
  } else {
    examples.push(`Code-path input candidate: ${params[0] || 'input'}`)
  }

  return {
    channel,
    methods: methodList,
    params: params.slice(0, 4),
    examples: examples.slice(0, 3),
  }
}

function extractIdentifiedInputs(flows) {
  const found = []
  const seen = new Set()
  const add = (name, origin, location, extra = {}) => {
    const cleaned = String(name || '').trim().replace(/^[$@]/, '')
    if (!cleaned) return
    const normalized = cleaned.toLowerCase()
    if (INPUT_NOISE_TOKENS.has(normalized)) return
    const key = [
      normalized,
      origin,
      location || '',
      extra.kind || '',
      extra.method || '',
      extra.action || '',
      extra.fieldType || '',
      extra.declaredAt || '',
    ].join('|')
    if (seen.has(key)) return
    seen.add(key)
    found.push({ name: cleaned, origin, location, ...extra })
  }

  for (const flow of flows || []) {
    const steps = flow.path || []
    for (const step of steps) {
      const code = String(step?.code || '')
      const location = shortLocation(step?.file, step?.line)
      for (const match of code.matchAll(/PHP (GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV) parameter `([^`]+)`/gi)) {
        add(match[2], match[1].toUpperCase(), location, { kind: match[1].toUpperCase() === 'FILES' ? 'upload' : 'request' })
      }
      for (const match of code.matchAll(/Request (GET|POST|INPUT|QUERY|COOKIE|HEADER|ROUTE|REQUEST|FILES?) (?:input|value) `([^`]+)`/gi)) {
        const origin = match[1].toUpperCase()
        add(match[2], origin, location, { kind: /FILES?/.test(origin) ? 'upload' : 'request' })
      }
      for (const match of code.matchAll(/form field `([^`]+)`/gi)) {
        add(match[1], 'FORM', location, { kind: 'form' })
      }
      for (const match of code.matchAll(/\$_(GET|POST|REQUEST|COOKIE|FILES)\s*\[\s*['"]([^'"]+)['"]\s*\]/gi)) {
        add(match[2], match[1].toUpperCase(), location, { kind: match[1].toUpperCase() === 'FILES' ? 'upload' : 'request' })
      }
      for (const match of code.matchAll(/Declared by form field `([^`]+)` in `([^`]+)` and submitted via ([A-Z]+) to `([^`]+)`\./gi)) {
        add(match[1], 'FORM', location, {
          kind: 'form',
          declaredAt: match[2],
          method: match[3].toUpperCase(),
          action: match[4],
        })
      }
      for (const match of code.matchAll(/Declared by form field `([^`]+)` in `([^`]+)` and submitted via ([A-Z]+) to `([^`]+)`\./gi)) {
        if (/PHP FILES parameter|Request FILES|uploaded file|move_uploaded_file/i.test(code)) {
          add(match[1], 'FILES', location, {
            kind: 'upload',
            declaredAt: match[2],
            method: match[3].toUpperCase(),
            action: match[4],
          })
        }
      }
      if (String(step?.role || '').toLowerCase() === 'source' && step?.source_symbol) {
        add(step.source_symbol, flow.input_surface?.methods?.[0] || flow.input_surface?.channel || 'source', location, { kind: 'tainted' })
      }
    }
    for (const param of flow.input_surface?.params || []) {
      add(param, flow.input_surface?.methods?.[0] || flow.input_surface?.channel || 'source', shortLocation(flow.source, flow.source_line), { kind: 'request' })
    }
  }

  return found.slice(0, 12)
}

function summarizeBasicFacts(flow, flows) {
  const inputs = extractIdentifiedInputs(flows)
  const methods = Array.from(new Set([
    ...(flow.input_surface?.methods || []).map((value) => String(value || '').toUpperCase()),
    ...inputs.map((item) => String(item.method || '').toUpperCase()).filter(Boolean),
    ...inputs.map((item) => (/^(GET|POST|PUT|PATCH|DELETE|FILES|FORM)$/.test(String(item.origin || '').toUpperCase()) ? String(item.origin || '').toUpperCase() : '')).filter((value) => value && value !== 'FORM' && value !== 'FILES'),
  ])).slice(0, 4)
  const endpoints = Array.from(new Set([
    ...(flow.input_surface?.uris || []),
    ...inputs.map((item) => item.action).filter(Boolean),
  ])).slice(0, 4)
  const requestParams = inputs.filter((item) => item.kind === 'request').map((item) => item.name)
  const formFields = inputs.filter((item) => item.kind === 'form').map((item) => item.name)
  const uploadFields = inputs.filter((item) => item.kind === 'upload').map((item) => item.name)
  const taintedInputs = Array.from(new Set([
    flow.trace_summary?.taintedInput,
    ...inputs.filter((item) => item.kind === 'tainted').map((item) => item.name),
  ].filter(Boolean)))
  const declaredForms = inputs
    .filter((item) => item.kind === 'form' && (item.action || item.declaredAt))
    .map((item) => ({
      name: item.name,
      method: item.method || '',
      action: item.action || '',
      declaredAt: item.declaredAt || '',
    }))

  return {
    methods,
    endpoints,
    requestParams: Array.from(new Set(requestParams)).slice(0, 8),
    formFields: Array.from(new Set(formFields)).slice(0, 8),
    uploadFields: Array.from(new Set(uploadFields)).slice(0, 8),
    taintedInputs: taintedInputs.slice(0, 8),
    declaredForms: declaredForms.slice(0, 6),
  }
}

function computeRisk(flow) {
  if (Number.isFinite(flow?.risk_score)) return Math.max(0, Math.min(100, Number(flow.risk_score)))
  const text = [
    flow.sink,
    flow.description,
    flow.explanation,
    ...(flow.path || []).map((step) => `${step.role || ''} ${step.code || ''}`),
  ].join(' ').toLowerCase()

  let score = 35
  if (/(eval|exec|runtime\.exec|process\.start|command execution|dynamic code)/.test(text)) score += 40
  else if (/(sql|query|xss|innerhtml|outerhtml|document\.write|template|redirect|ssrf)/.test(text)) score += 28
  else if (/(httpclient|webrequest|file write|deserialize|pickle|path traversal)/.test(text)) score += 16
  else score += 8

  const files = new Set((flow.path || []).map((step) => step.file).filter(Boolean))
  if (files.size > 1) score += 15
  const roles = new Set((flow.path || []).map((step) => String(step.role || '').toLowerCase()))
  if (roles.has('source')) score += 8
  if (roles.has('call')) score += 5
  score += Math.min((flow.path || []).length, 5) * 2
  return Math.min(score, 100)
}

function severityFromScore(score, rawSeverity) {
  const direct = String(rawSeverity || '').toLowerCase()
  if (SEVERITY_ORDER.includes(direct)) return direct
  if (score >= 85) return 'critical'
  if (score >= 70) return 'high'
  if (score >= 50) return 'medium'
  return 'low'
}

function deriveAttackVectors(flow) {
  const text = [
    flow.file,
    flow.function,
    flow.description,
    flow.explanation,
    flow.sink,
    ...(flow.path || []).map((step) => `${step.role || ''} ${step.code || ''}`),
  ].join('\n').toLowerCase()

  const out = []
  const add = (kind, label, reason, examples = []) => {
    if (!out.some((item) => item.kind === kind && item.label === label)) out.push({ kind, label, reason, examples })
  }

  const pathText = (flow.path || []).map((step) => String(step.code || '')).join('\n')
  const params = flow.input_surface?.params || []
  const examples = flow.input_surface?.examples || []

  if (/(query|string|req\.query|request\.args|getparameter)/.test(text)) add('external', 'Query string parameters', 'External user input: URL query values can be attacker-controlled and influence this path.', examples.length ? examples : params.map((param) => `query.${param}`))
  if (/(params|pathvariable|req\.params|route param)/.test(text)) add('external', 'Route or path parameters', 'External user input: route-bound parameters can be manipulated to drive this path to the sink.', params.map((param) => `path.${param}`))
  if (/(body|json|post|request\.body|req\.body|request\.json)/.test(text)) add('external', 'Request body fields', 'External user input: body content or JSON payload fields can influence this path.', examples)
  if (/(form|multipart|request\.form|uploadedfile|iformfile)/.test(text)) add('external', 'Form fields or uploads', 'External user input: submitted form values or uploaded content can influence this path.', params.map((param) => `form.${param}`))
  if (/(cookie|header|authorization|bearer)/.test(text)) add('external', 'Headers or cookies', 'External user input: request headers, cookies, or bearer material can influence this path.', params.map((param) => `header/cookie: ${param}`))
  if (/(stdin|argv|commandline)/.test(text)) add('external', 'CLI or local operator input', 'External user input: local command-line or stdin values can influence this path.', ['stdin', 'argv'])

  if (/(http|axios|fetch|curl|requests|urllib|webclient|grpc|webhook|queue|kafka|socket)/.test(text)) add('service', 'Remote services and API calls', 'Upstream service-controlled input: responses, messages, or remote request content can influence this path.', examples)
  if (/(endpoint|router\.|route\(|@requestmapping|@getmapping|@postmapping|express|restcontroller)/.test(text)) add('service', 'Application endpoints', 'External user input reaches internal application endpoints that seed this taint path.', examples)

  if (/(sql|query|select|insert|update|delete|redis|mongo)/.test(text)) add('datastore', 'Database-backed values', 'Internal trusted-but-influenceable input: database reads or query-driven values appear in the path and may already be tainted upstream.', ['query result', 'database row', 'record value'])
  if (/(file|fopen|readfile|writefile|path traversal|open\()/.test(text) || /(file|fopen|readfile|writefile|path traversal|open\()/.test(pathText)) add('datastore', 'Files, paths, and persisted content', 'Internal trusted-but-influenceable input: file names, file content, or persisted local state can influence this path.', ['file path', 'uploaded file', 'local content'])
  if (/(serialize|deserialize|pickle|yaml|json_decode)/.test(text)) add('datastore', 'Serialized or deserialized content', 'Internal trusted-but-influenceable input: deserialized payloads or serialized state can influence this path.', ['serialized object', 'deserialized payload'])

  if (/(auth|token|jwt|session|password|credential|role|permission|oauth)/.test(text)) add('auth', 'Identity, session, or credential data', 'Internal trusted-but-influenceable input: authentication and authorization data can steer the sink when sourced from tainted or replayable state.', ['token', 'session', 'credential', 'role'])

  if (/(env|getenv|process\.env|config|settings|vault|secret|dotenv|appsettings|configuration)/.test(text)) add('config', 'Config files, env vars, and secret stores', 'Operator/config-controlled input: environment and configuration-backed values can influence this path.', ['environment variable', 'config file', 'secret store'])

  if (!out.length) add('code-path', 'Internal or indirect code-path input', 'Internal trusted-but-influenceable input: the analyzer found a taint path, but the concrete external, upstream, or operator-controlled entry point remains weakly resolved.', examples)
  return out
}

function groupIdForFlow(flow) {
  const haystack = [
    flow.title,
    flow.description,
    flow.explanation,
    flow.source,
    flow.sink,
    flow.input_surface?.channel,
    ...(flow.attack_vectors || []).map((item) => `${item.kind} ${item.label} ${item.reason}`),
    ...(flow.path || []).map((step) => `${step.role || ''} ${step.code || ''}`),
  ].join(' ')
  const match = GROUPS.find((group) => group.match.test(haystack))
  return match?.id || 'other'
}

function buildPentestTargets(flows) {
  const grouped = new Map()
  for (const flow of flows) {
    const endpoint = flow.file || flow.source || 'Unknown file'
    const current = grouped.get(endpoint) || {
      endpoint,
      file: endpoint,
      channels: new Set(),
      methods: new Set(),
      examples: [],
      args: new Set(),
      flows: [],
    }
    current.channels.add(flow.input_surface?.channel || 'code-path')
    for (const method of flow.input_surface?.methods || []) current.methods.add(method)
    for (const example of flow.input_surface?.examples || []) {
      if (!current.examples.includes(example)) current.examples.push(example)
    }
    for (const value of [
      flow.trace_summary?.taintedInput,
      ...(flow.input_surface?.params || []),
      ...(flow.path || []).flatMap((step) => [step?.source_symbol, ...(step?.variables || [])]),
    ]) {
      const cleaned = String(value || '').trim().replace(/^[$@]/, '')
      if (cleaned && cleaned !== 'source') current.args.add(cleaned)
    }
    current.flows.push(flow)
    grouped.set(endpoint, current)
  }
  return Array.from(grouped.values())
    .map((item) => ({
      ...item,
      channels: Array.from(item.channels),
      methods: Array.from(item.methods),
      args: Array.from(item.args).slice(0, 10),
      examples: item.examples.slice(0, 4),
      flows: item.flows.slice(0, 6),
    }))
    .sort((a, b) => b.flows.length - a.flows.length || a.endpoint.localeCompare(b.endpoint))
}

function deriveSourceProfile(flow) {
  const pathText = (flow.path || []).map((step) => String(step.code || '')).join('\n')
  const input = flow.trace_summary?.taintedInput || extractTaintSymbol(flow, flow.path)
  const sourceFile = flow.source || flow.file || ''
  const sourceLine = flow.source_line || flow.line || ''

  const make = (group, kind, label) => ({
    group,
    kind,
    label,
    param: input,
    file: sourceFile,
    line: sourceLine,
    key: `${group}|${kind}|${label}|${sourceFile}|${sourceLine}`,
  })

  if (/\$_GET|\bGET\b/i.test(pathText)) return make('external', 'GET', `GET ${input}`)
  if (/\$_POST|\bPOST\b/i.test(pathText)) return make('external', 'POST', `POST ${input}`)
  if (/\$_REQUEST/i.test(pathText)) return make('external', 'REQUEST', `REQUEST ${input}`)
  if (/\$_FILES|uploaded file|move_uploaded_file/i.test(pathText)) return make('external', 'FILES', `FILES ${input}`)
  if (/\$_COOKIE|cookie/i.test(pathText)) return make('external', 'COOKIE', `COOKIE ${input}`)
  if (/\$_SESSION|\[session\]/i.test(pathText)) return make('internal', 'SESSION', `SESSION ${input}`)
  if (/\bdatabase\b|mysqli_|mysql_|pdo|select|insert|update|delete/i.test(pathText)) return make('internal', 'DATABASE', `DATABASE ${input}`)
  if (/\bfile\b|fopen|readfile|writefile|path|upload/i.test(pathText)) return make('internal', 'FILE', `FILE ${input}`)
  if (/\bhttp\b|axios|fetch|curl|socket|webhook|service/i.test(pathText)) return make('service', 'SERVICE', `SERVICE ${input}`)
  if (/\bconfig\b|process\.env|getenv|secret|vault|dotenv/i.test(pathText)) return make('config', 'CONFIG', `CONFIG ${input}`)
  return make('internal', 'CODE', `CODE ${input}`)
}

function detectTransformations(flow) {
  const rows = []
  for (const step of flow.path || []) {
    const code = String(step.code || '')
    const location = shortLocation(step.file, step.line)
    const add = (kind, label) => {
      if (!rows.some((row) => row.kind === kind && row.location === location && row.code === code)) {
        rows.push({ kind, label, location, code })
      }
    }
    if (/\btrim\s*\(|\bintval\s*\(|\bfloatval\s*\(/i.test(code)) add('normalize', 'Normalization or type conversion')
    if (/\bisset\s*\(|\bempty\s*\(|\bis_numeric\s*\(|\bfilter_var\s*\(|\bvalidate\b|\bpreg_match\s*\(/i.test(code)) add('validate', 'Validation or presence check')
    if (/\bhtmlspecialchars\s*\(|\bhtmlentities\s*\(|\bstrip_tags\s*\(|\bescape\b/i.test(code)) add('escape', 'Output escaping or sanitization')
    if (/\bmysqli_real_escape_string\s*\(|\bmysql_real_escape_string\s*\(|\baddslashes\s*\(/i.test(code)) add('sanitize', 'Input sanitization')
    if (/\bprepare\s*\(|\bbind_param\s*\(|\bbindvalue\s*\(/i.test(code)) add('parameterize', 'Parameterized query handling')
  }
  return rows
}

function collectTaintedArguments(flows) {
  const concrete = extractIdentifiedInputs(flows).map((item) => item.name)
  if (concrete.length) return concrete.slice(0, 8)

  const args = []
  const add = (value) => {
    const cleaned = String(value || '').trim().replace(/^[$@]/, '')
    if (!cleaned || INPUT_NOISE_TOKENS.has(cleaned.toLowerCase()) || args.includes(cleaned)) return
    args.push(cleaned)
  }
  for (const flow of flows || []) add(flow.trace_summary?.taintedInput)
  return args.slice(0, 8)
}

function buildSourceCatalog(flows) {
  const grouped = Object.fromEntries(SOURCE_GROUPS.map((group) => [group.id, []]))
  const byKey = new Map()
  for (const flow of flows) {
    const profile = deriveSourceProfile(flow)
    const existing = byKey.get(profile.key) || {
      ...profile,
      flows: [],
      files: new Set(),
      sinks: new Set(),
      transformations: [],
      receivePoints: new Set(),
      channels: new Set(),
    }
    existing.flows.push(flow)
    existing.files.add(shortLocation(flow.file, flow.line))
    existing.sinks.add(flow.sink || flow.title || 'sink')
    existing.receivePoints.add(shortLocation(flow.source || flow.file, flow.source_line || flow.line))
    existing.channels.add(flow.input_surface?.channel || 'code-path')
    for (const item of detectTransformations(flow)) {
      if (!existing.transformations.some((row) => row.kind === item.kind && row.location === item.location && row.code === item.code)) {
        existing.transformations.push(item)
      }
    }
    byKey.set(profile.key, existing)
  }
  for (const item of byKey.values()) {
    grouped[item.group].push({
      ...item,
      files: Array.from(item.files),
      sinks: Array.from(item.sinks),
      receivePoints: Array.from(item.receivePoints),
      channels: Array.from(item.channels),
      args: collectTaintedArguments(item.flows),
      transformations: item.transformations.slice(0, 6),
    })
  }
  for (const key of Object.keys(grouped)) {
    grouped[key].sort((a, b) => b.flows.length - a.flows.length || a.label.localeCompare(b.label))
  }
  return grouped
}

function flowKey(flow) {
  return [
    flow.sink,
    flow.file,
    flow.function,
    flow.line,
    normalizeTraceStatus(flow),
    ...(flow.path || []).map((step) => `${step.file}|${step.line}|${step.role}|${String(step.code || '').trim()}`),
  ].join('###')
}

function buildGraphModel(flow) {
  const pathNodes = (flow.path || []).map((step, index) => ({
    id: `p-${index}`,
    kind: 'path',
    role: String(step.role || 'step').toLowerCase(),
    label: String(step.role || 'step').toUpperCase(),
    file: step.file || '',
    line: step.line || '',
    sublabel: shortLocation(step.file, step.line),
    code: String(step.code || '').trim(),
    index,
  }))

  let xrefNodes = (flow.xref || []).slice(0, 12).map((xref, index) => ({
    id: `x-${index}`,
    kind: 'xref',
    role: String(xref.type || 'xref').toLowerCase(),
    label: xref.resolved_name || xref.symbol || 'xref',
    file: xref.file || '',
    line: xref.line || '',
    sublabel: shortLocation(xref.file, xref.line),
    context: xref.context || '',
    index,
  }))

  if (!xrefNodes.length) {
    const derived = []
    const seen = new Set()
    pathNodes.forEach((node, index) => {
      const callName = extractCallName(node.code)
      const tokens = [
        callName,
        ...extractSecurityTokens(`${node.label} ${node.code}`),
      ].filter(Boolean)
      for (const token of tokens) {
        const key = `${node.file}|${node.line}|${token}`
        if (seen.has(key)) continue
        seen.add(key)
        derived.push({
          id: `d-${index}-${derived.length}`,
          kind: 'xref',
          role: 'derived',
          label: token,
          file: node.file,
          line: node.line,
          sublabel: shortLocation(node.file, node.line),
          context: node.code,
          index: derived.length,
          derivedFromPath: true,
        })
        if (derived.length >= 12) break
      }
    })
    xrefNodes = derived
  }

  return { pathNodes, xrefNodes }
}

function compactPathLabel(code, fallback) {
  const text = String(code || '').trim().replace(/\s+/g, ' ')
  if (!text) return fallback || 'step'
  return text.length > 44 ? `${text.slice(0, 44)}...` : text
}

function xrefAnchorIndex(xrefNode, pathNodes) {
  const combined = `${xrefNode.label} ${xrefNode.context}`.toLowerCase()
  const exact = pathNodes.findIndex((node) => combined.includes(String(node.code || '').toLowerCase()) && String(node.code || '').trim())
  if (exact >= 0) return exact

  const tokens = extractSecurityTokens(combined)
  if (!tokens.length) return Math.max(pathNodes.length - 1, 0)

  let bestIndex = Math.max(pathNodes.length - 1, 0)
  let bestScore = 0
  pathNodes.forEach((node, index) => {
    const nodeText = `${node.label} ${node.sublabel} ${node.code}`.toLowerCase()
    let score = 0
    for (const token of tokens) {
      if (nodeText.includes(token)) score += 1
    }
    if (score >= bestScore) {
      bestScore = score
      bestIndex = index
    }
  })
  return bestIndex
}

function buildModel(analysis) {
  const results = Array.isArray(analysis?.results) ? analysis.results : []
  const taintTargets = []
  const heuristicTargets = []
  const rawFlows = []

  for (const result of results) {
    const target = result.target || result.platform || ''
    if (result.engine === 'dataflow_controlflow') {
      if (target && !taintTargets.includes(target)) taintTargets.push(target)
      for (const finding of result.findings || []) {
        if (finding.analysis_kind !== 'taint_flow') continue
        rawFlows.push({ ...finding, target })
      }
    } else if (target && !heuristicTargets.includes(target)) {
      heuristicTargets.push(target)
    }
  }

  const normalized = rawFlows.map((flow) => {
    const path = ensureSourceStep(flow)
    const risk_score = computeRisk({ ...flow, path })
    const severity = severityFromScore(risk_score, flow.severity)
    const input_surface = flow.input_surface || inferInputSurface({ ...flow, path })
    const attack_vectors = (flow.attack_vectors || []).length ? flow.attack_vectors : deriveAttackVectors({ ...flow, path, input_surface })
    const cross_file = new Set(path.map((step) => step.file).filter(Boolean)).size > 1
    const graph = buildGraphModel({ ...flow, path, input_surface, attack_vectors })
    const sourceStep = path.find((step) => String(step.role || '').toLowerCase() === 'source') || path[0]
    const sinkStep = [...path].reverse().find((step) => String(step.role || '').toLowerCase() === 'sink') || path[path.length - 1]
    const trace_summary = summarizeTrace(flow, path)

    return {
      ...flow,
      path,
      risk_score,
      severity,
      input_surface,
      attack_vectors,
      cross_file,
      trace_status: normalizeTraceStatus(flow),
      graph,
      trace_summary,
      source: flow.source || sourceStep?.file || '',
      source_line: flow.source_line || sourceStep?.line || '',
      sink: flow.sink || sinkStep?.code || sinkStep?.file || '',
      sink_file: sinkStep?.file || flow.file || '',
      sink_line: sinkStep?.line || flow.line || '',
    }
  })

  const deduped = new Map()
  for (const flow of normalized) {
    const key = flowKey(flow)
    const prev = deduped.get(key)
    if (!prev || flow.risk_score > prev.risk_score) deduped.set(key, flow)
  }

  const flows = Array.from(deduped.values())
    .sort((a, b) => (
      b.risk_score - a.risk_score ||
      Number(b.cross_file) - Number(a.cross_file) ||
      (b.path?.length || 0) - (a.path?.length || 0) ||
      String(a.file || '').localeCompare(String(b.file || '')) ||
      Number(a.line || 0) - Number(b.line || 0)
    ))
    .map((flow, index) => ({ ...flow, rank: index + 1, groupId: groupIdForFlow(flow) }))

  const stats = {
    total: flows.length,
    complete: flows.filter((flow) => flow.trace_status === 'complete').length,
    partial: flows.filter((flow) => flow.trace_status === 'partial').length,
    crossFile: flows.filter((flow) => flow.cross_file).length,
  }

  for (const level of SEVERITY_ORDER) stats[level] = flows.filter((flow) => flow.severity === level).length

  const vectorMap = new Map()
  for (const flow of flows) {
    for (const vector of flow.attack_vectors || []) {
      const key = `${vector.kind}:::${vector.label}`
      const existing = vectorMap.get(key) || { ...vector, count: 0, flows: [] }
      existing.count += 1
      if (existing.flows.length < 5) existing.flows.push(flow)
      vectorMap.set(key, existing)
    }
  }

  const vectors = Array.from(vectorMap.values()).sort((a, b) => b.count - a.count)
  const vectorGroups = Object.fromEntries(VECTOR_GROUPS.map((group) => [group.id, []]))
  for (const vector of vectors) {
    const bucket = vectorGroups[vector.kind] ? vector.kind : 'code-path'
    vectorGroups[bucket].push(vector)
  }
  const pentestTargets = buildPentestTargets(flows)
  const sourceCatalog = buildSourceCatalog(flows)
  return { flows, stats, vectors, vectorGroups, pentestTargets, sourceCatalog, taintTargets, heuristicTargets }
}

function OverviewStat({ label, value, accent, sub }) {
  return (
    <div className="aa-stat-card" style={{ '--aa-accent': accent }}>
      <div className="aa-stat-value">{value}</div>
      <div className="aa-stat-label">{label}</div>
      {sub ? <div className="aa-stat-sub">{sub}</div> : null}
    </div>
  )
}

function CoverageNotice({ taintTargets, heuristicTargets }) {
  if (!heuristicTargets.length) return null
  return (
    <div className="aa-coverage">
      <div className="aa-coverage-title">Advanced Analysis uses taint-engine data where available</div>
      <div className="aa-coverage-copy">
        {taintTargets.length ? `Analyzed: ${taintTargets.join(', ')}. ` : ''}
        Heuristic-only platforms still present in the scan: {heuristicTargets.join(', ')}.
      </div>
    </div>
  )
}

function FlowList({ flows, selectedId, onSelect }) {
  return (
    <div className="aa-list">
      {flows.map((flow) => (
        <button
          key={flowKey(flow)}
          className={`aa-list-item${selectedId === flowKey(flow) ? ' active' : ''}`}
          onClick={() => onSelect(flowKey(flow))}
          style={{ '--aa-item-accent': SEVERITY_COLORS[flow.severity] }}
        >
          <div className="aa-list-top">
            <span className={`aa-pill severity ${flow.severity}`}>{flow.severity}</span>
            <span className={`aa-pill trace ${flow.trace_status}`}>{flow.trace_status}</span>
            <span className="aa-list-rank">#{flow.rank}</span>
          </div>
          <div className="aa-list-title">{flow.title || flow.sink || 'Taint flow'}</div>
          <div className="aa-list-meta">
            <span>{shortLocation(flow.file, flow.line)}</span>
            {flow.function ? <span>{flow.function}</span> : null}
            {flow.cross_file ? <span>cross-file</span> : null}
            <span>{flow.risk_score}</span>
          </div>
        </button>
      ))}
    </div>
  )
}

function SourceCatalogList({ sourceCatalog, selectedFlow, onSelectFlow }) {
  const [activeGroup, setActiveGroup] = useState('external')
  const flatEntries = SOURCE_GROUPS.flatMap((group) => (sourceCatalog?.[group.id] || []))
  const selectedSourceKey = selectedFlow ? deriveSourceProfile(selectedFlow).key : flatEntries[0]?.key

  useEffect(() => {
    const resolved = SOURCE_GROUPS.find((group) => (sourceCatalog?.[group.id] || []).some((item) => item.key === selectedSourceKey))?.id
    if (resolved) setActiveGroup(resolved)
  }, [selectedSourceKey, sourceCatalog])

  const visible = sourceCatalog?.[activeGroup] || []

  return (
    <div className="aa-source-shell">
      <div className="aa-source-tabs">
        {SOURCE_GROUPS.map((group) => {
          const count = sourceCatalog?.[group.id]?.length || 0
          return (
            <button
              key={group.id}
              className={`aa-source-tab${activeGroup === group.id ? ' active' : ''}${count === 0 ? ' empty' : ''}`}
              onClick={() => setActiveGroup(group.id)}
              disabled={count === 0}
            >
              <span className="aa-source-tab-title">{group.label}</span>
              <span className="aa-source-tab-sub">{group.sublabel}</span>
              <span className="aa-source-tab-count">{count}</span>
            </button>
          )
        })}
      </div>
      <div className="aa-source-list">
        {visible.map((entry) => (
          <button
            key={entry.key}
            className={`aa-source-item${selectedSourceKey === entry.key ? ' active' : ''}`}
            onClick={() => entry.flows?.[0] && onSelectFlow(flowKey(entry.flows[0]))}
          >
            <div className="aa-source-item-title">{entry.label}</div>
            <div className="aa-source-item-sub">{shortLocation(entry.file, entry.line)}</div>
            {entry.args?.length ? (
              <div className="aa-tag-wrap aa-source-item-tags">
                {entry.args.slice(0, 4).map((arg) => (
                  <span key={`${entry.key}-${arg}`} className="aa-tag">{arg}</span>
                ))}
              </div>
            ) : null}
            <div className="aa-source-item-meta">
              <span>{entry.kind}</span>
              <span>{entry.flows.length} trace{entry.flows.length === 1 ? '' : 's'}</span>
              <span>{entry.sinks.length} sink{entry.sinks.length === 1 ? '' : 's'}</span>
            </div>
          </button>
        ))}
      </div>
    </div>
  )
}

function describeStep(step, nextStep) {
  const role = String(step?.role || '').toLowerCase()
  const sourceSymbol = String(step?.source_symbol || '').replace(/^[$@]/, '')
  const targetSymbol = String(step?.target_symbol || '').replace(/^[$@]/, '')
  const currentFile = String(step?.file || '')
  const nextFile = String(nextStep?.file || '')
  const crossesFile = currentFile && nextFile && currentFile !== nextFile

  if (role === 'source') {
    return step?.inferred
      ? 'Original receive point was not fully resolved. The analyzer inferred taint entering here from later usage.'
      : `Tainted input ${sourceSymbol ? `\`${sourceSymbol}\`` : 'value'} is received here.`
  }
  if (role === 'param') {
    return sourceSymbol && targetSymbol && sourceSymbol !== targetSymbol
      ? `Taint moves from \`${sourceSymbol}\` into parameter \`${targetSymbol}\`.`
      : `A function or method parameter carries this taint forward.`
  }
  if (role === 'assign') {
    return sourceSymbol && targetSymbol && sourceSymbol !== targetSymbol
      ? `Tainted value from \`${sourceSymbol}\` is assigned or rewritten into \`${targetSymbol}\`.`
      : 'Tainted value is assigned or reused in this step.'
  }
  if (role === 'call') {
    return 'Tainted value is passed into a call at this step.'
  }
  if (role === 'handoff') {
    return crossesFile
      ? `Taint crosses from ${shortPath(currentFile)} into ${shortPath(nextFile)}.`
      : 'Taint is handed off across a call boundary.'
  }
  if (role === 'sink') {
    return 'This is the final sink where the tainted value lands.'
  }
  if (role === 'termination') {
    return 'Tracing stops here because the next propagation step could not be resolved.'
  }
  return 'Taint is still present and used at this step.'
}

function transformationLabelForStep(step) {
  const code = String(step?.code || '')
  if (/\bprepare\s*\(|\bbind_param\s*\(|\bbindvalue\s*\(/i.test(code)) return 'Parameterized handling'
  if (/\bhtmlspecialchars\s*\(|\bhtmlentities\s*\(|\bstrip_tags\s*\(|\bescape\b/i.test(code)) return 'Output escaping or sanitization'
  if (/\bmysqli_real_escape_string\s*\(|\bmysql_real_escape_string\s*\(|\baddslashes\s*\(/i.test(code)) return 'Input sanitization'
  if (/\bisset\s*\(|\bempty\s*\(|\bis_numeric\s*\(|\bfilter_var\s*\(|\bvalidate\b|\bpreg_match\s*\(/i.test(code)) return 'Validation or presence check'
  if (/\btrim\s*\(|\bintval\s*\(|\bfloatval\s*\(/i.test(code)) return 'Normalization or type conversion'
  return ''
}

function SimpleTraceGraph({ flow }) {
  const transformations = detectTransformations(flow)
  const steps = flow.path || []

  return (
    <div className="aa-simple-graph">
      <div className="aa-simple-timeline">
        {steps.map((step, index) => {
          const role = String(step.role || '').toLowerCase()
          const nextStep = steps[index + 1]
          const transform = transformationLabelForStep(step)
          const sourceName = String(step.source_symbol || '').replace(/^[$@]/, '')
          const targetName = String(step.target_symbol || '').replace(/^[$@]/, '')
          return (
            <div key={`${step.file || 'step'}-${step.line || index}-${index}`} className={`aa-simple-step ${role || 'step'}`}>
              <div className="aa-simple-step-rail">
                <span className="aa-simple-step-dot" />
                {index < steps.length - 1 ? <span className="aa-simple-step-line" /> : null}
              </div>
              <div className="aa-simple-step-card">
                <div className="aa-simple-step-top">
                  <span className="aa-simple-step-index">Step {index + 1}</span>
                  <span className="aa-simple-step-role">{ROLE_LABELS[role] || String(step.role || 'step')}</span>
                  {step.inferred ? <span className="aa-pill plain">inferred</span> : null}
                  {String(step.file || '') !== String(nextStep?.file || '') && nextStep?.file ? <span className="aa-pill plain">cross-file next</span> : null}
                </div>
                <div className="aa-simple-step-loc">{shortLocation(step.file, step.line)}</div>
                <div className="aa-simple-step-copy">{describeStep(step, nextStep)}</div>
                {step.source_symbol || step.target_symbol || (step.variables || []).length ? (
                  <div className="aa-tag-wrap aa-simple-step-tags">
                    {sourceName ? <span className="aa-tag">source {sourceName}</span> : null}
                    {targetName && targetName !== sourceName ? <span className="aa-tag">target {targetName}</span> : null}
                    {(step.variables || [])
                      .map((value) => String(value || '').replace(/^[$@]/, ''))
                      .filter((value, idx, list) => value && value !== sourceName && value !== targetName && list.indexOf(value) === idx)
                      .slice(0, 4)
                      .map((value) => <span key={`${index}-${value}`} className="aa-tag">arg {value}</span>)}
                  </div>
                ) : null}
                {transform ? <div className="aa-simple-step-transform">{transform}</div> : null}
                <code>{step.code || 'No analyzer code detail recorded for this step.'}</code>
              </div>
            </div>
          )
        })}
      </div>
      <div className="aa-simple-transform-box">
        <div className="aa-simple-stage-title">Resolved transformations on this path</div>
        {transformations.length ? (
          <div className="aa-simple-mini-list">
            {transformations.map((item) => (
              <div key={`${item.kind}-${item.location}-${item.code}`} className="aa-simple-mini-item">
                <strong>{item.label}</strong>
                <span>{item.location}</span>
                <code>{item.code}</code>
              </div>
            ))}
          </div>
        ) : (
          <div className="aa-simple-mini-item">
            <span>No validation, parameterization, or output escaping step was resolved on this path.</span>
          </div>
        )}
      </div>
    </div>
  )
}

function TaintWorkspace({ sourceCatalog, selectedFlow, onSelectFlow, artifactIndex, onOpenReport }) {
  if (!selectedFlow) return null
  const selectedSourceKey = deriveSourceProfile(selectedFlow).key
  const selectedSource = SOURCE_GROUPS.flatMap((group) => sourceCatalog?.[group.id] || []).find((item) => item.key === selectedSourceKey)
  const sourceFlows = selectedSource?.flows || [selectedFlow]
  const transformations = detectTransformations(selectedFlow)
  const sourceArgs = selectedSource?.args?.length ? selectedSource.args : collectTaintedArguments(sourceFlows)
  const identifiedInputs = extractIdentifiedInputs(sourceFlows)
  const basicFacts = summarizeBasicFacts(selectedFlow, sourceFlows)

  return (
    <div className="aa-taint-workspace">
      <div className="aa-taint-sidebar">
        <div className="aa-sidebar-title">Tainted Sources</div>
        <SourceCatalogList sourceCatalog={sourceCatalog} selectedFlow={selectedFlow} onSelectFlow={onSelectFlow} />
      </div>
      <div className="aa-taint-main">
        <div className="aa-detail-card">
          <div className="aa-detail-header">
            <div>
              <div className="aa-detail-title">{shortPath(selectedFlow.source || selectedFlow.file) || selectedSource?.label || selectedFlow.trace_summary?.taintedInput}</div>
              <div className="aa-detail-sub">{shortLocation(selectedSource?.file || selectedFlow.source || selectedFlow.file, selectedSource?.line || selectedFlow.source_line || selectedFlow.line)} · {SOURCE_GROUPS.find((group) => group.id === selectedSource?.group)?.label || 'Taint source'}</div>
            </div>
            <div className="aa-pill-row">
              <span className="aa-pill plain">{sourceFlows.length} trace{sourceFlows.length === 1 ? '' : 's'}</span>
              <span className="aa-pill plain">{selectedSource?.sinks?.length || 1} sink{(selectedSource?.sinks?.length || 1) === 1 ? '' : 's'}</span>
            </div>
          </div>
          <div className="aa-taint-overview">
            <div className="aa-taint-overview-main">
              <div className="aa-compact-card">
                <div className="aa-compact-card-title">Selected file</div>
                <code>{selectedFlow.source || selectedFlow.file || 'Unknown file'}</code>
              </div>
              <div className="aa-compact-card">
                <div className="aa-compact-card-title">Final sink</div>
                <strong>{shortLocation(selectedFlow.sink_file, selectedFlow.sink_line)}</strong>
                <code>{selectedFlow.sink || selectedFlow.title || 'sink'}</code>
              </div>
            </div>
            <div className="aa-taint-overview-side">
              <div className="aa-compact-card">
                <div className="aa-compact-card-title">Request surface</div>
                <div className="aa-compact-fact">
                  <span>Methods</span>
                  {basicFacts.methods.length ? (
                    <div className="aa-tag-wrap">
                      {basicFacts.methods.map((method) => <span key={method} className="aa-tag">{method}</span>)}
                    </div>
                  ) : (
                    <strong>Not resolved</strong>
                  )}
                </div>
                <div className="aa-compact-fact">
                  <span>Endpoint</span>
                  {basicFacts.endpoints.length ? (
                    <div className="aa-inline-code-list">
                      {basicFacts.endpoints.map((endpoint) => <code key={endpoint}>{endpoint}</code>)}
                    </div>
                  ) : (
                    <strong>Not resolved</strong>
                  )}
                </div>
              </div>
            </div>
          </div>
          <div className="aa-source-argument-strip aa-source-argument-strip-compact">
            <div className="aa-source-argument-title">Input mapping</div>
            <div className="aa-compact-section-grid">
              <div className="aa-compact-card">
                <div className="aa-compact-card-title">Tainted inputs</div>
                {basicFacts.taintedInputs.length ? (
                  <div className="aa-tag-wrap">
                    {basicFacts.taintedInputs.map((value) => <span key={value} className="aa-tag">{value}</span>)}
                  </div>
                ) : (
                  <div className="aa-input-empty">No concrete tainted input name resolved.</div>
                )}
              </div>
              <div className="aa-compact-card">
                <div className="aa-compact-card-title">Request parameters</div>
                {basicFacts.requestParams.length ? (
                  <div className="aa-tag-wrap">
                    {basicFacts.requestParams.map((value) => <span key={value} className="aa-tag">{value}</span>)}
                  </div>
                ) : (
                  <div className="aa-input-empty">No request parameter name resolved for this file.</div>
                )}
              </div>
              <div className="aa-compact-card">
                <div className="aa-compact-card-title">Form fields</div>
                {basicFacts.formFields.length ? (
                  <div className="aa-tag-wrap">
                    {basicFacts.formFields.map((value) => <span key={value} className="aa-tag">{value}</span>)}
                  </div>
                ) : (
                  <div className="aa-input-empty">No form field mapping resolved for this file.</div>
                )}
              </div>
              <div className="aa-compact-card">
                <div className="aa-compact-card-title">Upload fields</div>
                {basicFacts.uploadFields.length ? (
                  <div className="aa-tag-wrap">
                    {basicFacts.uploadFields.map((value) => <span key={value} className="aa-tag">{value}</span>)}
                  </div>
                ) : (
                  <div className="aa-input-empty">No upload field name resolved for this file.</div>
                )}
              </div>
            </div>
          </div>
          {basicFacts.declaredForms.length ? (
            <div className="aa-source-argument-strip aa-source-argument-strip-compact">
              <div className="aa-source-argument-title">Resolved form mapping</div>
              <div className="aa-compact-section-grid">
                {basicFacts.declaredForms.map((item) => (
                  <div key={`${item.name}-${item.method}-${item.action}-${item.declaredAt}`} className="aa-compact-card">
                    <strong>{item.name}</strong>
                    <span>{item.method || 'METHOD ?'} {item.action || 'action unresolved'}</span>
                    {item.declaredAt ? <span>Declared at {item.declaredAt}</span> : null}
                  </div>
                ))}
              </div>
            </div>
          ) : null}
          {identifiedInputs.length ? (
            <div className="aa-source-argument-strip aa-source-argument-strip-compact">
              <div className="aa-source-argument-title">Raw identified inputs</div>
              <div className="aa-compact-section-grid aa-identified-input-grid">
                {identifiedInputs.map((item) => (
                  <div key={`${item.origin}-${item.name}-${item.location || ''}`} className="aa-compact-card">
                    <strong>{item.name}</strong>
                    <span>{item.origin}</span>
                    {item.location ? <span>{item.location}</span> : null}
                  </div>
                ))}
              </div>
            </div>
          ) : null}
          {sourceArgs.length ? (
            <div className="aa-source-argument-strip aa-source-argument-strip-compact">
              <div className="aa-source-argument-title">Other tainted arguments</div>
              <div className="aa-tag-wrap">
                {sourceArgs.map((arg) => (
                  <span key={`${selectedSource?.key || 'source'}-${arg}`} className="aa-tag">{arg}</span>
                ))}
              </div>
            </div>
          ) : null}
          <div className="aa-simple-summary-grid">
            <div className="aa-mini-card">
              <strong>Where received</strong>
              <span>{selectedFlow.trace_summary?.receiveSummary}</span>
              {selectedSource?.receivePoints?.length ? <span>Receive points: {selectedSource.receivePoints.join(', ')}</span> : null}
              {(selectedFlow.input_surface?.examples || []).slice(0, 2).map((example) => <code key={example}>{example}</code>)}
            </div>
            <div className="aa-mini-card">
              <strong>Where traced</strong>
              <span>{selectedFlow.trace_summary?.propagationSummary}</span>
              <span>{selectedFlow.trace_summary?.callSummary}</span>
            </div>
            <div className="aa-mini-card">
              <strong>Where it lands</strong>
              <span>{selectedFlow.trace_summary?.sinkSummary}</span>
              <code>{selectedFlow.sink || selectedFlow.title || 'sink'}</code>
            </div>
          </div>
        </div>

        <div className="aa-detail-card">
          <div className="aa-card-title">Trace Story</div>
          <SimpleTraceGraph flow={selectedFlow} />
          {selectedFlow.trace_summary?.gapSummary ? <div className="aa-trace-gap">{selectedFlow.trace_summary.gapSummary}</div> : null}
        </div>

        <div className="aa-detail-grid">
          <div className="aa-detail-card">
            <div className="aa-card-title">Observed Sinks</div>
            <div className="aa-mini-list">
              {sourceFlows.map((flow) => (
                <button key={flowKey(flow)} className={`aa-mini-card aa-flow-pick${flowKey(flow) === flowKey(selectedFlow) ? ' active' : ''}`} onClick={() => onSelectFlow(flowKey(flow))}>
                  <strong>{flow.title || flow.sink || 'sink'}</strong>
                  <span>{shortLocation(flow.sink_file, flow.sink_line)}</span>
                  <span>{flow.trace_status} · {flow.severity} · score {flow.risk_score}</span>
                </button>
              ))}
            </div>
          </div>
          <div className="aa-detail-card">
            <div className="aa-card-title">Transformations</div>
            <div className="aa-mini-list">
              {transformations.length ? transformations.map((item) => (
                <div key={`${item.kind}-${item.location}-${item.code}`} className="aa-mini-card">
                  <strong>{item.label}</strong>
                  <span>{item.location}</span>
                  <code>{item.code}</code>
                </div>
              )) : (
                <div className="aa-mini-card">
                  <strong>No transformation resolved</strong>
                  <span>The current trace did not resolve input validation, parameterization, or escaping on this path.</span>
                </div>
              )}
            </div>
          </div>
        </div>

        {(artifactIndex?.other_html || []).some((item) => item.toLowerCase().endsWith('analysis.html')) ? (
          <div className="aa-actions">
            <button className="btn btn-secondary btn-sm" onClick={onOpenReport}>Open In Analyzer Report</button>
          </div>
        ) : null}
      </div>
    </div>
  )
}

function PathGraph({ flow }) {
  if (!flow) return null
  return (
    <div className="aa-graph-board">
      <div className="aa-board-title">Graphical taint trace</div>
      <div className="aa-trace-intro">
        <strong>{flow.trace_summary?.inputSummary}</strong>
        <span>{flow.trace_summary?.gapSummary}</span>
      </div>
      <div className="aa-path-track clearer">
        {(flow.path || []).map((step, index) => {
          const role = String(step.role || 'step').toLowerCase()
          const tone = role === 'source' ? 'source' : role === 'sink' ? 'sink' : role === 'call' ? 'call' : role === 'handoff' ? 'handoff' : role === 'termination' ? 'termination' : 'step'
          return (
            <div key={`${step.file || 'step'}-${step.line || index}-${index}`} className="aa-path-segment">
              <div className={`aa-path-node ${tone}`}>
                <div className="aa-path-node-head">
                  <span className="aa-path-node-role">{ROLE_LABELS[role] || role.toUpperCase()}</span>
                  <span className="aa-path-node-loc">{shortLocation(step.file, step.line)}</span>
                </div>
                <div className="aa-path-node-meta">
                  {step.source_symbol ? <span className="aa-tag">input {step.source_symbol}</span> : null}
                  {step.target_symbol && step.target_symbol !== step.source_symbol ? <span className="aa-tag">target {step.target_symbol}</span> : null}
                  {step.inferred ? <span className="aa-tag">inferred</span> : null}
                </div>
                {step.code ? <pre className="aa-path-node-code">{String(step.code).trim()}</pre> : null}
              </div>
              {index < flow.path.length - 1 ? <div className="aa-path-arrow">{String(step.file || '') !== String(flow.path[index + 1]?.file || '') ? 'cross-file →' : '→'}</div> : null}
            </div>
          )
        })}
      </div>
    </div>
  )
}

function FlowDetail({ flow, artifactIndex, onOpenReport }) {
  if (!flow) {
    return (
      <div className="empty-state" style={{ padding: '40px 20px' }}>
        <div className="empty-title">No flow selected</div>
        <div className="empty-msg">Choose a ranked taint flow from the left to inspect it in graphical detail.</div>
      </div>
    )
  }

  return (
    <div className="aa-detail">
      <div className="aa-detail-header">
        <div>
          <div className="aa-detail-title">{flow.title || flow.sink || 'Taint flow'}</div>
          <div className="aa-detail-sub">{shortLocation(flow.file, flow.line)}{flow.function ? ` · ${flow.function}` : ''}{flow.target ? ` · ${flow.target}` : ''}</div>
        </div>
        <div className="aa-pill-row">
          <span className={`aa-pill severity ${flow.severity}`}>{flow.severity}</span>
          <span className={`aa-pill trace ${flow.trace_status}`}>{flow.trace_status}</span>
          <span className="aa-pill plain">score {flow.risk_score}</span>
        </div>
      </div>

      <div className="aa-detail-grid">
        <div className="aa-detail-card">
          <div className="aa-card-title">Taint summary</div>
          <div className="aa-kv"><span>Tainted input</span><code>{flow.trace_summary?.taintedInput || 'Unknown tainted value'}</code></div>
          <div className="aa-kv"><span>First seen</span><code>{shortLocation(flow.source, flow.source_line)}</code></div>
          <div className="aa-kv"><span>Final sink</span><code>{shortLocation(flow.sink_file, flow.sink_line)}</code></div>
          <div className="aa-kv"><span>Entry channel</span><code>{flow.input_surface?.channel || 'code-path'}</code></div>
          <div className="aa-mini-list">
            {[flow.trace_summary?.receiveSummary, flow.trace_summary?.propagationSummary, flow.trace_summary?.sinkSummary].filter(Boolean).map((line) => (
              <div key={line} className="aa-mini-card">
                <span>{line}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="aa-detail-card">
          <div className="aa-card-title">Trace clarity</div>
          <div className="aa-tag-wrap">
            {(flow.attack_vectors || []).map((vector) => (
              <span key={`${vector.kind}-${vector.label}`} className="aa-tag">{vector.label}</span>
            ))}
          </div>
          <p className="aa-copy">{flow.description || flow.trace_summary?.inputSummary}</p>
          <div className="aa-mini-list">
            {[flow.trace_summary?.reassignmentSummary, flow.trace_summary?.callSummary, flow.trace_summary?.gapSummary].filter(Boolean).map((item) => (
              <div key={item} className="aa-mini-card">
                <strong>Trace note</strong>
                <span>{item}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <PathGraph flow={flow} />

      {(flow.termination_nodes || []).length ? (
        <div className="aa-detail-card">
          <div className="aa-card-title">Termination points</div>
          <div className="aa-mini-list">
            {flow.termination_nodes.map((node, index) => (
              <div key={`${node.file || 'node'}-${node.line || index}-${index}`} className="aa-mini-card">
                <strong>{String(node.reason || 'unresolved').replace(/_/g, ' ')}</strong>
                <span>{shortLocation(node.file, node.line)}</span>
                {node.code ? <code>{String(node.code).trim()}</code> : null}
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {(artifactIndex?.other_html || []).some((item) => item.toLowerCase().endsWith('analysis.html')) ? (
        <div className="aa-actions">
          <button className="btn btn-secondary btn-sm" onClick={onOpenReport}>
            Open In Analyzer Report
          </button>
        </div>
      ) : null}
    </div>
  )
}

function ReportSubtab({ artifactIndex, flow, model, onSelect }) {
  const [severityFilter, setSeverityFilter] = useState('all')
  const [channelFilter, setChannelFilter] = useState('all')
  const [vectorFilter, setVectorFilter] = useState('all')
  const reportPath = (artifactIndex?.other_html || []).find((item) => item.toLowerCase().endsWith('analysis.html')) || ''
  const topVectors = model.vectors.slice(0, 6)
  const spotlightVectors = (flow?.attack_vectors || []).slice(0, 4)
  const headline = flow?.title || flow?.sink || 'Selected flow'
  const channels = Array.from(new Set(model.flows.map((item) => item.input_surface?.channel || 'code-path'))).sort()
  const vectorLabels = Array.from(new Set(model.vectors.map((item) => item.label))).sort()
  const filteredFlows = model.flows.filter((item) => {
    if (severityFilter !== 'all' && item.severity !== severityFilter) return false
    if (channelFilter !== 'all' && (item.input_surface?.channel || 'code-path') !== channelFilter) return false
    if (vectorFilter !== 'all' && !(item.attack_vectors || []).some((vector) => vector.label === vectorFilter)) return false
    return true
  })

  useEffect(() => {
    setSeverityFilter('all')
    setChannelFilter('all')
    setVectorFilter('all')
  }, [model.stats.total])

  const applyVectorDrilldown = (vector) => {
    setSeverityFilter('all')
    setChannelFilter('all')
    setVectorFilter(vector.label)
    if (vector.flows?.[0]) onSelect(flowKey(vector.flows[0]))
  }

  return (
    <div className="aa-report-shell">
      <div className="aa-report-toolbar">
        <div>
          <div className="aa-card-title">Analyzer report</div>
          <div className="aa-report-sub">
            Native web report view for the analyzer output. This stays inside the scan workspace and reuses the app layout instead of opening a standalone artifact page.
          </div>
        </div>
        {reportPath ? (
          <div className="aa-actions">
            <a className="btn btn-ghost btn-sm" target="_blank" rel="noreferrer" href={artifactUrl(reportPath)}>
              Open Raw HTML
            </a>
          </div>
        ) : null}
      </div>

      <div className="aa-report-grid">
        <div className="aa-detail-card">
          <div className="aa-card-title">Attack vector summary</div>
          {topVectors.length ? (
            <div className="aa-report-vectors">
              {topVectors.map((vector) => (
                <button
                  key={`${vector.kind}-${vector.label}`}
                  className="aa-report-vector"
                  onClick={() => applyVectorDrilldown(vector)}
                >
                  <div className="aa-report-vector-head">
                    <strong>{vector.label}</strong>
                    <span className="aa-pill plain">{vector.count}</span>
                  </div>
                  <div className="aa-report-vector-copy">{vector.reason}</div>
                  {vector.example || vector.examples?.[0] ? (
                    <code>{vector.example || vector.examples?.[0]}</code>
                  ) : null}
                </button>
              ))}
            </div>
          ) : (
            <div className="aa-xref-empty">No attack vector summary available.</div>
          )}
        </div>

        <div className="aa-detail-card">
          <div className="aa-card-title">Flow spotlight</div>
          {flow ? (
            <div className="aa-report-spotlight">
              <div className="aa-report-spotlight-head">
                <div>
                  <div className="aa-detail-title">{headline}</div>
                  <div className="aa-detail-sub">{shortLocation(flow.file, flow.line)}{flow.function ? ` · ${flow.function}` : ''}</div>
                </div>
                <div className="aa-pill-row">
                  <span className={`aa-pill severity ${flow.severity}`}>{flow.severity}</span>
                  <span className={`aa-pill trace ${flow.trace_status}`}>{flow.trace_status}</span>
                  <span className="aa-pill plain">score {flow.risk_score}</span>
                </div>
              </div>
              <div className="aa-report-spotlight-grid">
                <div className="aa-mini-card">
                  <strong>Entry surface</strong>
                  <span>{flow.input_surface?.channel || 'code-path'}</span>
                  {(flow.input_surface?.examples || []).slice(0, 2).map((example) => (
                    <code key={example}>{example}</code>
                  ))}
                </div>
                <div className="aa-mini-card">
                  <strong>Source to sink</strong>
                  <span>{shortLocation(flow.source, flow.source_line)}</span>
                  <span>{shortLocation(flow.file, flow.line)}</span>
                  <code>{flow.sink || headline}</code>
                </div>
              </div>
              {spotlightVectors.length ? (
                <div className="aa-tag-wrap">
                  {spotlightVectors.map((vector) => (
                    <span key={`${vector.kind}-${vector.label}`} className="aa-tag">{vector.label}</span>
                  ))}
                </div>
              ) : null}
              <div className="aa-report-chain">
                {(flow.path || []).slice(0, 6).map((step, index) => (
                  <div key={`${step.file || 'step'}-${step.line || index}-${index}`} className="aa-report-chain-step">
                    <span className={`aa-pill plain`}>{String(step.role || 'step').toUpperCase()}</span>
                    <strong>{compactPathLabel(step.code, shortLocation(step.file, step.line))}</strong>
                    <small>{shortLocation(step.file, step.line)}</small>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="aa-xref-empty">No flow selected.</div>
          )}
        </div>
      </div>

      <div className="aa-detail-card">
        <div className="aa-report-filter-bar">
          <div className="aa-card-title">Flow inventory</div>
          <div className="aa-filter-row">
            <select className="ta-select" value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
              <option value="all">All severities</option>
              {SEVERITY_ORDER.map((level) => (
                <option key={level} value={level}>{level}</option>
              ))}
            </select>
            <select className="ta-select" value={channelFilter} onChange={(event) => setChannelFilter(event.target.value)}>
              <option value="all">All channels</option>
              {channels.map((channel) => (
                <option key={channel} value={channel}>{channel}</option>
              ))}
            </select>
            <select className="ta-select" value={vectorFilter} onChange={(event) => setVectorFilter(event.target.value)}>
              <option value="all">All vector categories</option>
              {vectorLabels.map((label) => (
                <option key={label} value={label}>{label}</option>
              ))}
            </select>
            {(severityFilter !== 'all' || channelFilter !== 'all' || vectorFilter !== 'all') ? (
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => {
                  setSeverityFilter('all')
                  setChannelFilter('all')
                  setVectorFilter('all')
                }}
              >
                Clear filters
              </button>
            ) : null}
          </div>
        </div>
        <div className="aa-report-table-wrap">
          <table className="aa-report-table">
            <thead>
              <tr>
                <th>#</th>
                <th>Sink</th>
                <th>File</th>
                <th>Channel</th>
                <th>Status</th>
                <th>Score</th>
                <th>Vectors</th>
              </tr>
            </thead>
            <tbody>
              {filteredFlows.map((item) => (
                <tr
                  key={flowKey(item)}
                  className={flow && flowKey(item) === flowKey(flow) ? 'active' : ''}
                  onClick={() => onSelect(flowKey(item))}
                >
                  <td>{item.rank}</td>
                  <td>
                    <div className="aa-report-cell-main">{item.title || item.sink || 'Taint flow'}</div>
                    <div className="aa-report-cell-sub">{item.function || 'Unknown function'}</div>
                  </td>
                  <td>{shortLocation(item.file, item.line)}</td>
                  <td>{item.input_surface?.channel || 'code-path'}</td>
                  <td>
                    <span className={`aa-pill trace ${item.trace_status}`}>{item.trace_status}</span>
                  </td>
                  <td>
                    <div className="aa-pill-row">
                      <span className={`aa-pill severity ${item.severity}`}>{item.severity}</span>
                      <span className="aa-pill plain">{item.risk_score}</span>
                    </div>
                  </td>
                  <td>{(item.attack_vectors || []).slice(0, 2).map((vector) => vector.label).join(', ') || 'None'}</td>
                </tr>
              ))}
              {!filteredFlows.length ? (
                <tr>
                  <td colSpan="7">
                    <div className="aa-xref-empty">No flows matched the current report filters.</div>
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function XrefSubtab({ flow }) {
  const [activeKinds, setActiveKinds] = useState([])
  const [activeFile, setActiveFile] = useState('all')
  const [highlightedId, setHighlightedId] = useState('')
  const [expandedAnchors, setExpandedAnchors] = useState({})
  const [expandedFiles, setExpandedFiles] = useState({})
  const inventoryRefs = useRef({})

  useEffect(() => {
    setActiveKinds([])
    setActiveFile('all')
    setHighlightedId('')
    setExpandedAnchors({})
    setExpandedFiles({})
  }, [flow?.rank])

  if (!flow) {
    return (
      <div className="empty-state" style={{ padding: '40px 20px' }}>
        <div className="empty-title">No flow selected</div>
        <div className="empty-msg">Choose a taint flow first to inspect cross-references around the path.</div>
      </div>
    )
  }

  const pathNodes = flow.graph?.pathNodes || []
  const xrefNodes = flow.graph?.xrefNodes || []
  const availableKinds = Array.from(new Set(xrefNodes.map((node) => node.role || 'xref')))
  const availableFiles = Array.from(new Set(xrefNodes.map((node) => node.sublabel || '').filter(Boolean)))
  const anchoredXrefs = xrefNodes.map((node) => ({
    ...node,
    anchorIndex: xrefAnchorIndex(node, pathNodes),
  }))
  const filteredXrefs = anchoredXrefs.filter((node) => {
    if (activeKinds.length && !activeKinds.includes(node.role || 'xref')) return false
    if (activeFile !== 'all' && node.sublabel !== activeFile) return false
    return true
  })
  const xrefByAnchor = pathNodes.map((_, index) => filteredXrefs.filter((node) => node.anchorIndex === index))
  const pathStepCount = pathNodes.length
  const xrefCount = filteredXrefs.length
  const xrefTypeCounts = filteredXrefs.reduce((acc, node) => {
    const key = node.role || 'xref'
    acc[key] = (acc[key] || 0) + 1
    return acc
  }, {})
  const inventoryGroups = filteredXrefs.reduce((acc, node) => {
    const fileKey = shortPath(node.file) || 'Unknown file'
    if (!acc[fileKey]) acc[fileKey] = []
    acc[fileKey].push(node)
    return acc
  }, {})
  const inventoryGroupEntries = Object.entries(inventoryGroups).sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]))
  const hasRealXrefs = (flow.xref || []).length > 0

  const toggleKind = (kind) => {
    setActiveKinds((prev) => (
      prev.includes(kind) ? prev.filter((item) => item !== kind) : [...prev, kind]
    ))
  }
  const toggleAnchor = (index) => {
    setExpandedAnchors((prev) => ({ ...prev, [index]: !prev[index] }))
  }
  const toggleFileGroup = (fileKey) => {
    setExpandedFiles((prev) => ({ ...prev, [fileKey]: !prev[fileKey] }))
  }

  useEffect(() => {
    if (!highlightedId) return
    const node = inventoryRefs.current[highlightedId]
    if (node?.scrollIntoView) {
      node.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
    }
  }, [highlightedId])

  return (
    <div className="aa-xref-shell">
      <div className="aa-detail-card">
        <div className="aa-detail-header">
          <div>
            <div className="aa-detail-title">{flow.title || flow.sink || 'Selected flow'}</div>
            <div className="aa-detail-sub">{shortLocation(flow.file, flow.line)}{flow.function ? ` · ${flow.function}` : ''}</div>
          </div>
          <div className="aa-pill-row">
            <span className="aa-pill plain">{pathStepCount} path node{pathStepCount === 1 ? '' : 's'}</span>
            <span className="aa-pill plain">{xrefCount} xref{xrefCount === 1 ? '' : 's'}</span>
          </div>
        </div>
        <div className="aa-xref-overview">
          <div className="aa-compact-card">
            <div className="aa-compact-card-title">Reference mix</div>
            <div className="aa-tag-wrap">
              {Object.entries(xrefTypeCounts).length ? Object.entries(xrefTypeCounts).map(([kind, count]) => (
                <span key={kind} className="aa-tag">{XREF_KIND_LABELS[kind] || kind} {count}</span>
              )) : <span className="aa-tag">No inline xrefs</span>}
            </div>
          </div>
          <div className="aa-compact-card">
            <div className="aa-compact-card-title">Reading mode</div>
            <span>
              {hasRealXrefs
                ? 'Recorded XREF nodes are attached to the most relevant path step so definitions, callsites, and related symbols stay close to the sink path.'
                : 'Inline XREF nodes were not emitted, so this view falls back to a derived symbol map from the taint path.'}
            </span>
          </div>
        </div>
      </div>

      <div className="aa-detail-card">
        <div className="aa-xref-toolbar">
          <div>
            <div className="aa-card-title">XREF filters</div>
            <div className="aa-detail-sub">Reduce the graph to one file or reference kind before drilling into the inventory.</div>
          </div>
          <div className="aa-filter-row">
            <select className="ta-select" value={activeFile} onChange={(event) => setActiveFile(event.target.value)}>
              <option value="all">All files</option>
              {availableFiles.map((file) => (
                <option key={file} value={file}>{file}</option>
              ))}
            </select>
            {activeKinds.length || activeFile !== 'all' ? (
              <button className="btn btn-ghost btn-sm" onClick={() => { setActiveKinds([]); setActiveFile('all'); setHighlightedId('') }}>
                Clear filters
              </button>
            ) : null}
          </div>
        </div>
        <div className="aa-filter-row">
          {availableKinds.map((kind) => (
            <button
              key={kind}
              className={`aa-filter-chip${activeKinds.includes(kind) ? ' active' : ''}`}
              onClick={() => toggleKind(kind)}
            >
              {XREF_KIND_LABELS[kind] || kind}
            </button>
          ))}
          {availableKinds.length === 0 ? <span className="aa-tag">No xref kinds</span> : null}
        </div>
      </div>

      <div className="aa-xref-layout">
        <div className="aa-graph-board">
          <div className="aa-board-title">In-app XREF graph</div>
          <div className="aa-xref-lane">
            {pathNodes.map((node, index) => (
              <div key={node.id} className="aa-xref-stage">
                <div className={`aa-xref-stage-node ${node.role}`}>
                  <div className="aa-xref-stage-top">
                    <div className="aa-xref-stage-role">{node.label}</div>
                    <span className="aa-pill plain">{xrefByAnchor[index]?.length || 0}</span>
                  </div>
                  <div className="aa-xref-stage-label">{compactPathLabel(node.code, node.sublabel)}</div>
                  <div className="aa-xref-stage-sub">{node.sublabel}</div>
                </div>

                {xrefByAnchor[index]?.length ? (
                  <div className="aa-xref-stage-links">
                    <div className="aa-xref-stage-stack">
                      {(expandedAnchors[index] ? xrefByAnchor[index] : xrefByAnchor[index].slice(0, 3)).map((xrefNode) => (
                        <button
                          key={xrefNode.id}
                          className={`aa-xref-node ${xrefNode.role || 'xref'}${highlightedId === xrefNode.id ? ' active' : ''}`}
                          onClick={() => setHighlightedId((prev) => prev === xrefNode.id ? '' : xrefNode.id)}
                        >
                          <div className="aa-xref-node-top">
                            <strong>{xrefNode.label}</strong>
                            <small>{XREF_KIND_LABELS[xrefNode.role] || xrefNode.role || 'xref'}</small>
                          </div>
                          <span>{xrefNode.sublabel}</span>
                          {xrefNode.context ? <code>{String(xrefNode.context).trim()}</code> : null}
                        </button>
                      ))}
                      {xrefByAnchor[index].length > 3 ? (
                        <button className="aa-inline-toggle" onClick={() => toggleAnchor(index)}>
                          {expandedAnchors[index]
                            ? 'Collapse cluster'
                            : `Show ${xrefByAnchor[index].length - 3} more`}
                        </button>
                      ) : null}
                    </div>
                  </div>
                ) : (
                  <div className="aa-xref-stage-empty">No linked references</div>
                )}
              </div>
            ))}
            {!pathNodes.length ? (
              <div className="aa-xref-empty">No path nodes available for this flow.</div>
            ) : null}
          </div>
        </div>

        <div className="aa-detail-card">
          <div className="aa-card-title">Reference inventory</div>
          {inventoryGroupEntries.length ? (
            <div className="aa-xref-inventory">
              {inventoryGroupEntries.map(([fileKey, nodes]) => {
                const expanded = expandedFiles[fileKey] || nodes.length <= 4
                const visibleNodes = expanded ? nodes : nodes.slice(0, 4)
                return (
                  <div key={fileKey} className="aa-xref-group">
                    <button className="aa-xref-group-head" onClick={() => toggleFileGroup(fileKey)}>
                      <div className="aa-xref-group-title">{fileKey}</div>
                      <div className="aa-xref-group-meta">
                        <span className="aa-tag">{nodes.length} reference{nodes.length === 1 ? '' : 's'}</span>
                        <span className="aa-group-caret">{expanded ? '▲' : '▼'}</span>
                      </div>
                    </button>
                    <div className="aa-xref-group-body">
                      {visibleNodes.map((node) => {
                        const anchor = pathNodes[node.anchorIndex]
                        return (
                          <button
                            key={node.id}
                            ref={(el) => { inventoryRefs.current[node.id] = el }}
                            className={`aa-xref-row${highlightedId === node.id ? ' active' : ''}`}
                            onClick={() => setHighlightedId((prev) => prev === node.id ? '' : node.id)}
                          >
                            <div className="aa-xref-row-main">
                              <strong>{node.label}</strong>
                              <span>{node.sublabel}</span>
                            </div>
                            <div className="aa-xref-row-meta">
                              <span className="aa-tag">{XREF_KIND_LABELS[node.role] || node.role || 'xref'}</span>
                              <span className="aa-tag">linked to {anchor ? anchor.label.toLowerCase() : 'sink'}</span>
                            </div>
                            {node.context ? <code>{String(node.context).trim()}</code> : null}
                          </button>
                        )
                      })}
                      {nodes.length > 4 ? (
                        <button className="aa-inline-toggle" onClick={() => toggleFileGroup(fileKey)}>
                          {expanded ? 'Collapse file group' : `Show ${nodes.length - 4} more`}
                        </button>
                      ) : null}
                    </div>
                  </div>
                )
              })}
            </div>
          ) : (
            <div className="aa-xref-empty">No inline XREF nodes matched the current filters.</div>
          )}
        </div>
      </div>
    </div>
  )
}

function AttackVectorsSubtab({ vectors, vectorGroups, pentestTargets, onSelect }) {
  const [activeGroup, setActiveGroup] = useState('external')

  useEffect(() => {
    const firstNonEmpty = VECTOR_GROUPS.find((group) => (vectorGroups?.[group.id] || []).length > 0)?.id || 'code-path'
    setActiveGroup(firstNonEmpty)
  }, [vectors, vectorGroups])

  if (!vectors.length) {
    return (
      <div className="empty-state" style={{ padding: '40px 20px' }}>
        <div className="empty-title">No attack vectors derived</div>
        <div className="empty-msg">The scan did not expose enough taint-flow detail to build an attack surface summary.</div>
      </div>
    )
  }

  const resolvedGroup = VECTOR_GROUPS.some((group) => group.id === activeGroup && (vectorGroups?.[group.id] || []).length > 0)
    ? activeGroup
    : (VECTOR_GROUPS.find((group) => (vectorGroups?.[group.id] || []).length > 0)?.id || 'code-path')
  const activeVectors = vectorGroups?.[resolvedGroup] || []
  const activeMeta = VECTOR_GROUPS.find((group) => group.id === resolvedGroup) || VECTOR_GROUPS[VECTOR_GROUPS.length - 1]

  return (
    <div className="aa-vectors-shell">
      <div className="aa-vector-tabs">
        {VECTOR_GROUPS.map((group) => {
          const count = vectorGroups?.[group.id]?.length || 0
          return (
            <button
              key={group.id}
              className={`aa-vector-tab${resolvedGroup === group.id ? ' active' : ''}${count === 0 ? ' empty' : ''}`}
              onClick={() => setActiveGroup(group.id)}
              disabled={count === 0}
              style={{ '--aa-vector-color': group.color }}
            >
              <span className="aa-vector-tab-title">{group.label}</span>
              <span className="aa-vector-tab-sub">{group.sublabel}</span>
              <span className="aa-vector-tab-count">{count}</span>
            </button>
          )
        })}
      </div>

      <div className="aa-vector-panel">
        <div className="aa-vector-panel-head">
          <div>
            <div className="aa-vector-panel-title">{activeMeta.label}</div>
            <div className="aa-vector-panel-sub">{activeMeta.sublabel}</div>
          </div>
          <span className="aa-pill plain">{activeVectors.length} vector{activeVectors.length === 1 ? '' : 's'}</span>
        </div>

        <div className="aa-vector-summary-strip">
          {activeVectors.slice(0, 4).map((vector) => (
            <div key={`summary-${vector.kind}-${vector.label}`} className="aa-vector-summary-card">
              <strong>{vector.label}</strong>
              <span>{vector.reason}</span>
              <div className="aa-pill-row">
                <span className="aa-pill plain">{vector.count} flow{vector.count === 1 ? '' : 's'}</span>
                {vector.examples?.[0] ? <span className="aa-tag">{vector.examples[0]}</span> : null}
              </div>
            </div>
          ))}
        </div>

        <div className="aa-vector-grid">
          {activeVectors.map((vector) => (
            <div key={`${vector.kind}-${vector.label}`} className="aa-vector-card">
              <div className="aa-vector-head">
                <div>
                  <div className="aa-vector-title">{vector.label}</div>
                  <div className="aa-detail-sub">{vector.reason}</div>
                </div>
                <span className="aa-pill plain">{vector.count} flow{vector.count === 1 ? '' : 's'}</span>
              </div>
              {vector.examples?.length ? (
                <div className="aa-tag-wrap">
                  {vector.examples.slice(0, 4).map((example) => (
                    <span key={example} className="aa-tag">{example}</span>
                  ))}
                </div>
              ) : null}
              <div className="aa-vector-flow-list">
                {vector.flows.map((flow) => (
                  <button key={`${vector.kind}-${flow.rank}`} className="aa-vector-flow-row aa-pentest-flow" onClick={() => onSelect(flowKey(flow))}>
                    <div className="aa-vector-flow-main">
                      <strong>#{flow.rank} {flow.title || flow.sink || 'Taint flow'}</strong>
                      <span>{shortLocation(flow.file, flow.line)}</span>
                    </div>
                    <div className="aa-vector-flow-meta">
                      <span className="aa-tag">{flow.input_surface?.channel || 'code-path'}</span>
                      <span className={`aa-pill trace ${flow.trace_status}`}>{flow.trace_status}</span>
                      <span className="aa-pill plain">score {flow.risk_score}</span>
                    </div>
                    <span>Source: {shortPath(flow.source) || 'unknown'} → Sink: {shortPath(flow.file) || 'unknown'}:{flow.line || '?'}</span>
                    {(flow.input_surface?.examples || []).length ? (
                      <code>{flow.input_surface.examples[0]}</code>
                    ) : null}
                  </button>
                ))}
              </div>
            </div>
          ))}
          {!activeVectors.length ? (
            <div className="empty-state" style={{ padding: '28px 20px' }}>
              <div className="empty-title">No vectors in this category</div>
              <div className="empty-msg">This scan did not expose influenceable inputs for the selected category.</div>
            </div>
          ) : null}
        </div>
      </div>

      <div className="aa-detail-card">
        <div className="aa-card-title">Pentester Targets</div>
        <p className="aa-copy">Use this as the execution shortlist: each target groups the endpoint, methods, tainted arguments, and a few linked flows.</p>
        <div className="aa-pentest-grid">
          {pentestTargets.map((target) => (
            <div key={target.endpoint} className="aa-pentest-card">
              <div className="aa-vector-head">
                <div>
                  <div className="aa-vector-title">{shortPath(target.endpoint)}</div>
                  <div className="aa-detail-sub">{target.endpoint}</div>
                </div>
                <span className="aa-pill plain">{target.flows.length} flow{target.flows.length === 1 ? '' : 's'}</span>
              </div>
              <div className="aa-tag-wrap">
                {target.methods.map((method) => (
                  <span key={`${target.endpoint}-${method}`} className="aa-tag">{method}</span>
                ))}
                {target.channels.map((channel) => (
                  <span key={`${target.endpoint}-${channel}`} className="aa-tag">{channel}</span>
                ))}
              </div>
              <div className="aa-mini-card">
                <strong>Tainted arguments</strong>
                <div className="aa-tag-wrap">
                  {target.args.length ? target.args.map((arg) => (
                    <span key={`${target.endpoint}-${arg}`} className="aa-tag">{arg}</span>
                  )) : <span className="aa-tag">No concrete argument names resolved</span>}
                </div>
              </div>
              {target.examples.length ? (
                <div className="aa-mini-list">
                  {target.examples.map((example) => (
                    <div key={`${target.endpoint}-${example}`} className="aa-mini-card">
                      <strong>Test path</strong>
                      <code>{example}</code>
                    </div>
                  ))}
                </div>
              ) : null}
              <div className="aa-mini-list">
                {target.flows.slice(0, 3).map((flow) => (
                  <button key={`${target.endpoint}-${flow.rank}`} className="aa-mini-card aa-pentest-flow" onClick={() => onSelect(flowKey(flow))}>
                    <strong>#{flow.rank} {flow.title || flow.sink || 'Taint flow'}</strong>
                    <span>{flow.trace_summary?.inputSummary || shortLocation(flow.file, flow.line)}</span>
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default function AdvancedAnalysis({ analysis, artifactIndex }) {
  const [subtab, setSubtab] = useState('summary')
  const model = useMemo(() => buildModel(analysis), [analysis])
  const [selectedId, setSelectedId] = useState('')
  const hasEmbeddedReport = useMemo(
    () => (artifactIndex?.other_html || []).some((item) => item.toLowerCase().endsWith('analysis.html')),
    [artifactIndex]
  )

  useEffect(() => {
    setSelectedId(model.flows[0] ? flowKey(model.flows[0]) : '')
  }, [analysis])

  const selectedFlow = useMemo(
    () => model.flows.find((flow) => flowKey(flow) === selectedId) || model.flows[0] || null,
    [model.flows, selectedId]
  )

  if (!model.flows.length) {
    return (
      <div className="aa-root">
        <CoverageNotice taintTargets={model.taintTargets} heuristicTargets={model.heuristicTargets} />
        <div className="empty-state" style={{ padding: '40px 20px' }}>
          <div className="empty-title">No advanced taint data available</div>
          <div className="empty-msg">Run a scan with inter-file analysis enabled to populate Advanced Analysis.</div>
        </div>
      </div>
    )
  }

  const subtabs = [
    {
      key: 'summary',
      label: 'Summary',
      sublabel: 'High-level analyzer outcome overview',
      count: model.stats.total,
      icon: <SummaryTabIcon />,
      tone: 'summary',
    },
    {
      key: 'taint',
      label: 'Taint Flows',
      sublabel: `${model.stats.complete} complete · ${model.stats.partial} partial`,
      count: model.stats.total,
      icon: <TaintTabIcon />,
      tone: 'taint',
    },
    {
      key: 'xref',
      label: 'Cross-References',
      sublabel: `${model.stats.crossFile} cross-file propagation`,
      count: model.stats.crossFile,
      icon: <XrefTabIcon />,
      tone: 'xref',
    },
    {
      key: 'vectors',
      label: 'Attack Vectors',
      sublabel: model.taintTargets.join(', ') || 'taint-engine results',
      count: model.vectors.length,
      icon: <VectorsTabIcon />,
      tone: 'vectors',
    },
    ...(hasEmbeddedReport ? [{
      key: 'report',
      label: 'Analyzer Report',
      sublabel: 'Embedded HTML analysis report',
      count: 1,
      icon: <ReportTabIcon />,
      tone: 'report',
    }] : []),
  ]

  return (
    <div className="aa-root">
      <CoverageNotice taintTargets={model.taintTargets} heuristicTargets={model.heuristicTargets} />

      <div className="aa-subtabs">
        {subtabs.map((item) => (
          <button
            key={item.key}
            type="button"
            className={`aa-subtab tone-${item.tone}${subtab === item.key ? ' active' : ''}`}
            onClick={() => setSubtab(item.key)}
          >
            <span className="aa-subtab-icon">{item.icon}</span>
            <span className="aa-subtab-copy">
              <span className="aa-subtab-title">{item.label}</span>
              <span className="aa-subtab-meta">{item.sublabel}</span>
            </span>
            <span className="aa-subtab-count">{item.count}</span>
          </button>
        ))}
      </div>

      <div className="aa-body">
        {subtab === 'summary' ? (
          <section className="aa-summary-panel">
            <div className="aa-summary-head">
              <h3>Summary</h3>
              <p>Review the taint-analysis outcome at a glance, then switch to the relevant subsection for detailed traces, cross-references, or attack vectors.</p>
            </div>
            <div className="aa-stats">
              <OverviewStat label="Flows" value={model.stats.total} accent="var(--primary)" sub={`${model.stats.complete} complete · ${model.stats.partial} partial`} />
              <OverviewStat label="Critical + High" value={model.stats.critical + model.stats.high} accent="#f85149" sub={`${model.stats.critical} critical · ${model.stats.high} high`} />
              <OverviewStat label="Cross-file" value={model.stats.crossFile} accent="#58a6ff" sub="multi-file propagation" />
              <OverviewStat label="Attack Vectors" value={model.vectors.length} accent="#a371f7" sub={`${model.taintTargets.join(', ') || 'taint-engine results'}`} />
            </div>
          </section>
        ) : subtab === 'vectors' ? (
          <AttackVectorsSubtab vectors={model.vectors} vectorGroups={model.vectorGroups} pentestTargets={model.pentestTargets} onSelect={setSelectedId} />
        ) : subtab === 'report' ? (
          <ReportSubtab artifactIndex={artifactIndex} flow={selectedFlow} model={model} onSelect={setSelectedId} />
        ) : subtab === 'taint' ? (
          <TaintWorkspace
            sourceCatalog={model.sourceCatalog}
            selectedFlow={selectedFlow}
            onSelectFlow={setSelectedId}
            artifactIndex={artifactIndex}
            onOpenReport={() => setSubtab('report')}
          />
        ) : (
          <div className="aa-split">
            <div className="aa-sidebar">
              <div className="aa-sidebar-title">Ranked flows</div>
              <FlowList flows={model.flows} selectedId={selectedId} onSelect={setSelectedId} />
            </div>
            <div className="aa-main">
              {subtab === 'taint' ? (
                <FlowDetail flow={selectedFlow} artifactIndex={artifactIndex} onOpenReport={() => setSubtab('report')} />
              ) : (
                <XrefSubtab flow={selectedFlow} />
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
