import { useMemo, useState } from 'react'

/* ─── Group definitions ──────────────────────────────────────── */
const GROUPS = [
  {
    id: 'external',
    label: 'External Inputs',
    sublabel: 'User-Controlled',
    icon: (
      <svg viewBox="0 0 20 20" fill="currentColor">
        <path fillRule="evenodd" d="M10 1.944A11.954 11.954 0 012.166 5C2.056 5.649 2 6.319 2 7c0 5.225 3.34 9.67 8 11.317C14.66 16.67 18 12.225 18 7c0-.682-.057-1.35-.166-2.001A11.954 11.954 0 0110 1.944zM11 14a1 1 0 11-2 0 1 1 0 012 0zm0-7a1 1 0 10-2 0v3a1 1 0 102 0V7z" clipRule="evenodd" />
      </svg>
    ),
    color: '#f85149',
    bg: 'rgba(248,81,73,0.08)',
    border: 'rgba(248,81,73,0.25)',
    desc: 'Taint flows where a user-supplied value (HTTP param, form field, cookie, header, stdin) reaches a sensitive sink directly.',
    sourceKeys: ['get', 'post', 'request', 'cookie', 'header', 'input', 'param', 'query', 'body', 'form', 'argv', 'stdin', 'readline', 'getparameter', 'getquerystring', 'getbody', 'req.query', 'req.body', 'req.params', 'request.form', 'request.args', 'request.json', 'userinput', 'user_input', '$_get', '$_post', '$_request', '$_cookie', '$_server', 'flask.request'],
    sinkKeys: ['exec', 'system', 'shell', 'eval', 'popen', 'subprocess', 'sql', 'query', 'mysql', 'pdo', 'echo', 'print', 'innerhtml', 'write', 'execute', 'command', 'os.system'],
    titleKeys: ['injection', 'xss', 'rce', 'command', 'sqli', 'traversal', 'user input', 'user-controlled', 'external', 'tainted'],
  },
  {
    id: 'datastore',
    label: 'Data Layer',
    sublabel: 'Storage & Persistence',
    icon: (
      <svg viewBox="0 0 20 20" fill="currentColor">
        <path d="M3 12v3c0 1.657 3.134 3 7 3s7-1.343 7-3v-3c0 1.657-3.134 3-7 3s-7-1.343-7-3z" />
        <path d="M3 7v3c0 1.657 3.134 3 7 3s7-1.343 7-3V7c0 1.657-3.134 3-7 3S3 8.657 3 7z" />
        <path d="M17 5c0 1.657-3.134 3-7 3S3 6.657 3 5s3.134-3 7-3 7 1.343 7 3z" />
      </svg>
    ),
    color: '#e3842a',
    bg: 'rgba(227,132,42,0.08)',
    border: 'rgba(227,132,42,0.25)',
    desc: 'Flows touching databases, file systems, caches, or serialised storage. Data may arrive from DB reads that were themselves tainted upstream.',
    sourceKeys: ['file', 'fopen', 'fread', 'readfile', 'db', 'database', 'fetch', 'select', 'resultset', 'row', 'record', 'cache', 'redis', 'mongo', 'deserializ', 'json_decode', 'yaml', 'pickle'],
    sinkKeys: ['fwrite', 'file_put', 'fprintf', 'insert', 'update', 'delete', 'save', 'store', 'persist', 'writefile', 'serialize', 'dump', 'export'],
    titleKeys: ['file', 'database', 'storage', 'persistence', 'serializ', 'deserialization', 'path', 'directory', 'traversal', 'write', 'read', 'injection'],
  },
  {
    id: 'service',
    label: 'Service Calls',
    sublabel: 'APIs & Integrations',
    icon: (
      <svg viewBox="0 0 20 20" fill="currentColor">
        <path fillRule="evenodd" d="M12.586 4.586a2 2 0 112.828 2.828l-3 3a2 2 0 01-2.828 0 1 1 0 00-1.414 1.414 4 4 0 005.656 0l3-3a4 4 0 00-5.656-5.656l-1.5 1.5a1 1 0 101.414 1.414l1.5-1.5zm-5 5a2 2 0 012.828 0 1 1 0 101.414-1.414 4 4 0 00-5.656 0l-3 3a4 4 0 105.656 5.656l1.5-1.5a1 1 0 10-1.414-1.414l-1.5 1.5a2 2 0 11-2.828-2.828l3-3z" clipRule="evenodd" />
      </svg>
    ),
    color: '#d29922',
    bg: 'rgba(210,153,34,0.08)',
    border: 'rgba(210,153,34,0.25)',
    desc: 'Flows that cross service boundaries — outbound HTTP/RPC calls, message queues, webhooks, or data received from external APIs that propagates inward.',
    sourceKeys: ['curl', 'http', 'guzzle', 'axios', 'fetch', 'requests', 'urllib', 'httpclient', 'resttemplate', 'webclient', 'socket', 'grpc', 'amqp', 'kafka', 'sqs', 'pubsub', 'websocket', 'xmlrpc', 'soap', 'api_call', 'remote'],
    sinkKeys: ['send', 'post', 'put', 'patch', 'dispatch', 'publish', 'emit', 'notify', 'webhook', 'redirect', 'forward', 'proxy', 'curl_exec', 'httppost', 'makerequest'],
    titleKeys: ['ssrf', 'service', 'api', 'http', 'remote', 'network', 'request forgery', 'outbound', 'webhook', 'integration'],
  },
  {
    id: 'auth',
    label: 'Identity & Auth',
    sublabel: 'Authentication & Sessions',
    icon: (
      <svg viewBox="0 0 20 20" fill="currentColor">
        <path fillRule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clipRule="evenodd" />
      </svg>
    ),
    color: '#a371f7',
    bg: 'rgba(163,113,247,0.08)',
    border: 'rgba(163,113,247,0.25)',
    desc: 'Flows involving authentication tokens, session data, passwords, cryptographic operations, or privilege checks that could be bypassed or leaked.',
    sourceKeys: ['password', 'passwd', 'secret', 'token', 'jwt', 'session', 'auth', 'login', 'credential', 'apikey', 'api_key', 'bearer', 'oauth', 'saml', 'ldap', 'hash', 'role', 'permission', 'privilege', 'access_token'],
    sinkKeys: ['hash', 'encrypt', 'decrypt', 'verify', 'compare', 'check', 'validate', 'authenticate', 'authorize', 'grant', 'allow', 'deny', 'setcookie', 'session_start', 'jwt_encode', 'sign'],
    titleKeys: ['auth', 'session', 'password', 'credential', 'token', 'jwt', 'privilege', 'broken', 'bypass', 'escalation', 'hardcoded'],
  },
  {
    id: 'config',
    label: 'Environment',
    sublabel: 'Config & Secrets',
    icon: (
      <svg viewBox="0 0 20 20" fill="currentColor">
        <path fillRule="evenodd" d="M11.49 3.17c-.38-1.56-2.6-1.56-2.98 0a1.532 1.532 0 01-2.286.948c-1.372-.836-2.942.734-2.106 2.106.54.886.061 2.042-.947 2.287-1.561.379-1.561 2.6 0 2.978a1.532 1.532 0 01.947 2.287c-.836 1.372.734 2.942 2.106 2.106a1.532 1.532 0 012.287.947c.379 1.561 2.6 1.561 2.978 0a1.533 1.533 0 012.287-.947c1.372.836 2.942-.734 2.106-2.106a1.533 1.533 0 01.947-2.287c1.561-.379 1.561-2.6 0-2.978a1.532 1.532 0 01-.947-2.287c.836-1.372-.734-2.942-2.106-2.106a1.532 1.532 0 01-2.287-.947zM10 13a3 3 0 100-6 3 3 0 000 6z" clipRule="evenodd" />
      </svg>
    ),
    color: '#58a6ff',
    bg: 'rgba(88,166,255,0.08)',
    border: 'rgba(88,166,255,0.25)',
    desc: 'Flows originating from environment variables, config files, or secret stores. Values may be operator-controlled but could be tampered with in compromised environments.',
    sourceKeys: ['env', 'getenv', 'environ', 'config', 'settings', 'dotenv', 'ini_get', 'getproperty', 'properties', 'appconfig', 'vault', 'secret_manager', 'ssm', 'keychain', '.env'],
    sinkKeys: ['log', 'print', 'echo', 'debug', 'trace', 'error_log', 'syslog', 'sql', 'query', 'exec', 'eval', 'header', 'response', 'output'],
    titleKeys: ['config', 'environment', 'secret', 'env var', 'hardcoded', 'exposure', 'disclosure', 'leak', 'misconfiguration'],
  },
]

/* ─── Classify a single flow into a group ───────────────────── */
function classifyFlow(flow) {
  const src = String(flow.source || '').toLowerCase()
  const snk = String(flow.sink || '').toLowerCase()
  const title = String(flow.title || flow.id || '').toLowerCase()
  const desc = String(flow.description || '').toLowerCase()
  const combined = `${src} ${snk} ${title} ${desc}`

  for (const g of GROUPS) {
    const srcMatch = g.sourceKeys.some((k) => src.includes(k))
    const snkMatch = g.sinkKeys.some((k) => snk.includes(k))
    const titleMatch = g.titleKeys.some((k) => combined.includes(k))
    if ((srcMatch && snkMatch) || (srcMatch && titleMatch) || (snkMatch && titleMatch)) {
      return g.id
    }
    // single strong match
    if (srcMatch || snkMatch) return g.id
  }
  return 'other'
}

/* ─── Severity helper ────────────────────────────────────────── */
function flowSeverity(flow) {
  const s = (flow.confidence_score || 0)
  if (s >= 85) return 'critical'
  if (s >= 65) return 'high'
  if (s >= 40) return 'medium'
  if (s >= 20) return 'low'
  return 'info'
}

const SEV_COLOR = {
  critical: '#f85149', high: '#e3842a', medium: '#d29922', low: '#3fb950', info: '#58a6ff',
}
const SEV_BG = {
  critical: 'rgba(248,81,73,0.10)', high: 'rgba(227,132,42,0.10)',
  medium: 'rgba(210,153,34,0.10)', low: 'rgba(63,185,80,0.10)', info: 'rgba(88,166,255,0.10)',
}

/* ─── Trace step node ────────────────────────────────────────── */
function TraceNode({ step, role, index, total }) {
  const isSource = index === 0
  const isSink = index === total - 1
  const label = isSource ? 'SOURCE' : isSink ? 'SINK' : step.role ? String(step.role).toUpperCase() : 'STEP'
  const nodeColor = isSource ? '#3fb950' : isSink ? '#f85149' : '#58a6ff'
  const nodeBg = isSource ? 'rgba(63,185,80,0.08)' : isSink ? 'rgba(248,81,73,0.08)' : 'rgba(88,166,255,0.06)'

  const file = step.file ? String(step.file).split('/').slice(-1)[0] : null
  const fn = step.function || step.func || null
  const line = step.line || null
  const code = step.code || null

  return (
    <div className="ta-trace-node" style={{ '--node-color': nodeColor, '--node-bg': nodeBg }}>
      <div className="ta-node-header">
        <span className="ta-node-role">{label}</span>
        {file && <span className="ta-node-file">{file}{line ? `:${line}` : ''}</span>}
        {fn && !file && <span className="ta-node-file">{fn}</span>}
      </div>
      {code && <pre className="ta-node-code">{String(code).trim()}</pre>}
    </div>
  )
}

/* ─── Single flow card ───────────────────────────────────────── */
function FlowCard({ flow, index, open, onToggle, groupColor }) {
  const sev = flowSeverity(flow)
  const chain = flow.trace_chain || []
  const hasChain = chain.length > 0
  const src = flow.source ? String(flow.source).split(/[\\/]/).slice(-1)[0] : null
  const snk = flow.sink ? String(flow.sink).split(/[\\/]/).slice(-1)[0] : null

  return (
    <div className={`ta-flow-card${open ? ' open' : ''}`} style={{ '--gcolor': groupColor, '--sev-color': SEV_COLOR[sev], '--sev-bg': SEV_BG[sev] }}>
      <button className="ta-flow-header" onClick={onToggle}>
        {/* Rank */}
        <span className="ta-flow-rank">#{index + 1}</span>

        {/* Severity badge */}
        <span className="ta-sev-badge" style={{ color: SEV_COLOR[sev], background: SEV_BG[sev] }}>
          {sev}
        </span>

        {/* Score */}
        {flow.confidence_score > 0 && (
          <span className="ta-flow-score">{flow.confidence_score}%</span>
        )}

        {/* Title */}
        <span className="ta-flow-title">{flow.title || flow.id || `Flow #${index + 1}`}</span>

        {/* Source → Sink summary */}
        {(src || snk) && (
          <span className="ta-src-snk">
            {src && <span className="ta-src">{src}</span>}
            {src && snk && <span className="ta-arrow">→</span>}
            {snk && <span className="ta-snk">{snk}</span>}
          </span>
        )}

        {/* Step count */}
        {hasChain && (
          <span className="ta-step-count">{chain.length} step{chain.length !== 1 ? 's' : ''}</span>
        )}

        <span className="ta-caret">{open ? '▲' : '▼'}</span>
      </button>

      {open && (
        <div className="ta-flow-body">
          {flow.description && (
            <p className="ta-flow-desc">{flow.description}</p>
          )}

          {/* Visual trace chain */}
          {hasChain ? (
            <div className="ta-chain-wrap">
              <div className="ta-chain-label">Taint Path</div>
              <div className="ta-chain">
                {chain.map((step, si) => {
                  const stepObj = typeof step === 'string' ? { function: step } : step
                  return (
                    <div key={si} className="ta-chain-step">
                      <TraceNode step={stepObj} index={si} total={chain.length} />
                      {si < chain.length - 1 && (
                        <div className="ta-chain-connector">
                          <div className="ta-connector-line" />
                          <div className="ta-connector-arrow">↓</div>
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          ) : (src || snk) ? (
            <div className="ta-chain-wrap">
              <div className="ta-chain-label">Taint Path</div>
              <div className="ta-chain">
                {src && (
                  <div className="ta-chain-step">
                    <div className="ta-trace-node" style={{ '--node-color': '#3fb950', '--node-bg': 'rgba(63,185,80,0.08)' }}>
                      <div className="ta-node-header">
                        <span className="ta-node-role">SOURCE</span>
                        <span className="ta-node-file">{flow.source}</span>
                      </div>
                    </div>
                    {snk && (
                      <div className="ta-chain-connector">
                        <div className="ta-connector-line" />
                        <div className="ta-connector-arrow">↓</div>
                      </div>
                    )}
                  </div>
                )}
                {snk && (
                  <div className="ta-chain-step">
                    <div className="ta-trace-node" style={{ '--node-color': '#f85149', '--node-bg': 'rgba(248,81,73,0.08)' }}>
                      <div className="ta-node-header">
                        <span className="ta-node-role">SINK</span>
                        <span className="ta-node-file">{flow.sink}</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          ) : null}
        </div>
      )}
    </div>
  )
}

/* ─── Group panel ────────────────────────────────────────────── */
function GroupPanel({ group, flows, search }) {
  const [openIds, setOpenIds] = useState(new Set())

  const filtered = useMemo(() => {
    if (!search) return flows
    const q = search.toLowerCase()
    return flows.filter((f) =>
      `${f.title} ${f.description} ${f.source} ${f.sink}`.toLowerCase().includes(q)
    )
  }, [flows, search])

  function toggle(i) {
    setOpenIds((prev) => {
      const next = new Set(prev)
      next.has(i) ? next.delete(i) : next.add(i)
      return next
    })
  }

  if (filtered.length === 0) {
    return (
      <div className="empty-state" style={{ padding: '30px 20px' }}>
        <div className="empty-title">No matching flows</div>
        <div className="empty-msg">Try adjusting your search.</div>
      </div>
    )
  }

  return (
    <div className="ta-flow-list">
      {filtered.map((flow, i) => (
        <FlowCard
          key={i}
          flow={flow}
          index={i}
          open={openIds.has(i)}
          onToggle={() => toggle(i)}
          groupColor={group.color}
        />
      ))}
    </div>
  )
}

/* ─── Platform coverage notice ───────────────────────────────── */
function formatPlatformName(raw) {
  const map = {
    android: 'Android', ios: 'iOS', kotlin: 'Kotlin', swift: 'Swift',
    reactnative: 'React Native', flutter: 'Flutter', xamarin: 'Xamarin',
    cordova: 'Cordova', ionic: 'Ionic', nativescript: 'NativeScript',
    java: 'Java', python: 'Python', javascript: 'JavaScript', php: 'PHP',
    golang: 'Go', go: 'Go', dotnet: '.NET', csharp: 'C#', js: 'JavaScript',
    nodejs: 'Node.js', node: 'Node.js', py: 'Python', rust: 'Rust',
    ruby: 'Ruby', c: 'C', cpp: 'C++', powershell: 'PowerShell',
    bash: 'Bash', terraform: 'Terraform', kubernetes: 'Kubernetes',
    dockerfile: 'Dockerfile',
  }
  const key = String(raw || '').toLowerCase().replace(/[\s_-]/g, '')
  return map[key] || String(raw || '').replace(/\b\w/g, (c) => c.toUpperCase())
}

function PlatformCoverageNotice({ taintEngineTargets, heuristicOnlyTargets }) {
  if (!heuristicOnlyTargets.length) return null
  const hasBothKinds = taintEngineTargets.length > 0
  return (
    <div style={{
      background: 'rgba(251,191,36,0.07)',
      border: '1px solid rgba(251,191,36,0.28)',
      borderRadius: 8,
      padding: '12px 16px',
      marginBottom: 16,
      display: 'flex',
      gap: 12,
      alignItems: 'flex-start',
    }}>
      {/* Warning icon */}
      <svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor"
        style={{ color: '#fbbf24', flexShrink: 0, marginTop: 1 }}>
        <path fillRule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 5a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 5zm0 9a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
      </svg>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 13, fontWeight: 600, color: '#fbbf24', marginBottom: 5 }}>
          {hasBothKinds
            ? 'Taint analysis not available for all scanned platforms'
            : 'Taint analysis not supported for the scanned platform' + (heuristicOnlyTargets.length > 1 ? 's' : '')}
        </div>
        <div style={{ fontSize: 12, color: 'var(--text-2)', lineHeight: 1.6 }}>
          {hasBothKinds && (
            <div style={{ marginBottom: 6 }}>
              <span style={{ color: '#4ade80', fontWeight: 500 }}>Analyzed</span>
              {' — '}
              {taintEngineTargets.map(formatPlatformName).join(', ')}
            </div>
          )}
          <div>
            <span style={{ color: '#fbbf24', fontWeight: 500 }}>Not supported</span>
            {' — '}
            {heuristicOnlyTargets.map(formatPlatformName).join(', ')}
            {'. '}
            Rule-based review candidates for {heuristicOnlyTargets.length > 1 ? 'these platforms' : 'this platform'} are available in the{' '}
            <strong style={{ color: 'var(--text-1)' }}>Areas of Interest</strong> tab.
          </div>
        </div>
        <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text-3)' }}>
          Taint engine supported for: Java · Python · JavaScript / Node.js · PHP · Go · .NET
        </div>
      </div>
    </div>
  )
}

/* ─── Group selector tab ─────────────────────────────────────── */
function GroupTab({ group, count, active, onClick }) {
  return (
    <button
      className={`ta-group-tab${active ? ' active' : ''}${count === 0 ? ' empty' : ''}`}
      style={{ '--gcolor': group.color, '--gbg': group.bg, '--gborder': group.border }}
      onClick={onClick}
      disabled={count === 0}
    >
      <span className="ta-group-icon">{group.icon}</span>
      <span className="ta-group-tab-inner">
        <span className="ta-group-name">{group.label}</span>
        <span className="ta-group-sub">{group.sublabel}</span>
      </span>
      <span className={`ta-group-count${count === 0 ? ' zero' : ''}`}>{count}</span>
    </button>
  )
}

/* ─── Main TaintAnalysis ─────────────────────────────────────── */
export default function TaintAnalysis({ analysis }) {
  const [activeGroup, setActiveGroup] = useState(null)
  const [search, setSearch] = useState('')

  // Platforms that have a real taint engine (vs heuristic-only fallback)
  const taintEngineTargets = useMemo(() => {
    if (!analysis?.results?.length) return []
    return analysis.results
      .filter((r) => r.engine === 'dataflow_controlflow')
      .map((r) => r.target || r.platform)
      .filter(Boolean)
  }, [analysis])

  // Platforms present in analysis but without a taint engine
  const heuristicOnlyTargets = useMemo(() => {
    if (!analysis?.results?.length) return []
    return analysis.results
      .filter((r) => r.engine !== 'dataflow_controlflow')
      .map((r) => r.target || r.platform)
      .filter(Boolean)
  }, [analysis])

  // Only include findings that are actual taint flows (source-to-sink engine output).
  // Heuristic fallback findings (analysis_kind === "heuristic") are regular scan
  // findings re-packaged for platforms without a taint engine — they already appear
  // in the Areas of Interest tab and must not be duplicated here.
  const allFlows = useMemo(() => {
    if (!analysis?.results?.length) return []
    return analysis.results
      .filter((r) => r.engine === 'dataflow_controlflow')
      .flatMap((r) =>
        (r.findings || [])
          .filter((f) => f.analysis_kind === 'taint_flow')
          .map((f) => ({ ...f, _target: r.target }))
      )
  }, [analysis])

  // Classify flows into groups
  const grouped = useMemo(() => {
    const map = {}
    const otherFlows = []
    for (const g of GROUPS) map[g.id] = []

    for (const f of allFlows) {
      const gid = classifyFlow(f)
      if (map[gid]) {
        map[gid].push(f)
      } else {
        otherFlows.push(f)
      }
    }
    return { ...map, other: otherFlows }
  }, [allFlows])

  // Default to first non-empty group
  const firstNonEmpty = useMemo(() => {
    for (const g of GROUPS) if (grouped[g.id]?.length) return g.id
    if (grouped.other?.length) return 'other'
    return null
  }, [grouped])

  const currentGroup = activeGroup || firstNonEmpty

  if (!allFlows.length) {
    const noAnalysisAtAll = !analysis?.results?.length
    const engineRanButEmpty = taintEngineTargets.length > 0 && !allFlows.length
    return (
      <div style={{ padding: '24px 0' }}>
        {/* Coverage notice sits above the empty message when platforms are present */}
        {!noAnalysisAtAll && (
          <PlatformCoverageNotice
            taintEngineTargets={taintEngineTargets}
            heuristicOnlyTargets={heuristicOnlyTargets}
          />
        )}
        <div className="empty-state" style={{ padding: '32px 20px' }}>
          <svg className="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 16.875h3.375m0 0h3.375m-3.375 0V13.5m0 3.375v3.375M6 10.5h2.25a2.25 2.25 0 002.25-2.25V6a2.25 2.25 0 00-2.25-2.25H6A2.25 2.25 0 003.75 6v2.25A2.25 2.25 0 006 10.5zm0 9.75h2.25A2.25 2.25 0 0010.5 18v-2.25a2.25 2.25 0 00-2.25-2.25H6a2.25 2.25 0 00-2.25 2.25V18A2.25 2.25 0 006 20.25zm9.75-9.75H18a2.25 2.25 0 002.25-2.25V6A2.25 2.25 0 0018 3.75h-2.25A2.25 2.25 0 0013.5 6v2.25a2.25 2.25 0 002.25 2.25z" />
          </svg>
          <div className="empty-title">No taint flows detected</div>
          {noAnalysisAtAll ? (
            <div className="empty-msg">
              Inter-file analysis was not run for this scan.
              Enable <strong>Inter-file Analysis</strong> in scan options to trace data flows across file boundaries.
            </div>
          ) : engineRanButEmpty ? (
            <div className="empty-msg">
              The taint engine ran for <strong>{taintEngineTargets.map(formatPlatformName).join(', ')}</strong> but
              found no cross-file source-to-sink flows. All rule-based review candidates are in the <strong>Areas of Interest</strong> tab.
            </div>
          ) : (
            <div className="empty-msg">
              All rule-based review candidates for the scanned platform{heuristicOnlyTargets.length > 1 ? 's' : ''} are
              available in the <strong>Areas of Interest</strong> tab.
            </div>
          )}
        </div>
      </div>
    )
  }

  const activeGroupDef = GROUPS.find((g) => g.id === currentGroup) || {
    id: 'other', label: 'Other', sublabel: 'Uncategorized', color: '#8b949e',
    bg: 'rgba(139,148,158,0.08)', border: 'rgba(139,148,158,0.25)',
    icon: null, desc: 'Flows that did not match a specific category.',
  }

  return (
    <div className="ta-root">
      {/* ── Coverage notice for unsupported platforms in mixed scans ── */}
      <PlatformCoverageNotice
        taintEngineTargets={taintEngineTargets}
        heuristicOnlyTargets={heuristicOnlyTargets}
      />

      {/* ── Header strip ── */}
      <div className="ta-header">
        <div className="ta-header-left">
          <div className="ta-total-badge">{allFlows.length} flow{allFlows.length !== 1 ? 's' : ''}</div>
          <span className="ta-header-desc">Cross-file taint propagation results, grouped by attack surface</span>
        </div>
        {/* Search */}
        <div className="ta-search-wrap">
          <svg width="13" height="13" viewBox="0 0 20 20" fill="currentColor" className="ta-search-icon">
            <path fillRule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clipRule="evenodd" />
          </svg>
          <input className="ta-search" placeholder="Search flows…" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
      </div>

      {/* ── Group tabs ── */}
      <div className="ta-groups-bar">
        {GROUPS.map((g) => (
          <GroupTab
            key={g.id}
            group={g}
            count={grouped[g.id]?.length || 0}
            active={currentGroup === g.id}
            onClick={() => setActiveGroup(g.id)}
          />
        ))}
        {grouped.other?.length > 0 && (
          <GroupTab
            group={{ id: 'other', label: 'Other', sublabel: 'Uncategorized', color: '#8b949e', icon: (
              <svg viewBox="0 0 20 20" fill="currentColor"><path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" /></svg>
            ) }}
            count={grouped.other.length}
            active={currentGroup === 'other'}
            onClick={() => setActiveGroup('other')}
          />
        )}
      </div>

      {/* ── Active group detail ── */}
      {activeGroupDef && (
        <div className="ta-group-desc-bar" style={{ '--gcolor': activeGroupDef.color, '--gbg': activeGroupDef.bg, '--gborder': activeGroupDef.border }}>
          <span className="ta-group-desc-icon">{activeGroupDef.icon}</span>
          <div>
            <div className="ta-group-desc-title">{activeGroupDef.label} <span style={{ fontWeight: 400, color: 'var(--text-3)' }}>— {activeGroupDef.sublabel}</span></div>
            <div className="ta-group-desc-text">{activeGroupDef.desc}</div>
          </div>
        </div>
      )}

      {/* ── Flow list for active group ── */}
      <GroupPanel
        key={currentGroup}
        group={activeGroupDef}
        flows={grouped[currentGroup] || []}
        search={search}
      />
    </div>
  )
}
