import { useEffect, useMemo, useState } from 'react'

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low']

function SummaryTabIcon() {
  return (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
      <path d="M3 4.75A1.75 1.75 0 0 1 4.75 3h10.5A1.75 1.75 0 0 1 17 4.75v10.5A1.75 1.75 0 0 1 15.25 17H4.75A1.75 1.75 0 0 1 3 15.25V4.75Zm3 .25a.75.75 0 0 0-.75.75v1.5c0 .414.336.75.75.75h1.5a.75.75 0 0 0 .75-.75v-1.5A.75.75 0 0 0 7.5 5H6Zm0 4a.75.75 0 0 0-.75.75v4.25c0 .414.336.75.75.75h1.5a.75.75 0 0 0 .75-.75V9.75A.75.75 0 0 0 7.5 9H6Zm4-3.25a.75.75 0 0 1 .75-.75h3.25a.75.75 0 0 1 0 1.5H10.75a.75.75 0 0 1-.75-.75Zm0 4a.75.75 0 0 1 .75-.75h3.25a.75.75 0 0 1 0 1.5H10.75a.75.75 0 0 1-.75-.75Zm0 4a.75.75 0 0 1 .75-.75h3.25a.75.75 0 0 1 0 1.5H10.75a.75.75 0 0 1-.75-.75Z" />
    </svg>
  )
}

function VulnerabilityTabIcon() {
  return (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
      <path fillRule="evenodd" d="M10 2.5 4 5v4.736c0 3.341 2.294 6.411 6 7.764 3.706-1.353 6-4.423 6-7.764V5l-6-2.5Zm0 4.125a.875.875 0 0 1 .875.875v2.42l1.58 1.58a.875.875 0 1 1-1.238 1.237l-1.836-1.835A.875.875 0 0 1 9.125 10V7.5A.875.875 0 0 1 10 6.625Z" clipRule="evenodd" />
    </svg>
  )
}

function SuppressedTabIcon() {
  return (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
      <path fillRule="evenodd" d="M10 2.25A7.75 7.75 0 1 0 17.75 10 7.75 7.75 0 0 0 10 2.25Zm3.072 5.822a.75.75 0 0 1 0 1.06l-3.94 3.94a.75.75 0 0 1-1.06 0L6.93 11.928a.75.75 0 1 1 1.06-1.06l.612.61 3.409-3.407a.75.75 0 0 1 1.06 0Z" clipRule="evenodd" />
    </svg>
  )
}

function ManualReviewTabIcon() {
  return (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
      <path fillRule="evenodd" d="M18 10A8 8 0 1 1 2 10a8 8 0 0 1 16 0Zm-8.75-2.75a.75.75 0 0 1 1.5 0V10a.75.75 0 0 1-1.5 0V7.25Zm1.5 5.5a.75.75 0 1 1-1.5 0 .75.75 0 0 1 1.5 0Z" clipRule="evenodd" />
    </svg>
  )
}

function MitigationTabIcon() {
  return (
    <svg viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
      <path fillRule="evenodd" d="M10 2.5a1 1 0 0 1 1 1v.69a5.752 5.752 0 0 1 2.924 1.212l.49-.49a1 1 0 1 1 1.414 1.414l-.49.49A5.752 5.752 0 0 1 16.5 9.74h.69a1 1 0 1 1 0 2h-.69a5.752 5.752 0 0 1-1.212 2.924l.49.49a1 1 0 1 1-1.414 1.414l-.49-.49A5.752 5.752 0 0 1 11 17.31V18a1 1 0 1 1-2 0v-.69a5.752 5.752 0 0 1-2.924-1.212l-.49.49a1 1 0 0 1-1.414-1.414l.49-.49A5.752 5.752 0 0 1 3.5 11.74h-.69a1 1 0 1 1 0-2h.69a5.752 5.752 0 0 1 1.212-2.924l-.49-.49A1 1 0 1 1 5.636 4.91l.49.49A5.752 5.752 0 0 1 9 4.19V3.5a1 1 0 0 1 1-1Zm-2 7.5a2 2 0 1 0 4 0 2 2 0 0 0-4 0Z" clipRule="evenodd" />
    </svg>
  )
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

function severityFromScore(score, rawSeverity) {
  const direct = String(rawSeverity || '').toLowerCase()
  if (SEVERITY_ORDER.includes(direct)) return direct
  if (score >= 85) return 'critical'
  if (score >= 70) return 'high'
  if (score >= 50) return 'medium'
  return 'low'
}

function normalizeTraceStatus(flow) {
  return String(flow?.trace_status || '').toLowerCase() === 'partial' ? 'partial' : 'complete'
}

function extractTaintSymbol(flow, path) {
  const candidates = []
  for (const step of path || []) {
    for (const value of [step?.source_symbol, step?.symbol, ...(step?.variables || [])]) {
      const cleaned = String(value || '').trim().replace(/^[$@]/, '')
      if (!cleaned || cleaned === 'source' || candidates.includes(cleaned)) continue
      candidates.push(cleaned)
    }
  }
  const quoted = String(flow?.description || '').match(/`([^`]+)`/g) || []
  for (const raw of quoted) {
    const cleaned = raw.replace(/`/g, '').trim().replace(/^[$@]/, '')
    if (cleaned && !candidates.includes(cleaned)) candidates.push(cleaned)
  }
  return candidates[0] || 'tainted input'
}

function ensureSourceStep(flow) {
  let path = Array.isArray(flow?.path) ? [...flow.path] : []
  const primarySymbol = extractTaintSymbol(flow, path)

  if (!path.some((step) => String(step?.role || '').toLowerCase() === 'source')) {
    const first = path[0]
    path = [{
      file: flow.source || first?.file || flow.file || '',
      line: first?.line || flow.source_line || '',
      role: 'source',
      code: `[inferred] ${primarySymbol}`,
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
  const sinkStep = [...(path || [])].reverse().find((step) => String(step?.role || '').toLowerCase() === 'sink') || path?.[path.length - 1] || null
  const firstStep = path?.[0] || null
  return {
    taintedInput,
    inputSummary: `Tainted parameter \`${taintedInput}\` flows through ${files.length > 1 ? `${files.length} files` : 'this code path'} into sink \`${flow.sink || flow.sink_name || 'sink'}\`.`,
    receiveSummary: firstStep ? `First observed at ${shortLocation(firstStep.file, firstStep.line)}.` : '',
    sinkSummary: sinkStep ? `Final sink at ${shortLocation(sinkStep.file, sinkStep.line)}.` : '',
  }
}

function shortLoc(item) {
  return shortLocation(item?.file, item?.line)
}

function pathByFile(path) {
  const groups = []
  for (const step of path || []) {
    const fileKey = shortPath(step?.file) || 'Unresolved file'
    let current = groups[groups.length - 1]
    if (!current || current.fileKey !== fileKey) {
      current = { fileKey, file: step?.file || '', steps: [] }
      groups.push(current)
    }
    current.steps.push(step)
  }
  return groups
}

function snippetRows(step) {
  const before = Array.isArray(step?.context_before) ? step.context_before : []
  const after = Array.isArray(step?.context_after) ? step.context_after : []
  const resolved = String(step?.resolved_code || '').trim()
  const emitted = String(step?.code || '').trim()
  const line = step?.line
  const highlight = resolved || emitted || '(code not emitted by analyzer)'
  const analyzerNote = resolved && emitted && resolved !== emitted ? emitted : ''
  return {
    rows: [
      ...before,
      { line, code: highlight, isMatch: true },
      ...after,
    ],
    analyzerNote,
  }
}

function channelLabel(item) {
  return String(item?.input_surface?.channel || '').trim() || 'code-path'
}

function familyKey(item) {
  return [item.kind || item.title, item.cwe || '', item.platform || ''].join('::')
}

function severityRank(level) {
  return SEVERITY_ORDER.indexOf(String(level || '').toLowerCase())
}

function maxSeverity(items) {
  return items.reduce((best, item) => {
    if (!best) return item.severity
    return severityRank(item.severity) < severityRank(best) ? item.severity : best
  }, '')
}

function groupMitigations(mitigations) {
  const grouped = new Map()
  for (const item of mitigations) {
    const key = [item.kind || item.title, item.platform || ''].join('::')
    const group = grouped.get(key) || {
      key,
      title: item.title || item.kind || 'Mitigated implementation',
      kind: item.kind || '',
      platform: item.platform || '',
      items: [],
      description: item.description || '',
      whatItDoes: item.what_it_does || '',
      effectiveness: item.effectiveness || '',
      modernity: item.modernity || '',
      implementation: item.implementation_assessment || '',
      recommendation: item.recommendation || '',
    }
    group.items.push(item)
    grouped.set(key, group)
  }
  return Array.from(grouped.values()).sort((a, b) => b.items.length - a.items.length || a.title.localeCompare(b.title))
}

function groupFalsePositives(items) {
  const grouped = new Map()
  for (const item of items || []) {
    const key = [item.kind || item.rule_title || 'finding', item.platform || ''].join('::')
    const group = grouped.get(key) || {
      key,
      title: item.rule_title || item.kind || 'Suppressed finding',
      kind: item.kind || '',
      platform: item.platform || '',
      items: [],
    }
    group.items.push(item)
    grouped.set(key, group)
  }
  return Array.from(grouped.values()).sort((a, b) => b.items.length - a.items.length || a.title.localeCompare(b.title))
}

function groupManualReviews(items) {
  const grouped = new Map()
  for (const item of items || []) {
    const key = [item.kind || item.rule_title || 'finding', item.platform || ''].join('::')
    const group = grouped.get(key) || {
      key,
      title: item.rule_title || item.kind || 'Manual review recommended',
      kind: item.kind || '',
      platform: item.platform || '',
      items: [],
    }
    group.items.push(item)
    grouped.set(key, group)
  }
  return Array.from(grouped.values()).sort((a, b) => b.items.length - a.items.length || a.title.localeCompare(b.title))
}

function buildModel(analysis) {
  const results = Array.isArray(analysis?.results) ? analysis.results : []
  const platformResults = results.filter((item) => item?.target_type !== 'framework')
  const rawFlows = []

  for (const result of platformResults) {
    const target = result.target || result.platform || ''
    if (result.engine !== 'dataflow_controlflow') continue
    for (const finding of result.findings || []) {
      if (finding.analysis_kind !== 'taint_flow') continue
      rawFlows.push({ ...finding, target })
    }
  }

  const flows = rawFlows.map((flow) => {
    const path = ensureSourceStep(flow)
    const severity = severityFromScore(Number(flow.risk_score || 0), flow.severity)
    const trace_summary = summarizeTrace(flow, path)
    const attack_vectors = Array.isArray(flow.attack_vectors) && flow.attack_vectors.length
      ? flow.attack_vectors
      : (flow.input_surface?.params || []).map((param) => ({ kind: 'external', label: param }))
    const cross_file = new Set(path.map((step) => step.file).filter(Boolean)).size > 1
    const sourceStep = path.find((step) => String(step.role || '').toLowerCase() === 'source') || path[0]
    const sinkStep = [...path].reverse().find((step) => String(step.role || '').toLowerCase() === 'sink') || path[path.length - 1]
    return {
      ...flow,
      severity,
      path,
      trace_status: normalizeTraceStatus(flow),
      trace_summary,
      attack_vectors,
      cross_file,
      source: flow.source || sourceStep?.file || '',
      source_line: flow.source_line || sourceStep?.line || '',
      sink_file: sinkStep?.file || flow.file || '',
      sink_line: sinkStep?.line || flow.line || '',
    }
  })

  const flowIndex = new Map()
  for (const flow of flows) {
    const sinkFile = String(flow.sink_file || flow.file || '')
    const sinkLine = Number(flow.sink_line || flow.line || 0)
    const sourceFile = String(flow.source_file || flow.source || '')
    const sourceLine = Number(flow.source_line || 0)
    const sinkName = String(flow.title || '').trim()
    for (const key of [
      `${sinkFile}::${sinkLine}`,
      `${sinkFile}`,
      `${sourceFile}::${sourceLine}::${sinkFile}::${sinkLine}`,
      `${sourceFile}::${sourceLine}`,
      `${sinkName}::${sinkFile}::${sinkLine}`,
    ]) {
      if (!flowIndex.has(key)) flowIndex.set(key, flow)
    }
  }

  const vulnerabilities = platformResults.flatMap((result) => (
    (result?.security_inventory?.vulnerabilities || []).map((entry) => {
      const file = String(entry?.file || '')
      const line = Number(entry?.line || 0)
      const sourceFile = String(entry?.source || '').split(':')[0] || ''
      const sourceLine = Number(String(entry?.source || '').split(':')[1] || 0)
      const sinkName = String(entry?.sink_name || entry?.title || '')
      const flow = (
        flowIndex.get(`${file}::${line}`) ||
        flowIndex.get(`${sourceFile}::${sourceLine}::${file}::${line}`) ||
        flowIndex.get(`${sourceFile}::${sourceLine}`) ||
        flowIndex.get(`${sinkName}::${file}::${line}`) ||
        flowIndex.get(`${file}`)
      )
      const severity = severityFromScore(Number(entry?.risk_score || flow?.risk_score || 0), entry?.severity || flow?.severity)
      return {
        ...entry,
        severity,
        trace_status: normalizeTraceStatus(entry?.trace_status ? entry : flow),
        path: flow?.path || [],
        path_length: flow?.path?.length || entry?.path_length || 0,
        trace_summary: flow?.trace_summary || summarizeTrace({
          ...entry,
          sink: entry?.sink_name || entry?.sink,
          description: entry?.description || entry?.reason,
        }, flow?.path || []),
        input_surface: flow?.input_surface || entry?.input_surface || {},
        attack_vectors: flow?.attack_vectors || entry?.attack_vectors || [],
        cross_file: flow?.cross_file ?? entry?.cross_file,
        source: entry?.source || flow?.source || '',
        source_line: flow?.source_line || '',
        sink_file: flow?.sink_file || entry?.file || '',
        sink_line: flow?.sink_line || entry?.line || '',
      }
    })
  ))

  const grouped = new Map()
  for (const item of vulnerabilities) {
    const key = familyKey(item)
    const current = grouped.get(key) || {
      key,
      title: item.title || item.kind || 'Vulnerability',
      kind: item.kind || '',
      cwe: item.cwe || '',
      platform: item.platform || '',
      severity: item.severity,
      reason: item.reason || item.description || '',
      explanation: item.explanation || '',
      items: [],
      files: new Set(),
      vectors: new Map(),
    }
    current.items.push(item)
    current.files.add(shortLoc(item))
    if (severityRank(item.severity) < severityRank(current.severity)) current.severity = item.severity
    for (const vector of item.attack_vectors || []) {
      const label = String(vector?.label || '').trim()
      if (label && !current.vectors.has(label)) current.vectors.set(label, vector)
    }
    grouped.set(key, current)
  }

  const families = Array.from(grouped.values())
    .map((group) => ({
      ...group,
      items: group.items.sort((a, b) => (
        Number(b.risk_score || 0) - Number(a.risk_score || 0) ||
        String(a.file || '').localeCompare(String(b.file || '')) ||
        Number(a.line || 0) - Number(b.line || 0)
      )),
      files: Array.from(group.files),
      vectors: Array.from(group.vectors.values()),
      traceCount: group.items.filter((item) => item.trace_status === 'complete').length,
      maxRisk: Math.max(...group.items.map((item) => Number(item.risk_score || 0)), 0),
    }))
    .sort((a, b) => (
      severityRank(a.severity) - severityRank(b.severity) ||
      b.items.length - a.items.length ||
      b.maxRisk - a.maxRisk
    ))

  const mitigations = platformResults.flatMap((item) => item?.security_inventory?.mitigations || [])
  const falsePositives = platformResults.flatMap((item) => item?.security_inventory?.false_positives || [])
  const manualReviews = platformResults.flatMap((item) => item?.security_inventory?.manual_reviews || [])
  return {
    summary: analysis?.summary || {},
    vulnerabilities,
    families,
    mitigations,
    mitigationFamilies: groupMitigations(mitigations),
    falsePositives,
    falsePositiveFamilies: groupFalsePositives(falsePositives),
    manualReviews,
    manualReviewFamilies: groupManualReviews(manualReviews),
  }
}

function SeverityBadge({ value }) {
  const level = String(value || 'low').toLowerCase()
  return <span className={`aa-pill severity ${level}`}>{level}</span>
}

function TraceBadge({ value }) {
  const status = String(value || 'complete').toLowerCase() === 'partial' ? 'partial' : 'complete'
  return <span className={`aa-pill trace ${status}`}>{status}</span>
}

function FamilySummary({ family, open, onToggle }) {
  return (
    <button className={`vg-family-head${open ? ' open' : ''}`} onClick={onToggle}>
      <div className="vg-family-head-main">
        <div className="vg-family-title-row">
          <SeverityBadge value={family.severity} />
          <div className="vg-family-title">{family.title}</div>
          <span className="vg-family-count">{family.items.length} instance{family.items.length === 1 ? '' : 's'}</span>
        </div>
        <div className="vg-family-meta">
          <span>{family.cwe || family.kind || 'Analyzer-confirmed family'}</span>
          <span>{family.files.length} location{family.files.length === 1 ? '' : 's'}</span>
          <span>{family.items.length} trace{family.items.length === 1 ? '' : 's'}</span>
          <span>max score {family.maxRisk}</span>
        </div>
      </div>
      <div className="vg-family-head-side">
        {(family.vectors || []).slice(0, 3).map((vector) => (
          <span key={vector.label} className="aa-tag">{vector.label}</span>
        ))}
        <span className="vg-caret">{open ? '▲' : '▼'}</span>
      </div>
    </button>
  )
}

function InstanceDetail({ item }) {
  if (!item) return <div className="empty-msg">Choose an instance to inspect the exact sink path and trace context.</div>
  const pathGroups = pathByFile(item.path)
  const nodes = (() => {
    const path = Array.isArray(item.path) ? item.path.filter(Boolean) : []
    if (!path.length) {
      return [
        { key: 'src', role: 'source', label: item.source_symbol || 'input', loc: shortPath(item.source) || 'source' },
        { key: 'sink', role: 'sink', label: item.sink_name || item.sink || 'sink', loc: shortLoc(item) },
      ]
    }
    const first = path[0]
    const last = path[path.length - 1]
    const middle = Math.max(path.length - 2, 0)
    const out = [
      { key: 'src', role: 'source', label: item.trace_summary?.taintedInput || item.source_symbol || 'input', loc: shortLocation(first.file, first.line) },
    ]
    if (middle > 0) out.push({ key: 'mid', role: 'step', label: `${middle} propagation step${middle > 1 ? 's' : ''}`, loc: item.cross_file ? 'cross-file' : 'same-file' })
    out.push({ key: 'sink', role: 'sink', label: item.sink_name || item.sink || 'sink', loc: shortLocation(last.file, last.line) })
    return out
  })()

  return (
    <div className="vg-detail">
      <div className="vg-detail-head">
        <div>
          <div className="vg-detail-title">{shortLoc(item)}</div>
          <div className="vg-detail-sub">{item.function ? `${item.function} · ` : ''}{channelLabel(item)} · {item.platform || 'platform'}</div>
        </div>
        <div className="vg-detail-pills">
          <span className="aa-pill plain">score {item.risk_score}</span>
          <TraceBadge value={item.trace_status} />
        </div>
      </div>

      <div className="vg-detail-grid source-row">
        <div className="vg-mini-card source">
          <span>Source</span>
          <code>{item.source || '-'}</code>
        </div>
      </div>

      <div className="vg-detail-grid compact">
        <div className="vg-mini-card">
          <span>Sink</span>
          <code>{item.sink_name || item.sink || '-'}</code>
        </div>
        <div className="vg-mini-card">
          <span>Input</span>
          <code>{(item.input_surface?.params || []).join(', ') || item.source_symbol || item.trace_summary?.taintedInput || '-'}</code>
        </div>
        <div className="vg-mini-card">
          <span>Trace</span>
          <code>{item.path_length || item.path?.length || 0} nodes{item.cross_file ? ' · cross-file' : ''}</code>
        </div>
      </div>

      <div className="vg-trace">
        <div className="vg-section-label">Graphical Taint Path</div>
        <div className="vg-trace-row">
          {nodes.map((node, index) => (
            <div key={node.key} className="vg-trace-step-wrap">
              <div className={`vg-trace-step ${node.role}`}>
                <strong>{node.label}</strong>
                <span>{node.loc}</span>
              </div>
              {index < nodes.length - 1 ? <div className="vg-trace-arrow">→</div> : null}
            </div>
          ))}
        </div>
        <p className="vg-trace-copy">{item.trace_summary?.inputSummary || item.description || item.reason}</p>
      </div>

      {pathGroups.length ? (
        <div className="vg-snippets">
          <div className="vg-section-label">Affected Code Path</div>
          <div className="vg-snippet-groups">
            {pathGroups.map((group, groupIndex) => (
              <div key={`${group.fileKey}-${groupIndex}`} className="vg-snippet-group">
                {(() => {
                  const nextGroup = pathGroups[groupIndex + 1]
                  const hasCrossFileHop = !!(nextGroup && nextGroup.fileKey !== group.fileKey)
                  return (
                <div className="vg-snippet-head">
                  <div className="vg-snippet-file">{group.file || group.fileKey}</div>
                  <div className="vg-snippet-meta">
                    {group.steps.length} step{group.steps.length === 1 ? '' : 's'}
                    {hasCrossFileHop ? ' · cross-file hop' : ''}
                  </div>
                </div>
                  )
                })()}
                <div className="vg-code-viewer">
                  {group.steps.map((step, index) => {
                    const snippet = snippetRows(step)
                    return (
                    <div key={`${group.fileKey}-${step.line || index}-${index}`} className={`vg-code-block role-${String(step.role || 'step').toLowerCase()}`}>
                      <div className="vg-code-rolebar">
                        <div className="vg-code-role">{String(step.role || 'step').toUpperCase()}</div>
                        {step.line ? <div className="vg-code-loc">{shortLocation(step.file, step.line)}</div> : null}
                      </div>
                      <div className="vg-code-viewer">
                        {snippet.rows.map((row, rowIndex) => (
                          <div key={`${group.fileKey}-${step.line || index}-${row.line || rowIndex}-${rowIndex}`} className={`vg-code-row${row.isMatch ? ' match' : ''}`}>
                            <span className="vg-code-line">{row.line || ''}</span>
                            <code className="vg-code-text">{row.code}</code>
                          </div>
                        ))}
                      </div>
                      {snippet.analyzerNote ? (
                        <div className="vg-code-note">Analyzer note: {snippet.analyzerNote}</div>
                      ) : null}
                    </div>
                  )})}
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {(item.attack_vectors || []).length ? (
        <div className="vg-chip-row">
          {(item.attack_vectors || []).slice(0, 5).map((vector) => (
            <span key={`${vector.kind}-${vector.label}`} className="aa-tag">{vector.label}</span>
          ))}
        </div>
      ) : null}

      <p className="vg-body-copy">{item.reason}</p>
      {item.explanation ? <p className="vg-body-sub">{item.explanation}</p> : null}
      {item.matching_mitigation_count > 0 ? (
        <div className="vg-note">Mitigated implementations of the same class also exist in this scan: {item.matching_mitigation_count}</div>
      ) : null}
    </div>
  )
}

function FamilyBlock({ family, open, onToggle }) {
  const [selectedId, setSelectedId] = useState(family.items[0]?.id || '')
  const selected = family.items.find((item) => item.id === selectedId) || family.items[0]

  useEffect(() => {
    if (!family.items.some((item) => item.id === selectedId)) {
      setSelectedId(family.items[0]?.id || '')
    }
  }, [family, selectedId])

  return (
    <section className={`vg-family${open ? ' open' : ''}`}>
      <FamilySummary family={family} open={open} onToggle={onToggle} />
      {open ? (
        <div className="vg-family-body">
          <div className="vg-instance-list">
            {family.items.map((item, index) => (
              <button
                key={item.id || `${family.key}-${index}`}
                className={`vg-instance-row${selected?.id === item.id ? ' active' : ''}`}
                onClick={() => setSelectedId(item.id)}
              >
                <div className="vg-instance-row-top">
                  <strong>{shortLoc(item)}</strong>
                  <span className="vg-instance-score">score {item.risk_score}</span>
                </div>
                <div className="vg-instance-row-sub">
                  <span>{item.function || item.sink_name || item.sink || item.kind}</span>
                  <span>{(item.input_surface?.params || []).join(', ') || item.source_symbol || item.trace_summary?.taintedInput || 'input unresolved'}</span>
                </div>
              </button>
            ))}
          </div>
          <InstanceDetail item={selected} />
        </div>
      ) : null}
    </section>
  )
}

export default function VulnerabilitiesPanel({ analysis }) {
  const model = useMemo(() => buildModel(analysis), [analysis])
  const [openFamilies, setOpenFamilies] = useState({})
  const [activeSection, setActiveSection] = useState('summary')

  useEffect(() => {
    const first = model.families[0]?.key
    setOpenFamilies(first ? { [first]: true } : {})
  }, [model.families])

  useEffect(() => {
    const sections = [
      'summary',
      model.families.length ? 'confirmed' : null,
      model.falsePositiveFamilies.length ? 'false_positives' : null,
      model.manualReviewFamilies.length ? 'manual_review' : null,
      model.mitigationFamilies.length ? 'mitigations' : null,
    ].filter(Boolean)
    if (!sections.includes(activeSection)) {
      setActiveSection(sections[0] || 'confirmed')
    }
  }, [
    activeSection,
    model.families.length,
    model.falsePositiveFamilies.length,
    model.manualReviewFamilies.length,
    model.mitigationFamilies.length,
  ])

  if (!analysis?.results?.length) {
    return (
      <div className="empty-state" style={{ padding: '40px 20px' }}>
        <div className="empty-title">No analyzer data</div>
        <div className="empty-msg">Run a scan with analyzer support to confirm vulnerabilities and mitigated implementations.</div>
      </div>
    )
  }

  const severityCounts = model.vulnerabilities.reduce((acc, item) => {
    const key = String(item.severity || 'low').toLowerCase()
    acc[key] = (acc[key] || 0) + 1
    return acc
  }, {})

  const sectionTabs = [
    {
      key: 'summary',
      label: 'Summary',
      icon: <SummaryTabIcon />,
      tone: 'summary',
      count: [
        model.summary?.confirmed_vulnerabilities ?? model.vulnerabilities.length,
        model.summary?.suppressed_false_positives ?? model.falsePositives.length,
        model.summary?.manual_review_recommended ?? model.manualReviews.length,
        model.summary?.mitigated_implementations ?? model.mitigations.length,
      ].reduce((sum, value) => sum + Number(value || 0), 0),
      helper: 'High-level analyzer outcome overview',
    },
    {
      key: 'confirmed',
      label: 'Confirmed Vulnerabilities',
      icon: <VulnerabilityTabIcon />,
      tone: 'confirmed',
      count: model.summary?.confirmed_vulnerabilities ?? model.vulnerabilities.length,
      helper: `${model.families.length} grouped famil${model.families.length === 1 ? 'y' : 'ies'}`,
    },
    {
      key: 'false_positives',
      label: 'Suppressed False Positives',
      icon: <SuppressedTabIcon />,
      tone: 'suppressed',
      count: model.summary?.suppressed_false_positives ?? model.falsePositives.length,
      helper: model.falsePositiveFamilies.length ? `${model.falsePositiveFamilies.length} grouped rule famil${model.falsePositiveFamilies.length === 1 ? 'y' : 'ies'}` : 'No suppressed hits',
    },
    {
      key: 'manual_review',
      label: 'Manual Inspection Recommended',
      icon: <ManualReviewTabIcon />,
      tone: 'manual',
      count: model.summary?.manual_review_recommended ?? model.manualReviews.length,
      helper: model.manualReviewFamilies.length ? `${model.manualReviewFamilies.length} grouped review famil${model.manualReviewFamilies.length === 1 ? 'y' : 'ies'}` : 'No manual review backlog',
    },
    {
      key: 'mitigations',
      label: 'Mitigated Implementations',
      icon: <MitigationTabIcon />,
      tone: 'mitigated',
      count: model.summary?.mitigated_implementations ?? model.mitigations.length,
      helper: model.mitigationFamilies.length ? `${model.mitigationFamilies.length} grouped mitigation famil${model.mitigationFamilies.length === 1 ? 'y' : 'ies'}` : 'No mitigation patterns',
    },
  ]

  return (
    <div className="vg-panel">
      <div className="vg-subtabs" role="tablist" aria-label="Vulnerability result groups">
        {sectionTabs.map((tab) => (
          <button
            key={tab.key}
            type="button"
            role="tab"
            aria-selected={activeSection === tab.key}
            className={`vg-subtab tone-${tab.tone} ${activeSection === tab.key ? 'active' : ''}`}
            onClick={() => setActiveSection(tab.key)}
          >
            <span className="vg-subtab-icon">{tab.icon}</span>
            <span className="vg-subtab-copy">
              <span className="vg-subtab-title">{tab.label}</span>
              <span className="vg-subtab-meta">{tab.helper}</span>
            </span>
            <span className="vg-subtab-count">{tab.count}</span>
          </button>
        ))}
      </div>

      {activeSection === 'summary' ? (
        <section className="vg-section vg-subsection">
          <div className="vg-section-head">
            <div>
              <h3>Summary</h3>
              <p>Review the analyzer outcome at a glance, then switch to the relevant subsection for the full-width details.</p>
            </div>
          </div>
          <div className="vg-summary-grid">
            <div className="vg-summary-card">
              <div className="vg-summary-label">Confirmed Vulnerabilities</div>
              <div className="vg-summary-value">{model.summary?.confirmed_vulnerabilities ?? model.vulnerabilities.length}</div>
              <div className="vg-summary-sub">Grouped into {model.families.length} vulnerability famil{model.families.length === 1 ? 'y' : 'ies'} to reduce repeated cards and repeated sink logic.</div>
              <div className="vg-summary-chips">
                {SEVERITY_ORDER.map((level) => (
                  <span key={level} className={`vg-sev-chip ${level}`}>{level} {severityCounts[level] || 0}</span>
                ))}
              </div>
            </div>
            <div className="vg-summary-card">
              <div className="vg-summary-label">Mitigated Implementations</div>
              <div className="vg-summary-value">{model.summary?.mitigated_implementations ?? model.mitigations.length}</div>
              <div className="vg-summary-sub">Defensive patterns are also grouped by class so related safe implementations stay visible without dominating the page.</div>
            </div>
            <div className="vg-summary-card">
              <div className="vg-summary-label">Validated AOIs</div>
              <div className="vg-summary-value">{model.summary?.validated_findings ?? 0}</div>
              <div className="vg-summary-sub">Areas of interest that the analyzer could actually connect to a reachable vulnerable path.</div>
            </div>
            <div className="vg-summary-card">
              <div className="vg-summary-label">Suppressed False Positives</div>
              <div className="vg-summary-value">{model.summary?.suppressed_false_positives ?? model.falsePositives.length}</div>
              <div className="vg-summary-sub">Scanner hits suppressed by analyzer review because no matching source-to-sink path survived technical validation.</div>
            </div>
            <div className="vg-summary-card">
              <div className="vg-summary-label">Manual Inspection Recommended</div>
              <div className="vg-summary-value">{model.summary?.manual_review_recommended ?? model.manualReviews.length}</div>
              <div className="vg-summary-sub">Areas of interest that the analyzer could not evaluate automatically yet, so they remain open for human review.</div>
            </div>
          </div>
        </section>
      ) : null}

      {activeSection === 'confirmed' ? (
        <section className="vg-section vg-subsection">
          <div className="vg-section-head">
            <div>
              <h3>Confirmed Vulnerabilities</h3>
              <p>Families are grouped by vulnerability class. Expand only the class you want, then inspect the exact instance in the compact detail panel.</p>
            </div>
          </div>
          {model.families.length ? (
            <div className="vg-family-list">
              {model.families.map((family) => (
                <FamilyBlock
                  key={family.key}
                  family={family}
                  open={!!openFamilies[family.key]}
                  onToggle={() => setOpenFamilies((prev) => ({ ...prev, [family.key]: !prev[family.key] }))}
                />
              ))}
            </div>
          ) : (
            <div className="empty-msg">No confirmed vulnerabilities were derived from the current analyzer results.</div>
          )}
        </section>
      ) : null}

      {activeSection === 'false_positives' ? (
        <section className="vg-section vg-subsection">
          <div className="vg-section-head">
            <div>
              <h3>Suppressed False Positives</h3>
              <p>These rule hits were reviewed against analyzer output and suppressed because the analyzer could not validate them as reachable vulnerabilities. Each item includes the technical rationale.</p>
            </div>
          </div>
          {model.falsePositiveFamilies.length ? (
            <div className="vg-mitigation-list">
              {model.falsePositiveFamilies.map((group) => (
                <div key={group.key} className="vg-mitigation-card">
                  <div className="vg-mitigation-head">
                    <div>
                      <div className="vg-mitigation-title">{group.title}</div>
                      <div className="vg-mitigation-sub">{group.items.length} suppressed hit{group.items.length === 1 ? '' : 's'}{group.kind ? ` · ${group.kind}` : ''}</div>
                    </div>
                    <span className="aa-pill plain">suppressed</span>
                  </div>
                  <div className="vg-mitigation-list">
                    {group.items.map((item, index) => (
                      <div key={item.id || index} className="vg-mitigation-file">
                        <strong>{item.evidence?.[0]?.file ? shortLocation(item.evidence[0].file, item.evidence[0].line) : item.platform || 'location unresolved'}</strong>
                        {item.issue_desc ? <div className="vg-body-sub">{item.issue_desc}</div> : null}
                        <code>{item.technical_rationale}</code>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-msg">No areas of interest were suppressed as false positives by the analyzer in this scan.</div>
          )}
        </section>
      ) : null}

      {activeSection === 'manual_review' ? (
        <section className="vg-section vg-subsection">
          <div className="vg-section-head">
            <div>
              <h3>Manual Inspection Recommended</h3>
              <p>These areas of interest were not auto-suppressed. Automatic analyzer support is not available for the platform or issue type yet, so manual review is still required.</p>
            </div>
          </div>
          {model.manualReviewFamilies.length ? (
            <div className="vg-mitigation-list">
              {model.manualReviewFamilies.map((group) => (
                <div key={group.key} className="vg-mitigation-card">
                  <div className="vg-mitigation-head">
                    <div>
                      <div className="vg-mitigation-title">{group.title}</div>
                      <div className="vg-mitigation-sub">{group.items.length} review candidate{group.items.length === 1 ? '' : 's'}{group.kind ? ` · ${group.kind}` : ''}</div>
                    </div>
                    <span className="aa-pill plain">manual review</span>
                  </div>
                  <div className="vg-mitigation-list">
                    {group.items.map((item, index) => (
                      <div key={item.id || index} className="vg-mitigation-file">
                        <strong>{item.evidence?.[0]?.file ? shortLocation(item.evidence[0].file, item.evidence[0].line) : item.platform || 'location unresolved'}</strong>
                        {item.issue_desc ? <div className="vg-body-sub">{item.issue_desc}</div> : null}
                        <code>{item.technical_rationale}</code>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-msg">No areas of interest currently require manual inspection due to unsupported automatic analysis.</div>
          )}
        </section>
      ) : null}

      {activeSection === 'mitigations' ? (
        <section className="vg-section vg-subsection">
          <div className="vg-section-head">
            <div>
              <h3>Mitigated Implementations</h3>
              <p>Related safe implementations are grouped so you can see repeated secure patterns without another long card stack.</p>
            </div>
          </div>
          {model.mitigationFamilies.length ? (
            <div className="vg-mitigation-list">
              {model.mitigationFamilies.map((group) => (
                <div key={group.key} className="vg-mitigation-card">
                  <div className="vg-mitigation-head">
                    <div>
                      <div className="vg-mitigation-title">{group.title}</div>
                      <div className="vg-mitigation-sub">{group.items.length} implementation{group.items.length === 1 ? '' : 's'} · {group.kind || 'mitigation pattern'}</div>
                    </div>
                    <span className="aa-pill plain">mitigated</span>
                  </div>
                  <div className="vg-mitigation-context">
                    {group.description ? (
                      <div className="vg-mitigation-detail">
                        <span>Mitigation detected</span>
                        <p>{group.description}</p>
                      </div>
                    ) : null}
                    {group.whatItDoes ? (
                      <div className="vg-mitigation-detail">
                        <span>How it mitigates</span>
                        <p>{group.whatItDoes}</p>
                      </div>
                    ) : null}
                    {group.effectiveness ? (
                      <div className="vg-mitigation-detail">
                        <span>Effectiveness</span>
                        <p>{group.effectiveness}</p>
                      </div>
                    ) : null}
                    {group.modernity ? (
                      <div className="vg-mitigation-detail">
                        <span>Modernity</span>
                        <p>{group.modernity}</p>
                      </div>
                    ) : null}
                    {group.implementation ? (
                      <div className="vg-mitigation-detail">
                        <span>Implementation quality</span>
                        <p>{group.implementation}</p>
                      </div>
                    ) : null}
                    {group.recommendation ? (
                      <div className="vg-mitigation-detail">
                        <span>Recommendation</span>
                        <p>{group.recommendation}</p>
                      </div>
                    ) : null}
                  </div>
                  <div className="vg-mitigation-files">
                    {group.items.slice(0, 10).map((item, index) => (
                      <div key={item.id || index} className="vg-mitigation-file">
                        <strong>{shortLoc(item)}</strong>
                        {item.description ? <div className="vg-body-sub">{item.description}</div> : null}
                        {item.evidence ? <code>{item.evidence}</code> : null}
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-msg">No mitigation patterns were identified for this scan.</div>
          )}
        </section>
      ) : null}
    </div>
  )
}
