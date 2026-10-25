export const GRAPH_WINDOW = 120
export const NODE_WIDTH = 260
export const NODE_HEIGHT = 112
const string = value => value == null ? '' : String(value)
export const shortFile = path => string(path).split(/[\\/]/).slice(-2).join('/') || 'Location not recorded'
export function graphStep(step, index) {
  step = step && typeof step === 'object' ? step : {}
  const role = string(step.predicate || step.role || 'evidence').slice(0,80).toLowerCase()
  const tone = step.matched === false ? 'review' : role === 'source' ? 'source' : role === 'sink' ? 'sink' : /sanit|valid|guard|protect/.test(role) ? 'guard' : /missing|violation/.test(role) ? 'review' : 'step'
  const snippet = Array.isArray(step.snippet) ? step.snippet : []
  const code = string(step.code || snippet.slice(0,100).find(line => line.highlight)?.text || snippet[0]?.text)
  return { index, number: step.number || index + 1, role, tone, path: string(step.location?.path || step.file || step.path),
    line: step.location?.line || step.line || null, symbol: string(step.symbol || step.target_symbol || step.source_symbol),
    title: string(step.description || step.explanation || step.transition || step.role || step.predicate || 'Recorded evidence'),
    transition: string(step.transition), code, inferred: Boolean(step.inferred), original: step }
}
export function graphWindow(steps, requestedStart = 0, blocks = []) {
  const total = Array.isArray(steps) ? steps.length : 0
  requestedStart = Number.isFinite(requestedStart) ? requestedStart : 0
  const start = Math.max(0, Math.min(Math.floor(requestedStart / GRAPH_WINDOW) * GRAPH_WINDOW, Math.max(0, Math.floor((total - 1) / GRAPH_WINDOW) * GRAPH_WINDOW)))
  const slice = Array.isArray(steps) ? steps.slice(start, start + GRAPH_WINDOW) : []
  const lanes = [], laneIndex = new Map()
  const nodes = Array.from(slice).map((step, local) => {
    const node = graphStep(step, start + local)
    const evidence = evidenceLines(node, blocks)
    const selected = evidence.lines.find(line => line.selected)
    if (selected) node.code = selected.text
    node.codePreview = codePreview(selected || { text: node.code, spans: [] })
    const key = node.path || 'Location not recorded'
    if (!laneIndex.has(key)) {
      const lane = Math.min(lanes.length, 7)
      laneIndex.set(key, lane)
      if (lanes.length < 8) lanes.push(key)
      else lanes[7] = 'Additional files'
    }
    const lane = laneIndex.get(key)
    return { ...node, lane, x: 36 + lane * 304, y: 64 + local * 156, width: NODE_WIDTH, height: NODE_HEIGHT }
  })
  const edges = nodes.slice(1).map((node, i) => ({ from: nodes[i], to: node, crossFile: Boolean(nodes[i].path && node.path && nodes[i].path !== node.path), label: node.transition || 'Recorded order' }))
  return { nodes, edges, lanes, start, total, end: start + nodes.length, width: Math.max(340, lanes.length * 304 + 36), height: Math.max(240, nodes.length * 156 + 64) }
}
export function edgePath(edge) {
  const a = edge.from, b = edge.to
  const x1 = a.x + a.width / 2, y1 = a.y + a.height, x2 = b.x + b.width / 2, y2 = b.y
  return `M ${x1} ${y1} C ${x1} ${y1 + 22}, ${x2} ${y2 - 22}, ${x2} ${y2}`
}
export function visibleNodes(model, view, width, height) {
  const left = -view.x / view.zoom, top = -view.y / view.zoom
  return model.nodes.filter(n => n.x + n.width >= left && n.x <= left + width / view.zoom && n.y + n.height >= top && n.y <= top + height / view.zoom)
}
export function evidenceText(node, blocks = [], limit = 16000) {
  if (!node) return ''
  const step = node.original
  const block = (step.code_block ? blocks.find(item => item.id === step.code_block) : null) || blocks.find(item => item.path === node.path && item.start <= node.line && item.end >= node.line)
  const lines = block?.lines || step.snippet
  if (!Array.isArray(lines) || !lines.length) return node.code.slice(0, limit)
  let result = ''
  for (let i=0; i<lines.length && result.length<limit; i++) {
    result += `${lines[i].line ?? ''}  ${string(lines[i].text).slice(0, limit-result.length)}\n`
  }
  return result.slice(0,limit)
}
// Columns are one-based and end columns are exclusive in recorded locations.
// Only the selected step's location establishes an inline taint span.
export function evidenceLines(node, blocks = [], limit = 16000) {
  if (!node) return { lines: [], precise: false, symbolMatched: false, truncated: false }
  const step = node.original, location = step.location || {}
  const sameFile = block => !node.path || !block.path || block.path === node.path
  const block = blocks.find(item => item.id === step.code_block && sameFile(item)) ||
    blocks.find(item => sameFile(item) && item.start <= node.line && item.end >= node.line)
  let lines = block?.lines || step.snippet
  if (!Array.isArray(lines) || !lines.length) lines = node.code ? [{ line: node.line, text: node.code }] : []
  const selectedIndex = lines.findIndex(row => Number(row.line) === Number(node.line))
  const first = Math.max(0, selectedIndex - 20)
  const retained = lines.slice(first, first + 40)
  const budget = Math.max(1, Math.floor(limit / Math.max(1, retained.length)))
  let precise = false, symbolMatched = false, truncated = first > 0 || retained.length < lines.length
  const result = retained.map(row => {
    let text = string(row.text), spans = []
    const line = Number(row.line), selected = line === Number(node.line)
    const endLine = Number(location.end_line || node.line)
    if (Number.isInteger(location.column) && location.column > 0 && line >= Number(node.line) && line <= endLine) {
      const start = selected ? location.column - 1 : 0
      let end = line === endLine ? Number(location.end_column) - 1 : text.length
      if (!Number.isFinite(end) || end <= start) end = start + 1
      // A receiver token's location may cover only its first identifier.
      // Extend it only when the exact recorded symbol begins at that column.
      const symbol = node.symbol
      if (selected && endLine === line && symbol && text.startsWith(symbol, start)) end = Math.max(end, start + symbol.length)
      if (start < text.length) spans = [{ start, end: Math.min(text.length, end), basis: 'location' }]
    } else if (selected && !location.column && node.symbol) {
      // Older analyzers record a symbol and line but no columns. Highlight
      // it only if a single complete occurrence establishes its position.
      const symbol = node.symbol, matches = []
      let at = text.indexOf(symbol)
      while (at >= 0 && matches.length < 2) {
        const before = text[at-1] || '', after = text[at+symbol.length] || ''
        if ((!/[\w$]/.test(symbol[0]) || !/[\w$]/.test(before)) &&
            (!/[\w$]/.test(symbol.at(-1)) || !/[\w$]/.test(after))) matches.push(at)
        at = text.indexOf(symbol,at+Math.max(1,symbol.length))
      }
      if (matches.length === 1) spans = [{ start:matches[0], end:matches[0]+symbol.length, basis:'symbol' }]
    }
    const offset = text.length > budget && spans.length ? Math.max(0, Math.min(spans[0].start - 80, text.length - budget)) : 0
    const clipped = offset > 0 || text.length > budget
    truncated ||= clipped
    text = text.slice(offset, offset + budget)
    spans = spans.map(span => ({ ...span, start: Math.max(0, span.start-offset), end: Math.min(text.length, span.end-offset) })).filter(span => span.end > span.start)
    precise ||= spans.some(span => span.basis === 'location')
    symbolMatched ||= spans.some(span => span.basis === 'symbol')
    return { line: row.line, text, selected, highlighted: Boolean(row.highlight), spans, offset, clipped }
  })
  return { lines: result, precise, symbolMatched, truncated }
}
const syntax = /\/\/[^\n]*|\/\*[\s\S]*?\*\/|#[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`|\b(?:class|function|def|return|public|private|protected|static|new|const|let|var|if|else|import|from|namespace|use|void|int|String|async|await|throw|try|catch|for|while|true|false|null)\b|\b\d+(?:\.\d+)?\b/g
export function codeSegments(text, spans = []) {
  text = string(text)
  const tokens = Array.from(text.matchAll(syntax), match => ({ start: match.index, end: match.index + match[0].length,
    tone: /^(?:\/\/|\/\*|#)/.test(match[0]) ? 'comment' : /^["'`]/.test(match[0]) ? 'string' : /^\d/.test(match[0]) ? 'number' : 'keyword' }))
  const boundaries = [...new Set([0, text.length, ...tokens.flatMap(t => [t.start,t.end]), ...spans.flatMap(s => [s.start,s.end])])].filter(n => n >= 0 && n <= text.length).sort((a,b) => a-b)
  let tokenIndex = 0
  return boundaries.slice(0,-1).map((start,index) => {
    const end = boundaries[index+1]
    while (tokens[tokenIndex]?.end <= start) tokenIndex++
    const token = tokens[tokenIndex]
    return { text: text.slice(start,end), tone: token?.start <= start && token.end >= end ? token.tone : '', tainted: spans.some(span => start < span.end && end > span.start) }
  })
}
export function codePreview(row, limit = 32) {
  const text = string(row.text)
  const start = row.spans?.[0]?.start ?? 0
  const offset = Math.max(0, start - 8)
  const visible = text.slice(offset, offset + limit)
  const spans = (row.spans || []).map(span => ({ start: Math.max(0,span.start-offset), end: Math.min(visible.length,span.end-offset) })).filter(span => span.end > span.start)
  return codeSegments(visible, spans)
}
const escape = value => string(value).replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&apos;'}[char]))
export function graphSvg(model) {
  const colors = { source:'#38d9a9',sink:'#ff8796',guard:'#ffd166',review:'#ffd166',step:'#76aaff' }
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${model.width}" height="${model.height}" viewBox="0 0 ${model.width} ${model.height}"><rect width="100%" height="100%" fill="#0b1220"/><text x="24" y="26" fill="#adbcd3" font-family="monospace" font-size="12">Recorded evidence · steps ${model.start+1}–${model.end} of ${model.total} · arrows show recorded order</text>${model.edges.map(e=>`<path d="${edgePath(e)}" stroke="${e.crossFile?'#b9a1ff':'#506889'}" fill="none" stroke-width="2"/><path d="M ${e.to.x+e.to.width/2-5} ${e.to.y-7} l 5 7 l 5 -7" fill="none" stroke="#b9a1ff"/>`).join('')}${model.nodes.map(n=>`<g><rect x="${n.x}" y="${n.y}" width="${n.width}" height="${n.height}" rx="10" fill="#172338" stroke="${colors[n.tone]}"/><text x="${n.x+12}" y="${n.y+22}" fill="${colors[n.tone]}" font-family="monospace" font-size="12">${escape(n.number)} · ${escape(n.role.toUpperCase())}</text><text x="${n.x+12}" y="${n.y+46}" fill="#f0f5ff" font-family="monospace" font-size="12">${escape((n.symbol||n.title).slice(0,32))}</text><text x="${n.x+12}" y="${n.y+70}" fill="#aebed5" font-family="monospace" font-size="11">${escape(shortFile(n.path).slice(0,32))}:${escape(n.line||'?')}</text><text x="${n.x+12}" y="${n.y+94}" fill="#c8d8ed" font-family="monospace" font-size="11">${(n.codePreview || codeSegments(n.code.slice(0,32))).map(part => `<tspan fill="${part.tainted ? colors[n.tone] : ({keyword:'#c5a7ff',string:'#b5de9b',number:'#ffcb8b',comment:'#8698b4'}[part.tone] || '#c8d8ed')}"${part.tainted ? ' font-weight="bold" text-decoration="underline"' : ''}>${escape(part.text)}</tspan>`).join('')}</text></g>`).join('')}</svg>`
}
