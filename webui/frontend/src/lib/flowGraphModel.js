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
export function graphWindow(steps, requestedStart = 0) {
  const total = Array.isArray(steps) ? steps.length : 0
  requestedStart = Number.isFinite(requestedStart) ? requestedStart : 0
  const start = Math.max(0, Math.min(Math.floor(requestedStart / GRAPH_WINDOW) * GRAPH_WINDOW, Math.max(0, Math.floor((total - 1) / GRAPH_WINDOW) * GRAPH_WINDOW)))
  const slice = Array.isArray(steps) ? steps.slice(start, start + GRAPH_WINDOW) : []
  const lanes = [], laneIndex = new Map()
  const nodes = Array.from(slice).map((step, local) => {
    const node = graphStep(step, start + local)
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
const escape = value => string(value).replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&apos;'}[char]))
export function graphSvg(model) {
  const colors = { source:'#38d9a9',sink:'#ff8796',guard:'#ffd166',review:'#ffd166',step:'#76aaff' }
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${model.width}" height="${model.height}" viewBox="0 0 ${model.width} ${model.height}"><rect width="100%" height="100%" fill="#0b1220"/><text x="24" y="26" fill="#adbcd3" font-family="monospace" font-size="12">Recorded evidence · steps ${model.start+1}–${model.end} of ${model.total} · arrows show recorded order</text>${model.edges.map(e=>`<path d="${edgePath(e)}" stroke="${e.crossFile?'#b9a1ff':'#506889'}" fill="none" stroke-width="2"/><path d="M ${e.to.x+e.to.width/2-5} ${e.to.y-7} l 5 7 l 5 -7" fill="none" stroke="#b9a1ff"/>`).join('')}${model.nodes.map(n=>`<g><rect x="${n.x}" y="${n.y}" width="${n.width}" height="${n.height}" rx="10" fill="#172338" stroke="${colors[n.tone]}"/><text x="${n.x+12}" y="${n.y+22}" fill="${colors[n.tone]}" font-family="monospace" font-size="12">${escape(n.number)} · ${escape(n.role.toUpperCase())}</text><text x="${n.x+12}" y="${n.y+46}" fill="#f0f5ff" font-family="monospace" font-size="12">${escape((n.symbol||n.title).slice(0,32))}</text><text x="${n.x+12}" y="${n.y+70}" fill="#aebed5" font-family="monospace" font-size="11">${escape(shortFile(n.path).slice(0,32))}:${escape(n.line||'?')}</text><text x="${n.x+12}" y="${n.y+94}" fill="#c8d8ed" font-family="monospace" font-size="11">${escape(n.code.slice(0,32))}</text></g>`).join('')}</svg>`
}
