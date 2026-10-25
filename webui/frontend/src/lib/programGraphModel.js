// Layout uses recorded edges. No adjacency is manufactured from source order.
export const PROGRAM_NODE_LIMIT = 250
export const PROGRAM_EDGE_LIMIT = 600
export function programGraphModel(graph, limit = PROGRAM_NODE_LIMIT) {
  const raw = Array.isArray(graph?.nodes) ? graph.nodes : []
  const ids = new Set(raw.map(node => node.id))
  const validEdges = (graph?.edges || []).filter(edge => ids.has(edge.source) && ids.has(edge.target))
  const nodes = raw.slice(0, limit)
  const retained = new Set(nodes.map(node => node.id))
  const edges = validEdges.filter(edge => retained.has(edge.source) && retained.has(edge.target)).slice(0, PROGRAM_EDGE_LIMIT)
  const adjacency = new Map(nodes.map(node => [node.id, []]))
  for (const edge of edges) adjacency.get(edge.source).push(edge.target)
  // Collapse cycles before assigning layers, so loops remain visible and do
  // not make a topological layout grow indefinitely.
  let serial = 0
  const stack = [], indexes = new Map(), low = new Map(), active = new Set(), components = []
  function visit(id) {
    indexes.set(id, serial); low.set(id, serial++); stack.push(id); active.add(id)
    for (const target of adjacency.get(id)) {
      if (!indexes.has(target)) { visit(target); low.set(id, Math.min(low.get(id), low.get(target))) }
      else if (active.has(target)) low.set(id, Math.min(low.get(id), indexes.get(target)))
    }
    if (low.get(id) === indexes.get(id)) {
      const group = []; let current
      do { current = stack.pop(); active.delete(current); group.push(current) } while (current !== id)
      components.push(group.reverse())
    }
  }
  for (const node of nodes) if (!indexes.has(node.id)) visit(node.id)
  const component = new Map(), levels = new Map(), outgoing = new Map(), indegree = new Map()
  components.forEach((group, index) => { group.forEach(id => component.set(id, index)); outgoing.set(index, new Set()); indegree.set(index, 0); levels.set(index, 0) })
  for (const edge of edges) {
    const a = component.get(edge.source), b = component.get(edge.target)
    if (a !== b && !outgoing.get(a).has(b)) { outgoing.get(a).add(b); indegree.set(b, indegree.get(b) + 1) }
  }
  const queue = [...indegree.keys()].filter(id => !indegree.get(id))
  for (let i = 0; i < queue.length; i++) {
    const id = queue[i]
    for (const target of outgoing.get(id)) {
      levels.set(target, Math.max(levels.get(target), levels.get(id) + 1))
      indegree.set(target, indegree.get(target) - 1)
      if (!indegree.get(target)) queue.push(target)
    }
  }
  const rows = new Map(), positioned = nodes.map(node => {
    const column = levels.get(component.get(node.id)) || 0, row = rows.get(column) || 0
    rows.set(column, row + 1)
    return { ...node, x: 40 + column * 290, y: 40 + row * 126, width: 220, height: 82 }
  })
  const byId = new Map(positioned.map(node => [node.id, node]))
  return { nodes: positioned, edges: edges.map((edge, index) => ({ ...edge, id: `${edge.source}-${edge.target}-${index}`, from: byId.get(edge.source), to: byId.get(edge.target), cyclic: component.get(edge.source) === component.get(edge.target) })),
    width: Math.max(480, ...positioned.map(node => node.x + node.width + 70)), height: Math.max(260, ...positioned.map(node => node.y + node.height + 70)),
    totalNodes: raw.length, totalEdges: validEdges.length, truncated: nodes.length < raw.length || edges.length < validEdges.length }
}

export function programEdgePath(edge) {
  const a = edge.from, b = edge.to
  if (edge.source === edge.target) return `M ${a.x + a.width - 24} ${a.y} C ${a.x + a.width + 54} ${a.y - 44}, ${a.x + a.width + 54} ${a.y + 55}, ${a.x + a.width} ${a.y + 30}`
  if (edge.cyclic || b.x <= a.x) return `M ${a.x + a.width / 2} ${a.y + a.height} C ${a.x + a.width / 2 + 80} ${a.y + a.height + 54}, ${b.x + b.width / 2 + 80} ${b.y + b.height + 54}, ${b.x + b.width / 2} ${b.y + b.height}`
  return `M ${a.x + a.width} ${a.y + a.height / 2} C ${a.x + a.width + 40} ${a.y + a.height / 2}, ${b.x - 40} ${b.y + b.height / 2}, ${b.x} ${b.y + b.height / 2}`
}

export function querySavedProgramGraphs(catalog, options = {}) {
  const { search = '', language = 'all', file_id = '', function_id = '', kind = 'cfg' } = options
  const offset = Number(options.offset || 0), limit = 40
  const files = (catalog.files || []).filter(file => (language === 'all' || file.language === language) && file.path.toLowerCase().includes(search.toLowerCase()))
  const selected = (catalog.files || []).find(file => file.id === file_id) || null
  let graph = selected?.[kind] || null
  if (graph) {
    let nodes = graph.nodes || [], edges = graph.edges || []
    if (function_id) {
      const members = new Set(nodes.filter(node => node.function_id === function_id).map(node => node.id))
      edges = edges.filter(edge => members.has(edge.source) || members.has(edge.target))
      const retained = new Set([...members, ...edges.flatMap(edge => [edge.source, edge.target])])
      nodes = nodes.filter(node => retained.has(node.id)).map(node => ({ ...node, boundary: !members.has(node.id) }))
    }
    graph = { ...graph, nodes, edges, kind }
  }
  return { ...catalog, available: true, needs_rebuild: false, files: files.slice(offset, offset + limit), total: files.length, offset, limit, has_more: offset + limit < files.length, selected, graph }
}
