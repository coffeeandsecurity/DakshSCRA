// Distinct projections of the same recorded evidence, without changing verdicts.
export function flowEvidence(finding) {
  const select = items => (Array.isArray(items) ? items : []).filter(item => item.matched !== false && ['SOURCE', 'PROPAGATION', 'SINK'].includes(item.predicate))
  const traced = select(finding.trace?.steps)
  const evidence = select(finding.evidence)
  // Keep each recorded path intact. Never stitch unrelated observations into
  // a path, but do not let an older source-only trace hide fuller evidence.
  const quality = steps => steps.some(item => item.predicate === 'SOURCE')
    ? (steps.some(item => item.predicate === 'SINK') ? 3 : steps.some(item => item.predicate === 'PROPAGATION') ? 2 : 1)
    : 0
  return quality(evidence) > quality(traced) ? evidence : quality(traced) ? traced : evidence
}

export function graphableFlow(finding) {
  const flow = flowEvidence(finding)
  return flow.some(step => step.predicate === 'SOURCE') && flow.some(step => ['PROPAGATION', 'SINK'].includes(step.predicate)) ? flow : []
}

export const locationKey = location => [location?.path || '', location?.line ?? null, location?.column ?? null, location?.end_line ?? null, location?.end_column ?? null]
export const sourceKey = source => JSON.stringify([locationKey(source.location), source.symbol || source.explanation || ''])
const stepKey = step => [step.predicate, locationKey(step.location), step.symbol || step.explanation || '', step.transition || '']
export const flowKey = finding => JSON.stringify(flowEvidence(finding).map(stepKey))

export function collectPaths(items) {
  const paths = new Map()
  for (const item of items) {
    const flow = flowEvidence(item.finding)
    const source = flow.find(step => step.predicate === 'SOURCE')
    if (!source) continue
    const key = flowKey(item.finding)
    if (!paths.has(key)) paths.set(key, { key, source, sink: flow.findLast(step => step.predicate === 'SINK'), flow, items: [] })
    const path = paths.get(key)
    if (!path.items.some(link => link.id === item.id)) path.items.push(item)
  }
  return [...paths.values()]
}

export function handoffs(finding) {
  const flow = flowEvidence(finding)
  if (!flow.some(step => step.predicate === 'SOURCE')) return []
  const edges = []
  for (let i = 1; i < flow.length; i++) {
    const from = flow[i - 1], to = flow[i]
    if (!from.location?.path || !to.location?.path) continue
    const crossFile = from.location.path !== to.location.path
    if (!crossFile && !['argument-parameter', 'return-call'].includes(to.transition)) continue
    const transition = to.transition || ''
    edges.push({ from, to, crossFile, transition, key: JSON.stringify([locationKey(from.location), from.symbol || from.explanation || '', locationKey(to.location), to.symbol || to.explanation || '', transition]) })
  }
  return edges
}

export function collectReferences(items) {
  const references = new Map()
  for (const item of items) {
    for (const edge of handoffs(item.finding)) {
      if (!references.has(edge.key)) references.set(edge.key, { ...edge, items: [] })
      const reference = references.get(edge.key)
      if (!reference.items.some(link => link.id === item.id)) reference.items.push(item)
    }
  }
  return [...references.values()]
}

export function handoffLabel(edge) {
  if (edge.transition === 'argument-parameter') return 'Argument → parameter'
  if (edge.transition === 'return-call') return 'Return → caller'
  return 'File handoff'
}
