// Group consecutive observations only; revisiting a line later is a new event.
function excerptForStep(step, blocks) {
  const block = blocks.get(step.code_block)
  if (block && block.path === step.location?.path) {
    const first = step.location.line
    const last = Math.max(first, step.location.end_line || first)
    return block.lines.filter(line => line.line >= first && line.line <= last)
  }
  return step.snippet || []
}

export function groupTraceSteps(steps, blocks = [], { mergeSameLine = true } = {}) {
  const blockMap = new Map(blocks.map(block => [block.id, block]))
  const groups = []
  for (const step of steps) {
    const excerpt = excerptForStep(step, blockMap)
    const previous = groups.at(-1)
    const location = step.location
    const sameLine = location?.path && Number.isInteger(location.line) && location.line > 0 &&
      previous?.location?.path === location.path && previous.location.line === location.line
    const conflict = sameLine && excerpt.some(line => previous.lines.some(old => old.line === line.line && old.text !== line.text))
    const group = mergeSameLine && sameLine && !conflict ? previous : { steps: [], location, lines: [], links: [] }
    if (group !== previous) groups.push(group)
    group.steps.push(step)
    for (const line of excerpt) {
      const existing = group.lines.find(old => old.line === line.line && old.text === line.text)
      if (existing) existing.highlight ||= Boolean(line.highlight)
      else group.lines.push({ ...line, highlight: Boolean(line.highlight) })
    }
    group.lines.sort((a, b) => a.line - b.line)
    if (step.code_block && location && !group.links.some(link => link.block === step.code_block && link.line === location.line)) {
      group.links.push({ block: step.code_block, line: location.line })
    }
  }
  return groups
}

export const SHORT_TRACE_LABELS = {
  SOURCE: 'Input', SINK: 'Sink', PROPAGATION: 'Transfer', EXISTS: 'Observe',
  'STATE TRANSITION': 'State change', 'STATE VIOLATION': 'State review',
  TEXT_MATCHES: 'Pattern found', TEXT_MISSING: 'Absence check', FILE_NAME_IS: 'File match',
  FILE_PATH_GLOB: 'Path match', PROJECT_OBSERVATION: 'Project check',
}
const SHORT_TRANSITIONS = {
  reference: 'Read', argument: 'Call', assignment: 'Assign', 'argument-parameter': 'Receive parameter',
  return: 'Return', 'return-call': 'Receive return', receiver: 'Use input',
}
export function traceActionLabels(steps) {
  const labels = []
  for (const step of steps) {
    const label = (step.predicate === 'PROPAGATION' && SHORT_TRANSITIONS[step.transition]) || SHORT_TRACE_LABELS[step.predicate] || 'Check'
    const previous = labels.at(-1)
    if (previous?.label === label) previous.count++
    else labels.push({ label, count: 1 })
  }
  return labels.map(item => item.label + (item.count > 1 ? ` ×${item.count}` : ''))
}
