// Issue families describe observations; individual rule evidence stays available.
const rank = value => ({ CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4, INFORMATIONAL: 4, INFORMATION: 4 })[String(value || '').toUpperCase()] ?? 5
const familyKey = finding => finding.issue_family || String(finding.title || 'Untitled review').trim().toLowerCase()
const stable = value => JSON.stringify(value, (_, item) => item && !Array.isArray(item) && typeof item === 'object' ? Object.fromEntries(Object.keys(item).sort().map(key => [key, item[key]])) : item)
export function occurrenceKey(record, finding) {
  if (finding.occurrence_id) return finding.occurrence_id
  const loc = finding.location || {}
  const path = String(loc.path || finding.path || record.context?.file_path || '').replace(/\\/g, '/')
  const steps = finding.trace?.steps || finding.evidence || []
  const flow = steps.filter(s => s.matched !== false && ['SOURCE', 'PROPAGATION', 'SINK'].includes(s.predicate))
  const anchor = flow.length ? ['flow', flow.map(s => [s.predicate, s.location, s.symbol, s.transition])] : finding.path_only ? ['path'] : finding.occurrence_anchor || (loc.line ? ['location', loc.line, loc.column] : ['unlocated', record.v2_rule_id || record.v2_rule, finding.evidence])
  return stable([familyKey(finding), path, anchor])
}
export function groupFindings(records, totals = []) {
  const totalsByFamily = new Map()
  for (const total of totals) {
    const key = total.issue_family || String(total.title || '').trim().toLowerCase()
    // Older exports split totals by CWE. Without occurrence identities their
    // sum cannot establish a unique count; omit that total until refreshed.
    totalsByFamily.set(key, totalsByFamily.has(key) ? null : total)
  }
  const families = new Map()
  for (const record of records || []) {
    if (record.v2_outcome !== 'MATCH') continue
    for (const finding of record.v2_findings || []) {
      const key = familyKey(finding)
      if (!families.has(key)) families.set(key, { key, title: finding.title, severity: finding.severity, items: [], occurrences: new Map(), cwes: new Set(), totals: totalsByFamily.get(key) })
      const family = families.get(key)
      if (finding.cwe) family.cwes.add(finding.cwe)
      if (rank(finding.severity) < rank(family.severity)) family.severity = finding.severity
      const id = occurrenceKey(record, finding)
      const contribution = { record, finding }
      let item = family.occurrences.get(id)
      if (!item) {
        item = { id, finding, record, contributions: [], seen: new Set(), focusIds: [] }
        family.occurrences.set(id, item); family.items.push(item)
      }
      item.focusIds.push(JSON.stringify([record.v2_rule_id || record.v2_rule, finding.location, finding.path || record.context?.file_path, finding.evidence?.length ? finding.evidence : finding.trace?.steps]))
      const evidenceId = stable([record.v2_rule_id || record.v2_rule, finding])
      if (!item.seen.has(evidenceId)) { item.seen.add(evidenceId); item.contributions.push(contribution) }
      if (rank(finding.severity) < rank(item.finding.severity) || (rank(finding.severity) === rank(item.finding.severity) && String(item.record.v2_rule_id || '').startsWith('baseline.') && !String(record.v2_rule_id || '').startsWith('baseline.'))) { item.finding = finding; item.record = record }
    }
  }
  for (const family of families.values()) {
    for (const cwe of family.totals?.cwes || []) family.cwes.add(cwe)
    family.cwe = [...family.cwes].sort().join(', ')
    family.items.sort((a, b) => rank(a.finding.severity) - rank(b.finding.severity) || a.id.localeCompare(b.id))
  }
  return [...families.values()].sort((a, b) => rank(a.severity) - rank(b.severity) || a.title.localeCompare(b.title) || a.key.localeCompare(b.key))
}

export function familyTotals(totals = []) {
  const groups = new Map()
  let ambiguous = false
  for (const total of totals) {
    const key = total.issue_family || String(total.title || '').trim().toLowerCase()
    if (!groups.has(key)) groups.set(key, { ...total, key })
    else {
      ambiguous = true
      const previous = groups.get(key)
      groups.set(key, { ...previous, instances: null, files: null, cwe: [...new Set([previous.cwe, total.cwe].filter(Boolean))].join(', ') })
    }
  }
  return { totals: [...groups.values()], ambiguous }
}
