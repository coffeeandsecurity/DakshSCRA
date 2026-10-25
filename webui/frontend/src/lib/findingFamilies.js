const levels = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
const rank = finding => { const value = levels.indexOf(String(finding.confidence_level || 'unknown').toLowerCase()); return value < 0 ? levels.length : value }
const platformName = finding => String(finding.platform || 'Unspecified').trim() || 'Unspecified'
const familyKey = finding => String(finding.rule_title || '').trim().toLowerCase() || JSON.stringify([platformName(finding).toLowerCase(), finding.rule_id || 'Unnamed area of interest'])
const strongest = (previous, finding) => rank(finding) < rank(previous) || (rank(finding) === rank(previous) && (finding.confidence_score || 0) > (previous.confidence_score || 0)) ? finding : previous
export const countFindingFamilies = findings => new Set((findings || []).map(familyKey)).size
export function groupFindingFamilies(findings = []) {
  const families = new Map()
  for (const finding of findings) {
    const key = familyKey(finding)
    if (!families.has(key)) families.set(key, { key, representative: finding, members: [], platforms: new Map(), locations: new Set() })
    const group = families.get(key)
    group.members.push(finding)
    group.representative = strongest(group.representative, finding)
    const name = platformName(finding)
    const platformKey = name.toLowerCase()
    if (!group.platforms.has(platformKey)) group.platforms.set(platformKey, { key: JSON.stringify([key, platformKey]), name, representative: finding, members: [], locations: new Set() })
    const platform = group.platforms.get(platformKey)
    platform.members.push(finding)
    platform.representative = strongest(platform.representative, finding)
    for (const [index, evidence] of (finding.evidence || []).entries()) {
      const matches = evidence.matches?.length ? evidence.matches : [evidence]
      for (const [matchIndex, match] of matches.entries()) {
        const file = String(evidence.file || match.file || '').replace(/\\/g, '/')
        const identity = JSON.stringify([file, match.line ?? evidence.line ?? (file ? 'path-only' : `${finding.rule_id || ''}:${index}:${matchIndex}`), match.column ?? evidence.column ?? null])
        platform.locations.add(identity)
        group.locations.add(identity)
      }
    }
  }
  return [...families.values()].map(group => {
    const platforms = [...group.platforms.values()].map(({ locations, ...platform }) => ({ ...platform, instanceCount: locations.size }))
    return { ...group, platforms, instanceCount: group.locations.size }
  })
}

export const findingCheckKey = (groupKey, finding, index) => JSON.stringify([groupKey, platformName(finding).toLowerCase(), finding.rule_id || '', index])

export function findingCheckLabel(finding) {
  const source = String(finding.logic_source || finding.rdl_ref || '').replace(/\\/g, '/')
  const stem = source.split('/').pop()?.replace(/\.(yaml|rdl)$/, '') || ''
  const labels = {
    untrusted_data_in_innerhtml: 'innerHTML assignment',
    untrusted_data_in_document_write: 'document.write and document.writeln',
  }
  if (labels[stem]) return labels[stem]
  const description = String(finding.issue_desc || finding.description || '')
  if (/document\.write/.test(description)) return 'document.write and document.writeln'
  if (/innerHTML/.test(description)) return 'innerHTML assignment'
  if (stem) return stem.replace(/^rdl_(?:conditional_)?/, '').replace(/_/g, ' ').replace(/^./, c => c.toUpperCase())
  return finding.rule_title || 'Source review'
}
