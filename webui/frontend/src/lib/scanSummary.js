export function recordedNumber(value) {
  if (!['number', 'string'].includes(typeof value) || (typeof value === 'string' && !value.trim())) return null
  const number = Number(value)
  return Number.isFinite(number) && number >= 0 ? number : null
}
export function recordedDuration(value) {
  if (typeof value !== 'string') return null
  const match = value.match(/(\d+)Hr:(\d+)Min:(\d+)s(?::(\d+)ms)?/)
  return match ? Number(match[1]) * 3600 + Number(match[2]) * 60 + Number(match[3]) + Number(match[4] || 0) / 1000 : null
}
const LANGUAGES = { js: 'JavaScript', jsx: 'JavaScript', ts: 'TypeScript', tsx: 'TypeScript', php: 'PHP', py: 'Python', java: 'Java', kt: 'Kotlin', kts: 'Kotlin', swift: 'Swift', m: 'Objective-C', mm: 'Objective-C++', cs: 'C#', c: 'C', cpp: 'C++', rb: 'Ruby', go: 'Go', dart: 'Dart', xml: 'XML', html: 'HTML', json: 'JSON', yml: 'YAML', yaml: 'YAML' }
export function buildScanSummary(run = {}, data, suppressedCount) {
  const meta = { ...(data?.summary || {}), ...(data?.scan_meta || {}) }
  for (const key of ['detection_summary', 'inputs_received', 'analyzer_summary', 'live_progress', 'scanning_timeline']) {
    meta[key] = { ...(data?.summary?.[key] || {}), ...(data?.scan_meta?.[key] || {}) }
  }
  const detection = meta.detection_summary || {}, inputs = meta.inputs_received || {}, analysis = meta.analyzer_summary || {}, progress = meta.live_progress || {}, timeline = meta.scanning_timeline || {}
  const removed = Boolean(data?.data_removed || run.data_removed_at)
  const code = removed ? null : Array.isArray(data?.findings) ? data.findings.length : recordedNumber(detection.areas_of_interest_identified)
  const paths = removed ? null : Array.isArray(data?.filepaths) ? data.filepaths.length : recordedNumber(detection.file_paths_areas_of_interest_identified)
  const files = recordedNumber(detection.total_files_scanned)
  const identified = recordedNumber(detection.total_files_identified)
  const discovered = recordedNumber(detection.total_project_files_identified)
  const languages = new Map(), evidenceFiles = new Set()
  let locations = 0
  for (const rule of removed ? [] : data?.findings || []) {
    for (const entry of rule.evidence || []) {
      if (entry.file) evidenceFiles.add(String(entry.file).replace(/\\/g, '/'))
      locations += Array.isArray(entry.matches) ? entry.matches.length : 1
    }
  }
  for (const row of removed ? [] : data?.loc_breakdown || []) {
    if (!row.path) continue
    const extension = String(row.path).split('/').pop().split('.').slice(1).pop()?.toLowerCase() || ''
    const label = LANGUAGES[extension] || (extension ? `.${extension}` : 'No extension')
    const item = languages.get(label) || { label, files: 0, loc: 0 }
    item.files++; item.loc += recordedNumber(row.loc) || 0; languages.set(label, item)
  }
  const platformRules = Array.from(String(inputs.platform_specific_rules || '').matchAll(/([^,\[\]]+)\[(\d+)\]/g), match => ({ label: match[1].trim(), value: Number(match[2]) }))
  const common = recordedNumber(inputs.common_rules), framework = recordedNumber(inputs.framework_rules_count)
  if (common != null) platformRules.push({ label: 'Common', value: common })
  if (framework != null) platformRules.push({ label: 'Frameworks', value: framework })
  return { meta, inputs, detection, analysis, progress, timeline, removed, code, paths, areas: code == null || paths == null ? null : code + paths,
    suppressed: removed ? null : recordedNumber(suppressedCount) ?? recordedNumber(detection.suppressed_findings), files, identified, discovered,
    otherFiles: discovered != null && (files ?? identified) != null && discovered >= (files ?? identified) ? discovered - (files ?? identified) : null,
    loc: recordedNumber(detection.total_loc), rules: recordedNumber(inputs.total_rules_loaded), parserErrors: recordedNumber(progress.parse_error_count),
    directories: recordedNumber(progress.directories_scanned), duration: recordedNumber(run.duration_sec), scanningDuration: recordedDuration(timeline.scan_duration), reconDuration: recordedDuration(timeline.recon_duration),
    targets: recordedNumber(analysis.targets_total), completed: recordedNumber(analysis.targets_analyzed), failed: recordedNumber(analysis.targets_failed), observations: recordedNumber(analysis.findings_identified),
    locations: removed || !Array.isArray(data?.findings) ? null : locations, evidenceFiles: removed || !Array.isArray(data?.findings) ? null : evidenceFiles.size,
    languages: [...languages.values()], platformRules,
    mode: inputs.rdl_engine || run.rdl_engine || null }
}
