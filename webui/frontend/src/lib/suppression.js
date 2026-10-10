// Identify the suppressing logic from the record, never from scan-wide engine selection.
export function suppressionDetails(item) {
  const source = item.suppression_source || item.logic_source || (item.rdl_condition || '').replace(/^RDL:/i, '')
  const engine = String(item.suppression_engine || item.logic_engine || '').toLowerCase()
  const explicit = String(item.suppression_version || item.logic_version || '')
  const engineVersion = engine.match(/^rdl[ _-]?v?([12])$/)?.[1]
  const pathVersion = source.replace(/\\/g, '/').match(/(?:^|\/)rdl\/v([12])\//i)?.[1]
  const textVersion = (item.rdl_text || '').match(/^\s*VERSION\s+([12])\b/im)?.[1]
  const version = explicit.match(/^v?([12])$/i)?.[1] || engineVersion || pathVersion || textVersion
  const isRdl = engine.startsWith('rdl') || Boolean(pathVersion || textVersion) || /^RDL:/i.test(item.rdl_condition || '')
  const label = isRdl ? (version ? `RDL v${version}` : 'RDL · version not recorded') : (engine || 'Engine not recorded')
  return { source, engine: label, reason: item.suppression_reason || 'Suppression reason was not recorded for this finding.' }
}
