// Presentation must preserve gaps instead of manufacturing source/sink nodes.
export function recordedAnalyzerPath(flow) {
  return Array.isArray(flow?.path) ? flow.path.filter(step => step && typeof step === 'object') : []
}

export function analyzerTraceStatus(flow) {
  const roles = new Set(recordedAnalyzerPath(flow).map(step => String(step.role || '').toLowerCase()))
  return ['partial', 'unresolved'].includes(String(flow?.trace_status || '').toLowerCase()) ||
    flow?.analysis_kind === 'unresolved_call' || !roles.has('source') || !roles.has('sink') ? 'partial' : 'complete'
}
