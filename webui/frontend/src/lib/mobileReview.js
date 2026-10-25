export const MOBILE_GROUPS = [
  { id: 'android', label: 'Android native', note: 'Android implementation and platform integration' },
  { id: 'ios', label: 'iOS native', note: 'Apple implementation and platform integration' },
  { id: 'framework', label: 'Shared app & framework', note: 'Cross-platform app code, bridges and framework integration' },
  { id: 'backend', label: 'Backend & APIs', note: 'Server implementation included in the scanned source' },
  { id: 'other', label: 'Other / needs classification', note: 'Source without enough evidence to assign an application layer' },
]

// Classify implementation location, never an API mentioned by client code.
export function mobileScope(file = '', platform = '') {
  const path = String(file).replace(/\\/g, '/').toLowerCase()
  const target = String(platform).toLowerCase().replace(/[\s_.-]/g, '')
  if (/(^|\/)(android|androidmain|androidtest)(\/|$)|\/platforms\/android\/|androidmanifest\.xml$|\.android\.[^/]+$/.test(path)) return 'android'
  if (/(^|\/)(ios|iosmain|iostest)(\/|$)|\/platforms\/ios\/|\.(swift|m|mm)$|\.ios\.[^/]+$/.test(path)) return 'ios'
  if (/(^|\/)(backend|server|servers|functions)(\/|$)|\/pages\/api\/|\/app\/api\//.test(path)) return 'backend'
  if (['android', 'jetpack'].includes(target)) return 'android'
  if (['ios', 'swiftui'].includes(target)) return 'ios'
  if (['reactnative', 'expo', 'flutter', 'dart', 'cordova', 'ionic', 'nativescript', 'xamarin', 'maui', 'kmp', 'kotlinmultiplatform'].includes(target)) return 'framework'
  if (['spring', 'springboot', 'aspnet', 'aspnetcore', 'django', 'flask', 'fastapi', 'express', 'nestjs', 'laravel', 'rails', 'gin'].includes(target)) return 'backend'
  return 'other'
}

export function splitMobileFindings(findings = []) {
  const buckets = Object.fromEntries(MOBILE_GROUPS.map(group => [group.id, []]))
  for (const finding of findings) {
    if (!finding.evidence?.length) {
      buckets[mobileScope('', finding.platform)].push(finding)
      continue
    }
    const evidence = new Map()
    for (const item of finding.evidence) {
      const scope = mobileScope(item.file, finding.platform)
      if (!evidence.has(scope)) evidence.set(scope, [])
      evidence.get(scope).push(item)
    }
    for (const [scope, items] of evidence) buckets[scope].push({ ...finding, evidence: items })
  }
  return buckets
}

export function mobileRecordScope(record, finding) {
  return mobileScope(finding?.location?.path || finding?.path || record.context?.file_path, record.context?.platform || record.platform || record.target)
}
