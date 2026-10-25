let preferences = { date_format: 'MM-DD-YYYY', time_format: '24h', timezone: 'UTC' }
export function setDisplayPreferences(value) {
  preferences = { ...preferences, ...value }
  window.dispatchEvent(new Event('display-preferences-changed'))
}
export function formatDateTime(value, dateOnly = false) {
  if (!value) return '-'
  // API records without an offset represent UTC; legacy scan strings retain server interpretation.
  let input = value
  if (typeof value === 'string' && /^\d{4}-\d\d-\d\dT/.test(value) && !/(Z|[+-]\d\d:\d\d)$/.test(value)) input += 'Z'
  if (typeof value === 'string' && /^\d{4}-\d\d-\d\d$/.test(value)) {
    const [year, month, day] = value.split('-')
    return preferences.date_format === 'DD-MM-YYYY' ? `${day}-${month}-${year}` : preferences.date_format === 'YYYY-MM-DD' ? value : `${month}-${day}-${year}`
  }
  const date = new Date(input)
  if (Number.isNaN(date.getTime())) return String(value)
  const parts = Object.fromEntries(new Intl.DateTimeFormat('en-US', {
    timeZone: preferences.timezone || 'UTC', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hourCycle: preferences.time_format === '12h' ? 'h12' : 'h23', timeZoneName: 'short',
  }).formatToParts(date).map(p => [p.type, p.value]))
  const orders = { 'MM-DD-YYYY': ['month', 'day', 'year'], 'DD-MM-YYYY': ['day', 'month', 'year'], 'YYYY-MM-DD': ['year', 'month', 'day'] }
  const day = (orders[preferences.date_format] || orders['MM-DD-YYYY']).map(k => parts[k]).join('-')
  return dateOnly ? day : `${day} ${parts.hour}:${parts.minute}:${parts.second}${parts.dayPeriod ? ` ${parts.dayPeriod}` : ''} ${parts.timeZoneName}`
}
