export const EFFORT_LABELS = {
  hours_per_day: 'Productive hours per person-day',
  evidence_budget_fraction: 'Additional evidence budget (fraction of inspection)',
  assisted_effort_fraction: 'Daksh effort (fraction of manual)',
  ai_effort_fraction: 'AI effort (fraction of Daksh)',
  inspection_loc_per_hour: 'Code inspection (effective LOC/hour)',
  manual_active_minutes: 'Fully manual: flagged locations (minutes/location)',
  manual_confirmed_minutes: 'Fully manual: rule-supported / reviewer-confirmed locations (minutes/location)',
  manual_suppressed_minutes: 'Fully manual: excluded-match review (minutes/location)',
  manual_unresolved_minutes: 'Fully manual: unresolved checks (minutes/location)',
  manual_trace_step_minutes: 'Manual path reconstruction (minutes/step)',
  manual_setup_hours: 'Manual orientation (hours)',
  manual_file_minutes: 'Manual file mapping (minutes/file)',
  domain_exploration_hours: 'Targeted control exploration (hours/domain)',
  report_base_hours: 'Report preparation (hours)',
  report_unit_minutes: 'Record review decisions (minutes/location)',
}

export default function EffortAssumptions({ values, onChange, disabled = false }) {
  return <div className="effort-assumptions">{Object.entries(EFFORT_LABELS).map(([key, label]) => {
    const value = values?.[key]
    if (value == null) return null
    return <div className="effort-assumption" key={key}><span>{label}</span><div>
      {Array.isArray(value) ? value.map((v, index) => <label key={index}><small>{index ? 'High' : 'Low'}</small>
        <input type="number" min={key === 'inspection_loc_per_hour' ? 1 : 0} step="any" disabled={disabled}
          aria-label={`${label} ${index ? 'high' : 'low'}`} value={v}
          onChange={(event) => onChange({ ...values, [key]: value.map((n, i) => i === index ? Number(event.target.value) : n) })} />
      </label>) : <input type="number" min="0.1" max="24" step="0.1" aria-label={label} disabled={disabled} value={value}
        onChange={(event) => onChange({ ...values, [key]: Number(event.target.value) })} />}
    </div></div>
  })}</div>
}
