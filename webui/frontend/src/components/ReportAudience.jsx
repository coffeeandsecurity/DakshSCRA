import { createContext, useContext, useId } from 'react'
import { GuidanceText } from './PatternEvidence'

export const ReportAudienceContext = createContext('both')
export const AUDIENCE_LABELS = { both: 'Both', developer: 'Developer Mode', code_review: 'Code Review Mode' }

export function AudienceSelector({ value = 'both', onChange, disabled = false }) {
  const id = useId()
  return <fieldset className="report-audience">
    <legend>Report audience</legend>
    <p>Developer Mode checks implementation protections. Code Review Mode assesses reachability, mitigations and exploitation possibilities.</p>
    <label><input type="checkbox" aria-label="Both report audiences" checked={value === 'both'} disabled={disabled} onChange={event => onChange(event.target.checked ? 'both' : 'developer')} /><span><strong>Both</strong><small>Include both perspectives (default).</small></span></label>
    <div className="report-audience-options">{['developer', 'code_review'].map(mode => <label key={mode}>
      <input type="radio" name={id} aria-label={AUDIENCE_LABELS[mode]} checked={value === mode} disabled={disabled || value === 'both'} onChange={() => onChange(mode)} />
      <span>{AUDIENCE_LABELS[mode]}</span>
    </label>)}</div>
    <small className="text-muted">Clear Both to choose one audience. This changes guidance in the display and reports.</small>
  </fieldset>
}

export function ReviewGuidance({ developer, reviewer }) {
  const audience = useContext(ReportAudienceContext)
  return <div className="fr-guidance-stack">
    {audience !== 'developer' && reviewer ? <section className="fr-note rev"><h4 className="fr-note-label">Review guidance</h4><div className="fr-note-text"><GuidanceText text={reviewer} /></div></section> : null}
    {audience !== 'code_review' && developer ? <section className="fr-note dev"><h4 className="fr-note-label">Recommendations</h4><div className="fr-note-text"><GuidanceText text={developer} /></div></section> : null}
  </div>
}
