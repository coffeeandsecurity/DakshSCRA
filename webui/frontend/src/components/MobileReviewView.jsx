import { useState } from 'react'
import { MOBILE_GROUPS } from '../lib/mobileReview'

export default function MobileReviewView({ buckets, children, unit = 'checks', pageOnly = false }) {
  const [mobile, setMobile] = useState(false)
  return <>
    <div className="mobile-review-toolbar">
      <div><strong>Review perspective</strong><p>Organize the same evidence by application layer.</p></div>
      <div className="mobile-review-switch" role="group" aria-label="Review perspective">
        <button type="button" aria-pressed={!mobile} onClick={() => setMobile(false)}>Standard</button>
        <button type="button" aria-pressed={mobile} onClick={() => setMobile(true)}>Mobile review</button>
      </div>
    </div>
    {!mobile ? children(null) : <div className="mobile-review-layers">
      <p className="rdl-coverage-note">Grouped by source path and recorded platform. Framework groups identify implementation scope, not proof that a framework generated or caused an issue. Client API calls stay with client code. Uncertain scope stays visible.{pageOnly ? ' Group counts cover this page only; use Previous / Next to review the remaining results.' : ' A check spanning layers appears in each relevant group with only that layer’s evidence.'}</p>
      {MOBILE_GROUPS.map(group => <details className={`mobile-review-layer mobile-review-${group.id}`} key={group.id} open>
        <summary><span><strong>{group.label}</strong><small>{group.note}</small></span><span className="fr-category-chip">{buckets[group.id]?.length || 0} {buckets[group.id]?.length === 1 ? unit.replace(/s$/, '') : unit}</span></summary>
        {buckets[group.id]?.length ? children(group.id) : <p className="mobile-review-empty">No {unit} in this group{pageOnly ? ' on this page' : ' in the current results'}.</p>}
      </details>)}
    </div>}
  </>
}
