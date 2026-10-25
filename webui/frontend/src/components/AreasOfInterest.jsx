import { countFindingFamilies } from '../lib/findingFamilies'
import { useEffect, useId, useRef, useState } from 'react'
import FindingsReport from './FindingsReport'
import { FilePaths } from './InsightsPanel'
import RetainedTab from './RetainedTab'
import SuppressedPanel from './SuppressedPanel'

const SECTIONS = [
  {
    id: 'code', label: 'Code Matches', tone: 'summary',
    description: 'Issue families with platform-specific evidence',
    icon: <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true"><path d="m6 5-5 5 5 5m8-10 5 5-5 5m-3-13L9 18" /></svg>,
  },
  {
    id: 'paths', label: 'File Path Matches', tone: 'xref',
    description: 'Rules matched against file and directory names',
    icon: <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true"><path d="M2 5h6l2 2h8v9H2z" /><path d="M2 5V3h6l2 2h7v2" /></svg>,
  },
  {
    id: 'suppressed', label: 'Suppressed Areas of Interests', tone: 'vectors',
    description: 'Source matches excluded by RDL v1 logic',
    icon: <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden="true"><path d="M3 3h14v14H3zM6 10h8" /></svg>,
  },
]

export default function AreasOfInterest({ data, status, rdlEngine, onViewAnalysis, requestedSection, runUuid, suppressedCount, onSuppressedLoaded }) {
  const [section, setSection] = useState(SECTIONS.some(item => item.id === requestedSection?.section) ? requestedSection.section : 'code')
  useEffect(() => { if (SECTIONS.some(item => item.id === requestedSection?.section)) setSection(requestedSection.section) }, [requestedSection])
  const id = useId()
  const buttons = useRef([])
  const counts = { code: countFindingFamilies(data?.findings), paths: data?.filepaths?.length ?? 0, suppressed: suppressedCount }

  function handleKey(event, index) {
    let next
    if (event.key === 'ArrowRight') next = (index + 1) % SECTIONS.length
    else if (event.key === 'ArrowLeft') next = (index + SECTIONS.length - 1) % SECTIONS.length
    else if (event.key === 'Home') next = 0
    else if (event.key === 'End') next = SECTIONS.length - 1
    else return
    event.preventDefault()
    setSection(SECTIONS[next].id)
    buttons.current[next]?.focus()
  }

  return (
    <div className="aa-root aoi-root">
      <div className="aa-subtabs" role="tablist" aria-label="Areas of Interest sections">
        {SECTIONS.map((item, index) => (
          <button key={item.id} type="button" role="tab"
            id={`${id}-tab-${item.id}`} aria-controls={`${id}-panel-${item.id}`}
            aria-selected={section === item.id} tabIndex={section === item.id ? 0 : -1}
            ref={(element) => { buttons.current[index] = element }}
            className={`aa-subtab tone-${item.tone}${section === item.id ? ' active' : ''}`}
            onClick={() => setSection(item.id)} onKeyDown={(event) => handleKey(event, index)}>
            <span className="aa-subtab-icon">{item.icon}</span>
            <span className="aa-subtab-copy">
              <span className="aa-subtab-title">{item.label}</span>
              <span className="aa-subtab-meta">{item.description}</span>
            </span>
            <span className="aa-subtab-count" aria-label={`${counts[item.id] ?? 0} ${item.id === 'suppressed' ? 'suppressed records' : item.id === 'code' ? 'issue families' : 'matched rules'}`}>{counts[item.id] ?? '…'}</span>
            <span className="aa-subtab-arrow" aria-hidden="true">
              <svg viewBox="0 0 20 20" fill="currentColor"><path d="m7 5 5 5-5 5 1 1 6-6-6-6z" /></svg>
            </span>
          </button>
        ))}
      </div>
      <RetainedTab active={section === 'code'} role="tabpanel"
        id={`${id}-panel-code`} aria-labelledby={`${id}-tab-code`}>
        {rdlEngine === 'v2' ? (
          <div className="empty-state"><div className="empty-title">RDL v1 was not run for this scan</div><p>Open the RDL v2 tab to review its results. Select Both or RDL v1 for the original rule-based findings.</p></div>
        ) : <FindingsReport data={data} status={status} onViewAnalysis={onViewAnalysis} />}
      </RetainedTab>
      <RetainedTab active={section === 'paths'} role="tabpanel" className="ip-content"
        id={`${id}-panel-paths`} aria-labelledby={`${id}-tab-paths`}>
        <FilePaths filepaths={data?.filepaths} />
      </RetainedTab>
      <RetainedTab active={section === 'suppressed'} role="tabpanel"
        id={`${id}-panel-suppressed`} aria-labelledby={`${id}-tab-suppressed`}>
        {rdlEngine === 'v2' ? <div className="empty-state"><div className="empty-title">RDL v1 was not run for this scan</div><p>RDL v1 suppressions require a scan with Both or RDL v1 selected.</p></div> : <SuppressedPanel runUuid={runUuid} onLoaded={onSuppressedLoaded} />}
      </RetainedTab>
    </div>
  )
}
