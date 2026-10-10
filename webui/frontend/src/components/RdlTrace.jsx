import FlowView from './FlowView'
import { useId, useMemo } from 'react'
import { groupTraceSteps } from '../lib/rdlTraceGroups'
import { flowEvidence, graphableFlow } from '../lib/rdlReviewModels'
export { flowEvidence } from '../lib/rdlReviewModels'

const CONDITION_ROLES = new Set(['TEXT_MATCHES', 'TEXT_MISSING', 'FILE_NAME_IS', 'FILE_PATH_GLOB', 'PROJECT_OBSERVATION', 'PRESENT', 'MISSING', 'MATCHES'])
const ROLE_LABELS = {
  SOURCE: 'Tainted input received', SINK: 'Final sink reached', PROPAGATION: 'Value carried forward',
  EXISTS: 'Relevant operation observed', 'STATE TRANSITION': 'State changed', 'STATE VIOLATION': 'State requires review',
  TEXT_MATCHES: 'Source pattern observed', TEXT_MISSING: 'Expected pattern not found',
  FILE_NAME_IS: 'File name matched', FILE_PATH_GLOB: 'File path matched', PROJECT_OBSERVATION: 'Project context checked',
}
const TRANSITION_LABELS = {
  assignment: 'Assigned or reassigned', reference: 'Value read', argument: 'Passed into call',
  'argument-parameter': 'Parameter carrying taint', return: 'Value returned', 'return-call': 'Return received by caller', receiver: 'Operation uses input',
}
export const shortPath = path => String(path || 'Location not recorded').split(/[\\/]/).slice(-2).join('/')
export const locationLabel = location => location?.path ? `${shortPath(location.path)}${location.line ? ':' + location.line : ''}` : 'Location not recorded'

function stepDescription(step) {
  if (step.description || step.explanation) return step.description || step.explanation
  if (step.predicate === 'TEXT_MATCHES' || step.predicate === 'PRESENT' || step.predicate === 'MATCHES') return 'The highlighted source matches this review rule. Inspect the surrounding code to determine its security impact.'
  if (step.predicate === 'TEXT_MISSING' || step.predicate === 'MISSING') return 'The expected pattern was not found in the inspected scope. Equivalent controls may exist elsewhere; this absence alone does not establish a vulnerability.'
  if (step.predicate === 'FILE_NAME_IS' || step.predicate === 'FILE_PATH_GLOB') return 'This file or directory path matches a review condition. No source line or data flow is implied.'
  if (step.predicate === 'PROJECT_OBSERVATION') return 'Project context was checked as part of this rule. Expand the rule conditions for the recorded observation.'
  return step.description || step.explanation || 'Inspect the recorded evidence and source context.'
}

export function RuleConditions({ evidence = [] }) {
  return <details className="rdl-rule-conditions">
    <summary>View rule conditions <span className="rdl-condition-count">{evidence.length}</span></summary>
    <p>Exact checks and recorded outcomes used by this rule. A satisfied absence check means the pattern was not found in the inspected scope.</p>
    <ol>{evidence.map((item, index) => <li key={index}>
      <div className="rdl-condition-heading"><code>{item.predicate}</code><span className="aa-pill plain">{item.matched === true ? 'Satisfied' : item.matched === false ? 'Not satisfied' : 'Outcome not recorded'}</span></div>
      <p>{item.explanation || item.symbol || 'No further condition detail was recorded.'}</p>
      {item.location ? <code className="rdl-source-location">{item.location.path}:{item.location.line}</code> : null}
    </li>)}</ol>
  </details>
}

function SourceBlock({ block, prefix, linkSteps = true }) {
  return <section className="rdl-shared-code">
    <h4>Code {block.id.split('-').at(-1)} · lines {block.start}-{block.end}</h4>
    <code className="rdl-source-location">{block.path}</code>
    <pre className="rdl-source-snippet">{block.lines.map(line => <span id={`${prefix}-${block.id}-L${line.line}`} className={`rdl-code-line${line.highlight ? ' highlight' : ''}`} key={line.line}>
      <span className="rdl-line-number">{line.line}</span><span>{line.text}</span><span className="rdl-step-tags">{(linkSteps ? line.steps || [] : []).map(number => <a href={`#${prefix}-step-${number}`} title={`Trace step ${number}`} key={number}>[{number}]</a>)}</span>
    </span>)}</pre>
  </section>
}

// Evidence-only surfaces reuse the exact recorded lines and highlights. Step
// backlinks are shown only when the corresponding timeline is rendered.
export function RdlSourceEvidence({ finding, step, title = 'Source evidence' }) {
  const prefix = useId()
  const blocks = finding.trace?.blocks || []
  const matched = step?.location ? blocks.filter(block => block.path === step.location.path && block.start <= step.location.line && block.end >= step.location.line) : blocks
  const snippet = step?.snippet || (finding.evidence || []).find(item => item.location?.path === step?.location?.path && item.location?.line === step?.location?.line)?.snippet || []
  return <section className="rdl-evidence-only">
    <h4>{title}</h4>
    {matched.length ? matched.map(block => <SourceBlock key={block.id} block={block} prefix={prefix} linkSteps={false} />) : snippet.length ? <>
      <code className="rdl-source-location">{step?.location?.path}</code>
      <pre className="rdl-source-snippet">{snippet.map(line => <span className={line.highlight ? 'highlight' : ''} key={line.line}><span className="rdl-line-number">{line.line}</span>{line.text}{'\n'}</span>)}</pre>
    </> : <p className="rdl-coverage-note">{finding.path_only ? 'Path-only check; no code excerpt applies.' : 'No source excerpt was recorded for this location.'}</p>}
  </section>
}

function RdlTextTrace({ finding, fullSource, fullSink }) {
  const prefix = useId()
  const trace = finding.trace || {}
  const evidence = finding.evidence?.length ? finding.evidence : trace.steps || []
  const steps = trace.steps?.length ? trace.steps : evidence.map((item, index) => ({ ...item, number: index + 1 }))
  const blocks = trace.blocks || []
  const groups = useMemo(() => groupTraceSteps(steps, blocks, { mergeSameLine: false }), [steps, blocks])
  const flow = flowEvidence(finding)
  const source = fullSource || flow.find(step => step.predicate === 'SOURCE')
  const sink = fullSink || flow.findLast(step => step.predicate === 'SINK')
  const paths = [...new Set((source ? flow : steps).map(step => step.location?.path).filter(Boolean))]
  const handoffs = []
  for (const step of flow) {
    const path = step.location?.path
    if (path && path !== handoffs.at(-1)) handoffs.push(path)
  }
  const sourcePath = finding.location?.path || finding.path || source?.location?.path
  return <div className="rdl-shared-trace">
    {source ? <p className="rdl-coverage-note"><strong>Confidence: {finding.confidence || 'Unspecified'}.</strong> {finding.confidence_reason}</p> : null}
    <div className="rdl-trace-overview">
      <div className="rdl-context-card"><span className="aa-simple-stage-title">{source ? 'Where received' : 'Selected source'}</span><strong>{source ? locationLabel(source.location) : finding.path_only ? shortPath(sourcePath) : locationLabel(finding.location)}</strong><code className="rdl-source-location">{source?.location?.path || sourcePath || 'No source location recorded'}</code>{source?.symbol ? <span className="aa-tag">{source.symbol}</span> : null}</div>
      <div className="rdl-context-card"><span className="aa-simple-stage-title">{source ? 'Where traced' : 'Evidence scope'}</span><strong>{paths.length} source file{paths.length === 1 ? '' : 's'} · {steps.length} steps</strong><span>{source ? `${Math.max(0, handoffs.length - 1)} recorded file handoff(s)` : finding.path_only ? 'Path-only review; no source line applies.' : 'Source and rule evidence; data flow is not established.'}</span></div>
      <div className="rdl-context-card"><span className="aa-simple-stage-title">{source ? 'Where it lands' : 'Review assessment'}</span><strong>{source ? sink ? locationLabel(sink.location) : 'No final sink recorded' : (finding.confidence || 'Unspecified') + ' confidence'}</strong><span>{source ? sink?.symbol || 'This is a partial trace. Review unresolved propagation.' : finding.confidence_reason}</span></div>
    </div>
    {source && handoffs.length > 1 ? <div className="rdl-shadow-callout rdl-file-handoffs"><strong>Cross-file path · {paths.length} files</strong><p>{handoffs.map((path, index) => <span key={index}>{index ? ' → ' : ''}<code title={path}>{shortPath(path)}</code></span>)}</p><small>Recorded order includes returns to callers.</small></div> : null}
    <div className="rdl-story-heading"><h4>{source ? 'Trace Story' : 'Evidence Story'}</h4><span>{groups.length === steps.length ? `${steps.length} step${steps.length === 1 ? '' : 's'}` : `${groups.length} story step${groups.length === 1 ? '' : 's'} · ${steps.length} recorded actions`} · {blocks.length} shared code block{blocks.length === 1 ? '' : 's'}</span></div>
    <div className="rdl-story-layout">
      <ol className="aa-simple-timeline rdl-story-timeline">{groups.map((group, index) => {
        const first = group.steps[0]
        const next = groups[index + 1]?.steps[0]
        const role = group.steps.some(step => step.predicate === 'SINK') ? 'sink' : group.steps.some(step => step.predicate === 'SOURCE') ? 'source' : group.steps.some(step => ['argument', 'argument-parameter', 'return', 'return-call'].includes(step.transition)) ? 'call' : 'step'
        const previous = groups[index - 1]?.steps.at(-1)
        const crossesFile = previous?.location?.path && first.location?.path && previous.location.path !== first.location.path
        const symbols = [...new Set(group.steps.filter(step => !CONDITION_ROLES.has(step.predicate)).map(step => step.symbol).filter(Boolean))]
        return <li className={`aa-simple-step ${role}`} key={first.number} id={`${prefix}-step-${first.number}`}>
          {group.steps.slice(1).map(step => <span className="rdl-step-anchor" id={`${prefix}-step-${step.number}`} key={step.number} aria-hidden="true" />)}
          <div className="aa-simple-step-rail" aria-hidden="true"><span className="aa-simple-step-dot" />{index < groups.length - 1 ? <span className="aa-simple-step-line" /> : null}</div>
          <div className="aa-simple-step-card">
            <div className="aa-simple-step-top"><span className="aa-simple-step-index">{`Step ${first.number}`}</span><span className="aa-simple-step-role">{(first.predicate === 'PROPAGATION' && TRANSITION_LABELS[first.transition]) || ROLE_LABELS[first.predicate] || 'Evidence checked'}</span>{crossesFile ? <span className="aa-pill plain">Cross-file handoff</span> : next?.location?.path && first.location?.path && next.location.path !== first.location.path ? <span className="aa-pill plain">Cross-file next</span> : null}</div>
            {group.location ? <div className="aa-simple-step-loc" title={group.location.path}>{locationLabel(group.location)}{group.location.column ? ` · column ${group.location.column}` : ''}{group.location.end_line > group.location.line ? ` · through line ${group.location.end_line}` : ''}</div> : null}
            <div className="aa-simple-step-copy">{group.steps.map(step => stepDescription(step)).join(' ')}</div>
            {symbols.length ? <div className="aa-tag-wrap aa-simple-step-tags">{symbols.map(symbol => <span className="aa-tag" key={symbol}>Symbol: {symbol}</span>)}</div> : null}
            {group.lines.length ? <pre className="rdl-source-snippet rdl-step-snippet">{group.lines.map((line, lineIndex) => <span className={line.highlight ? 'highlight' : ''} key={`${line.line}-${lineIndex}`}><span className="rdl-line-number">{line.line}</span>{line.text}</span>)}</pre> : null}
            <div className="rdl-code-jumps">{group.links.map(link => <a className="rdl-code-jump" key={`${link.block}-${link.line}`} href={`#${prefix}-${link.block}-L${link.line}`}>View code {link.block.split('-').at(-1)}, line {link.line}</a>)}</div>
            {first.explanation && first.explanation !== first.description ? <div className="aa-simple-step-copy"><strong>Recorded detail: </strong>{first.explanation}</div> : null}
            <div className="aa-tag-wrap aa-simple-step-tags">
              {first.source_symbol ? <span className="aa-tag">Source: {first.source_symbol}</span> : null}
              {first.target_symbol ? <span className="aa-tag">Target: {first.target_symbol}</span> : null}
              {(first.variables || []).map((value, i) => <span className="aa-tag" key={i}>Argument: {value}</span>)}
              {first.transition ? <span className="aa-tag">Transfer: {first.transition}</span> : null}
              {first.matched === false ? <span className="aa-tag">Condition not satisfied</span> : null}
            </div>
          </div>
        </li>
      })}</ol>
      <aside className="aa-simple-transform-box rdl-protection-note"><div className="aa-simple-stage-title">{source ? 'Protection and trace scope' : 'What this evidence establishes'}</div><div className="aa-simple-mini-item">{trace.protection_note || (source ? 'Protection was not resolved in the recorded evidence. Review validation and controls along this path.' : 'A review condition matched. This does not establish taint propagation or confirm a vulnerability.')}</div>{trace.review_note ? <p>{trace.review_note}</p> : null}<RuleConditions evidence={evidence} /></aside>
    </div>
    {blocks.length ? <div className="rdl-source-blocks"><h4>Source evidence</h4><p className="rdl-coverage-note">Full recorded context with highlighted lines. Step numbers link back to the story above.</p>{blocks.map(block => <SourceBlock block={block} prefix={prefix} key={block.id} />)}</div> : <p className="rdl-coverage-note">{finding.path_only ? 'This is a path-only check; no code excerpt applies.' : 'No shared source excerpt was recorded for this result.'}</p>}
  </div>
}

function RdlRuleEvidence({ finding }) {
  const evidence = finding.evidence?.length ? finding.evidence : finding.trace?.steps || []
  const observed = evidence.filter(step => step.matched !== false && step.location)
  const locations = [...new Map(observed.map(step => [JSON.stringify(step.location), step])).values()]
  return <section className="rdl-evidence-only" aria-label="Recorded rule evidence">
    <h4>Recorded rule evidence</h4>
    <p className="rdl-coverage-note">This result records source or configuration checks. No source-to-sink data flow was recorded.</p>
    {locations.map((step, index) => <div key={index}>
      <code className="rdl-source-location">{locationLabel(step.location)}</code>
      <RdlSourceEvidence finding={finding} step={step} title="Recorded source context" />
    </div>)}
    {!locations.length ? <RdlSourceEvidence finding={finding} /> : null}
    <RuleConditions evidence={evidence} />
  </section>
}

export default function RdlTrace({ finding }) {
  const trace = finding.trace || {}
  const flow = flowEvidence(finding)
  if (!flow.some(step => step.predicate === 'SOURCE')) return <RdlRuleEvidence finding={finding} />
  const steps = flow.map((step, index) => ({ ...step, number: index + 1 }))
  const conditions = (finding.evidence || []).filter(step => !['SOURCE', 'PROPAGATION', 'SINK'].includes(step.predicate))
  // Block backlinks use original trace numbers; remap them to flow-only numbers.
  const numbers = new Map(flow.map((step, index) => [step.number, index + 1]).filter(([number]) => number != null))
  const blocks = (trace.blocks || []).map(block => ({ ...block, lines: (block.lines || []).map(line => ({ ...line, steps: (line.steps || []).map(number => numbers.get(number)).filter(number => number != null) })) }))
  const projected = { ...finding, evidence: steps, trace: { ...trace, steps, blocks } }
  return <>
    <FlowView steps={steps} graphSteps={graphableFlow(projected)} blocks={blocks} title="Recorded data-flow trace" note={[finding.confidence_reason, trace.protection_note, trace.review_note].filter(Boolean).join(' ')}>{({steps:visible,start}) => <RdlTextPage finding={projected} steps={visible} start={start}/>}</FlowView>
    {conditions.length ? <RuleConditions evidence={conditions} /> : null}
  </>
}

function RdlTextPage({ finding, steps, start }) {
  const original = finding.trace || {}
  const allBlocks = original.blocks || []
  const index = useMemo(() => new Map(allBlocks.map(block => [block.id,block])), [allBlocks])
  const endpoints = useMemo(() => { const list = finding.evidence?.length ? finding.evidence : original.steps || []; return { source:list.find(step=>step.predicate==='SOURCE' && step.matched!==false), sink:list.findLast(step=>step.predicate==='SINK' && step.matched!==false) } }, [finding])
  const references = new Set(steps.map(step=>step.code_block).filter(Boolean))
  const ranges = new Map()
  for (const step of steps) {
    const path = step.location?.path, line = step.location?.line
    if (!path || !Number.isFinite(line)) continue
    const range = ranges.get(path) || {start:line,end:line}
    range.start = Math.min(range.start,line); range.end = Math.max(range.end,line); ranges.set(path,range)
  }
  const blocks = references.size ? [...references].map(id=>index.get(id)).filter(Boolean) : allBlocks.filter(block=>{const range=ranges.get(block.path);return range && block.start<=range.end && block.end>=range.start}).slice(0,120)
  const numbered = steps.map((step,i)=>({...step,number:step.number || start+i+1}))
  const numbers = new Set(numbered.map(step=>step.number))
  const linkedBlocks = blocks.map(block=>({...block,lines:(block.lines || []).map(line=>({...line,steps:(line.steps || []).filter(number=>numbers.has(number))}))}))
  return <RdlTextTrace fullSource={endpoints.source} fullSink={endpoints.sink} finding={{...finding,evidence:(finding.evidence || []).slice(start,start+120),trace:{...original,steps:numbered,blocks:linkedBlocks}}}/>
}
