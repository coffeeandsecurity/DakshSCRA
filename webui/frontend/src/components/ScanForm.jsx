import { useEffect, useMemo, useRef, useState } from 'react'
import { getCheckCatalog } from '../api'
import RulesSelect from './RulesSelect'

const TABS = [
  ['setup', 'Setup'], ['checks', 'Check Classes'], ['exclusions', 'Exclusions'],
  ['analysis', 'Analysis & Output'], ['custom', 'Custom RDL'],
]
const ENGINES = [
  ['both', 'Comprehensive Review', 'Security areas of interest plus findings.'],
  ['v2', 'Finding Analysis Only', 'Source, semantic and supported flow checks.'],
  ['v1', 'Areas of Interest Review Only', 'Security areas of interest for manual review.'],
]
const OPTIONS = [
  ['analysis', 'Inter-file analysis', 'Trace data across files and functions. Larger projects take longer.'],
  ['recon', 'Reconnaissance', 'Map languages, frameworks and repository structure.'],
  ['estimate', 'Review effort estimate', 'Estimate manual review effort. Requires reconnaissance and lines of code.'],
  ['loc', 'Lines of code', 'Include source line counts by file and language.'],
]
const nonEmpty = (lines = []) => lines.filter((line) => line.trim())

function SelectionBox({ checked, mixed, ...props }) {
  const input = useRef(null)
  useEffect(() => { if (input.current) input.current.indeterminate = Boolean(mixed) }, [mixed])
  return <input ref={input} type="checkbox" checked={checked} aria-checked={mixed ? 'mixed' : checked} {...props} />
}

function CheckDatabase({ catalog, error, loading, reload, excluded, setExcluded }) {
  const [search, setSearch] = useState('')
  const [expanded, setExpanded] = useState(() => new Set(['injection']))
  const excludedSet = useMemo(() => new Set(excluded), [excluded])
  const groups = catalog?.groups || []
  const all = useMemo(() => groups.flatMap((group) => group.checks), [groups])
  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase()
    return groups.map((group) => ({ ...group, visible: group.checks.filter((check) =>
      `${group.label} ${check.label} ${check.rules.map((rule) => rule.title).join(' ')}`.toLowerCase().includes(query)) }))
      .filter((group) => group.visible.length)
  }, [groups, search])
  function toggle(ids, enabled) {
    const updated = new Set(excluded)
    ids.forEach((id) => enabled ? updated.delete(id) : updated.add(id))
    setExcluded([...updated])
  }
  return <>
    <div className="scan-section-heading"><h2>Vulnerability check classes</h2><p>Choose which vulnerability classes the scan checks. All available checks are included by default.</p></div>
    <div className="check-toolbar">
      <input className="form-input" type="search" aria-label="Search vulnerability checks" placeholder="Search SQL injection, authentication, TLS…" value={search} onChange={(e) => setSearch(e.target.value)} />
      <button type="button" className="btn btn-ghost btn-sm" onClick={() => setExcluded([])}>Select all</button>
      <button type="button" className="btn btn-ghost btn-sm" disabled={!all.length} onClick={() => setExcluded(all.map((check) => check.id))}>Clear all</button>
    </div>
    {loading && <p role="status" className="text-muted">Loading registered checks…</p>}
    {error && <div role="alert" className="scan-config-notice">Checks could not be loaded: {error} <button type="button" className="btn btn-ghost btn-sm" onClick={reload}>Retry</button></div>}
    {catalog && <div className="check-selection-summary" aria-live="polite">{all.filter((check) => !excludedSet.has(check.id)).length} of {all.length} classes selected <span>{all.reduce((sum, check) => sum + check.count, 0)} registered definitions</span></div>}
    <div className="check-groups">
      {filtered.map((group) => {
        const enabled = group.checks.filter((check) => !excludedSet.has(check.id)).length
        const open = Boolean(search.trim()) || expanded.has(group.id)
        return <section className="check-group" key={group.id}>
          <div className="check-group-heading">
            <SelectionBox aria-label={`Include ${group.label}`} checked={enabled === group.checks.length} mixed={enabled > 0 && enabled < group.checks.length} onChange={(e) => toggle(group.checks.map((check) => check.id), e.target.checked)} />
            <button type="button" aria-expanded={open} aria-controls={`check-group-${group.id}`} onClick={() => setExpanded((previous) => { const next = new Set(previous); next.has(group.id) ? next.delete(group.id) : next.add(group.id); return next })}>
              <span>{group.label}</span><small>{enabled}/{group.checks.length} selected</small><span className="check-chevron" aria-hidden="true">{open ? '−' : '+'}</span>
            </button>
          </div>
          {open && <div id={`check-group-${group.id}`} className="check-group-rows">
            {group.visible.map((check) => <div className="check-class" key={check.id}>
              <label><input type="checkbox" checked={!excludedSet.has(check.id)} onChange={(e) => toggle([check.id], e.target.checked)} /><span>{check.label}</span></label>
              {check.count > 0 ? <details className="check-definitions"><summary>{check.count} checks</summary><ul>{check.rules.map((rule, index) => <li key={`${rule.title}-${rule.scope}-${index}`}><span>{rule.title}</span><small>{rule.scope || 'cross-platform'}</small></li>)}</ul></details> : <small className="text-muted">{check.id === 'custom' ? 'From selected packs' : 'No dedicated definitions'}</small>}
            </div>)}
          </div>}
        </section>
      })}
    </div>
    {catalog && !filtered.length && <p className="text-muted">No checks match your search.</p>}
    <p className="scan-config-note">Checks run where supported by the selected platforms and engine. A match is a review lead. Flow traces remain available for context.</p>
    {all.length > 0 && excluded.length === all.length && <p className="scan-config-notice" role="status">All check classes are excluded. This scan will retain repository and flow context without security check results.</p>}
  </>
}

function LinesField({ id, label, description, placeholder, value, onChange, disabled, rows = 3 }) {
  return <div className="form-field">
    <label className="form-label" htmlFor={id}>{label}</label>
    <textarea id={id} className="form-input" rows={rows} value={(value || []).join('\n')} onChange={(e) => onChange(e.target.value.split('\n'))} placeholder={placeholder} disabled={disabled} aria-describedby={`${id}-help`} />
    <small id={`${id}-help`} className="text-muted">{description}</small>
  </div>
}

export default function ScanForm({ values, setValues, onSubmit, onBrowse, creating }) {
  const [activeTab, setActiveTab] = useState('setup')
  const [catalog, setCatalog] = useState(null)
  const [catalogError, setCatalogError] = useState('')
  const [catalogLoading, setCatalogLoading] = useState(true)
  const [catalogAttempt, setCatalogAttempt] = useState(0)
  useEffect(() => {
    let cancelled = false
    setCatalogLoading(true)
    setCatalogError('')
    getCheckCatalog().then((data) => {
      if (!data || !Array.isArray(data.groups)) throw new Error('Invalid check inventory')
      if (!cancelled) setCatalog(data)
    }).catch((error) => { if (!cancelled) setCatalogError(error.message) })
      .finally(() => { if (!cancelled) setCatalogLoading(false) })
    return () => { cancelled = true }
  }, [catalogAttempt])
  function upd(field, value) { setValues((previous) => ({ ...previous, [field]: value })) }
  function selectTab(id, focus = false) {
    setActiveTab(id)
    if (focus) document.getElementById(`scan-tab-${id}`)?.focus()
  }
  function tabKey(event, index) {
    let next
    if (event.key === 'ArrowRight') next = (index + 1) % TABS.length
    if (event.key === 'ArrowLeft') next = (index + TABS.length - 1) % TABS.length
    if (event.key === 'Home') next = 0
    if (event.key === 'End') next = TABS.length - 1
    if (next !== undefined) { event.preventDefault(); selectTab(TABS[next][0], true) }
  }
  const exclusions = ['exclude_paths', 'exclude_types', 'exclude_keywords'].reduce((sum, key) => sum + nonEmpty(values[key]).length, 0)
  const packs = nonEmpty(values.custom_rdl).length
  const disabledChecks = (values.exclude_checks || []).length
  const tabIndex = TABS.findIndex(([id]) => id === activeTab)
  const needsBaseline = values.baseline_mode === 'custom' && !values.baseline_file?.trim()
  const canSubmit = Boolean(values.target_dir.trim()) && !needsBaseline && !creating
  return <form className="scan-form-panel scan-config" onSubmit={(event) => { event.preventDefault(); if (canSubmit) onSubmit() }}>
    <div className="scan-form-header"><div><span className="scan-form-title">New scan</span><p>Configure a focused source code review.</p></div><span className="scan-config-default">{disabledChecks ? `${disabledChecks} ${disabledChecks === 1 ? 'class' : 'classes'} excluded` : 'All checks included'}</span></div>
    <div className="scan-config-tabs" role="tablist" aria-label="Scan configuration">
      {TABS.map(([id, label], index) => <button key={id} id={`scan-tab-${id}`} type="button" role="tab" aria-selected={activeTab === id} aria-controls={`scan-panel-${id}`} tabIndex={activeTab === id ? 0 : -1} onClick={() => selectTab(id)} onKeyDown={(event) => tabKey(event, index)}>{label}{id === 'exclusions' && exclusions > 0 && <span>{exclusions}</span>}{id === 'custom' && packs > 0 && <span>{packs}</span>}</button>)}
    </div>
    <div className="scan-config-layout">
      <div id={`scan-panel-${activeTab}`} className="scan-config-content" role="tabpanel" aria-labelledby={`scan-tab-${activeTab}`} tabIndex={0}>
        {activeTab === 'setup' && <>
          <div className="scan-section-heading"><h2>Project & scope</h2><p>Choose the source directory and the technologies to review.</p></div>
          <div className="form-field"><label className="form-label" htmlFor="scan-project">Project name</label><input id="scan-project" className="form-input" value={values.project_name} onChange={(e) => upd('project_name', e.target.value)} placeholder="Auto-generated if empty" /></div>
          <div className="form-field"><label className="form-label" htmlFor="scan-target">Target directory <span className="form-required">*</span></label><div className="input-addon"><input id="scan-target" className="form-input" value={values.target_dir} onChange={(e) => upd('target_dir', e.target.value)} placeholder="/path/to/source" /><button type="button" className="btn-addon" onClick={onBrowse}>Browse</button></div></div>
          <div className="form-field"><label className="form-label">Platforms & frameworks</label><RulesSelect value={values.rules} onChange={(rules) => setValues((previous) => ({ ...previous, rules, file_types: rules === 'auto' ? 'auto' : previous.file_types }))} /></div>
          <fieldset className="scan-engine-field">
            <legend className="form-label">Review mode</legend>
            <div className="scan-engine-grid">{ENGINES.map(([mode, label, description]) => <label key={mode} className={`scan-engine-choice${(values.rdl_engine || 'both') === mode ? ' selected' : ''}`}>
              <input type="radio" name="rdl_engine" aria-label={label} checked={(values.rdl_engine || 'both') === mode} onChange={() => setValues((previous) => ({ ...previous, rdl_engine: mode, custom_rdl: mode === 'v1' ? [] : previous.custom_rdl }))} />
              <span className="scan-engine-copy"><span className="scan-engine-title"><strong>{label}</strong>{mode === 'both' && <span className="scan-engine-badge">Recommended</span>}</span><small>{description}</small></span>
            </label>)}</div>
            <details className="scan-mode-help"><summary><span>Compare modes and understand the evidence</span><span className="scan-mode-help-hint">RDL v1 / v2</span></summary><div className="scan-mode-help-body">
            <div className="scan-review-explanation">
              <div><h3>Areas of Interest Filtering <span>RDL v1</span></h3><p>Regex finds code patterns and file paths worth reading. RDL conditions then filter those candidates. The results form your Areas of Interest for manual review.</p></div>
              <div><h3>Finding Analysis <span>RDL v2</span></h3><p>Checks applicable files beyond the regex areas of interest. It combines text and path checks with source analysis and semantic rules.</p><p><strong>Semantic analysis</strong> checks how relevant code is used. A rule may inspect a call and its arguments or look for a security control. Supported flow rules follow data towards a sensitive operation within a file or across files. Coverage depends on the rule and language.</p></div>
            </div>
            <div className="scan-v2-benefits"><h3>What RDL v2 adds to your review</h3><ul>
              <li><strong>Find more than pattern matches.</strong> V2 checks applicable files independently of the areas of interest list. It can surface issues that regex discovery misses.</li>
              <li><strong>Reduce misleading matches.</strong> Semantic rules inspect relevant calls and arguments. They can distinguish unsafe use from a supported protective control. A safe-looking setting elsewhere in the file is not enough.</li>
              <li><strong>Follow the evidence.</strong> Supported flow checks connect an input to a sensitive operation within a file or across files. Locations and recorded handoffs help you check how the issue arises.</li>
              <li><strong>Make a better review decision.</strong> Rule evidence and recorded limits help you decide what to investigate or dismiss. A match is a review lead rather than proof of an exploitable issue.</li>
            </ul><p>For example a deserialization check can inspect whether the actual call blocks object creation. A simple function-name match cannot establish that. Benefits depend on the selected rules and language support.</p></div>
            <div className="scan-review-guidance"><strong>Prefer to read the code before dismissing a result?</strong><p>Choose Comprehensive Review. Areas of Interest give you another route to inspect security areas of interest that Finding Analysis may miss or leave unresolved. Existing filters and exclusions still apply.</p></div>
            <p className="scan-config-note">RDL v1 filters security areas of interest. RDL v2 produces its own findings and evidence. They serve different roles. A rule match still needs review. Configure separate inter-file analysis in Analysis &amp; Output.</p>
            </div></details>
          </fieldset>
          <div className="form-field"><label className="form-label" htmlFor="scan-file-types">Include file types {values.rules === 'auto' && <span className="form-label-hint">Auto-detected from platforms</span>}</label><input id="scan-file-types" className="form-input" value={values.file_types} onChange={(e) => upd('file_types', e.target.value)} disabled={values.rules === 'auto'} placeholder="auto, or php, javascript" /><small className="text-muted">Choose technologies above to limit included types. Use Exclusions to omit extensions or paths.</small></div>
        </>}
        {activeTab === 'checks' && <CheckDatabase catalog={catalog} error={catalogError} loading={catalogLoading} reload={() => setCatalogAttempt((attempt) => attempt + 1)} excluded={values.exclude_checks || []} setExcluded={(ids) => upd('exclude_checks', ids)} />}
        {activeTab === 'exclusions' && <>
          <div className="scan-section-heading"><h2>File & finding exclusions</h2><p>Keep generated code, fixtures or known review noise outside this scan.</p></div>
          <LinesField id="scan-exclude-paths" label="File paths & directories" value={values.exclude_paths} onChange={(list) => upd('exclude_paths', list)} placeholder={'vendor/**\n**/generated/**\ntests/fixtures/example.php'} description="One project-relative path or glob per line. Directory patterns include their contents; matching is case-sensitive." />
          <div className="scan-fields-two"><LinesField id="scan-exclude-types" label="File types" value={values.exclude_types} onChange={(list) => upd('exclude_types', list)} placeholder={'.min.js\n.map\n*.snap'} description="One extension or filename glob per line. Matching is case-insensitive." /><LinesField id="scan-exclude-keywords" label="File content keywords" value={values.exclude_keywords} onChange={(list) => upd('exclude_keywords', list)} placeholder={'generated file — do not edit\nsynthetic fixture'} description="One literal phrase per line, case-insensitive. Any match excludes the whole file, including comments." /></div>
          <p className="scan-config-notice">File exclusions apply to discovery, source checks and analyzer dependency scope. Excluded helpers can reduce flow coverage.</p>
          <div className="scan-fields-two"><div className="form-field"><label className="form-label" htmlFor="scan-baseline-mode">Suppression baseline</label><select id="scan-baseline-mode" className="form-select" value={values.baseline_mode || 'default'} onChange={(e) => upd('baseline_mode', e.target.value)}><option value="default">Use configured baseline</option><option value="disabled">Ignore baseline for this scan</option><option value="custom">Use a custom baseline JSON</option></select><small className="text-muted">Baseline matches are retained as suppressed findings.</small></div><div className="form-field"><label className="form-label" htmlFor="scan-review-config">Review / triage JSON (optional)</label><input id="scan-review-config" className="form-input" value={values.review_config || ''} onChange={(e) => upd('review_config', e.target.value)} placeholder="/scan-targets/review.json" /><small className="text-muted">Apply previously reviewed false positives and suppressions.</small></div></div>
          {values.baseline_mode === 'custom' && <div className="form-field"><label className="form-label" htmlFor="scan-baseline-file">Baseline JSON path <span className="form-required">*</span></label><input id="scan-baseline-file" className="form-input" value={values.baseline_file || ''} onChange={(e) => upd('baseline_file', e.target.value)} placeholder="/scan-targets/baseline.json" /><small className="text-muted">The JSON file must be accessible within an allowed source or application directory.</small></div>}
        </>}
        {activeTab === 'analysis' && <>
          <div className="scan-section-heading"><h2>Analysis & output</h2><p>Choose supporting analysis and the level of scan detail.</p></div>
          <div className="scan-analysis-options">{OPTIONS.map(([key, label, description]) => <label key={key}><input type="checkbox" aria-label={label} checked={Boolean(values[key]) || (values.estimate && ['recon', 'loc'].includes(key))} disabled={Boolean(values.estimate && ['recon', 'loc'].includes(key))} onChange={(e) => setValues((previous) => ({ ...previous, [key]: e.target.checked, ...(key === 'estimate' && e.target.checked ? { recon: true, loc: true } : {}), ...(key === 'recon' && !e.target.checked ? { recon_strict: false } : {}) }))} /><span><strong>{label}</strong><small>{description}</small></span></label>)}<label className="scan-option-child"><input type="checkbox" aria-label="Strict reconnaissance" checked={Boolean(values.recon_strict)} disabled={!values.recon} onChange={(e) => upd('recon_strict', e.target.checked)} /><span><strong>Strict reconnaissance</strong><small>Keep high-confidence technology detections. Requires reconnaissance.</small></span></label></div>
          <div className="scan-fields-two"><div className="form-field"><label className="form-label" htmlFor="scan-verbosity">Log detail</label><select id="scan-verbosity" className="form-select" value={values.verbosity} onChange={(e) => upd('verbosity', Number(e.target.value))}><option value={1}>Normal</option><option value={2}>Verbose</option><option value={3}>Debug</option></select></div><div className="form-field"><label className="form-label" htmlFor="scan-state-mode">Scan checkpoints</label><select id="scan-state-mode" className="form-select" value={values.state_mode || 'default'} onChange={(e) => upd('state_mode', e.target.value)}><option value="default">Use system setting</option><option value="enabled">Enable for this scan</option><option value="disabled">Disable for this scan</option></select><small className="text-muted">Save scan progress in this run’s isolated workspace.</small></div></div>
          <div className="scan-config-notice"><strong>Reports</strong><p>Results are available in the Web UI. Use Reports after completion to generate downloadable HTML, PDF or Word documents.</p></div>
        </>}
        {activeTab === 'custom' && <>
          <div className="scan-section-heading"><h2>Project-specific RDL</h2><p>Add checks for business rules and source patterns unique to a project or related projects.</p></div>
          <LinesField id="custom-rdl-packs" label="App-specific RDL packs (optional)" value={values.custom_rdl} onChange={(list) => upd('custom_rdl', list)} disabled={values.rdl_engine === 'v1'} rows={5} placeholder="/app/examples/custom-rdl/schoolhub/pack.json" description="One pack JSON path per line, up to eight packs. Files must be accessible to the scanner within an allowed directory." />
          {values.rdl_engine === 'v1' && <p className="scan-config-notice">Select Comprehensive Review or Finding Analysis Only in Setup to include custom packs.</p>}
          {(values.exclude_checks || []).includes('custom') && <p className="scan-config-notice">Custom RDL checks are excluded in Check Classes. Re-enable that class to run selected packs.</p>}
          <div className="scan-custom-guide"><h3>Reusable project packs</h3><p>Keep a pack with the project’s rules, limit checks to relevant file globs, and give each rule a unique <code>custom.</code> ID. Related projects can share a pack or select their own version.</p><p>Pack definitions are validated before the scan is queued. Custom matches are review leads with source evidence.</p></div>
        </>}
      </div>
      <aside className="scan-config-summary" aria-label="Scan configuration summary"><h3>Scan summary</h3><dl><dt>Project</dt><dd>{values.project_name || 'Auto-generated'}</dd><dt>Target</dt><dd className="scan-summary-target">{values.target_dir || 'Choose a source directory'}</dd><dt>Technologies</dt><dd>{values.rules === 'auto' ? 'Auto-detect' : values.rules}</dd><dt>Review mode</dt><dd>{ENGINES.find(([id]) => id === (values.rdl_engine || 'both'))?.[1]}</dd><dt>Checks</dt><dd>{disabledChecks ? `${disabledChecks} ${disabledChecks === 1 ? 'class' : 'classes'} excluded` : 'All available checks'}</dd><dt>File exclusions</dt><dd>{exclusions || 'None'}</dd><dt>Custom packs</dt><dd>{packs || 'None'}</dd></dl><p>Settings apply only to this scan. Your draft stays intact when switching tabs.</p></aside>
    </div>
    <div className="scan-config-footer"><div className="scan-step-navigation"><button type="button" className="btn btn-ghost" disabled={tabIndex === 0} onClick={() => selectTab(TABS[tabIndex - 1][0])}>Previous</button>{tabIndex < TABS.length - 1 && <button type="button" className="btn btn-ghost" onClick={() => selectTab(TABS[tabIndex + 1][0])}>Next: {TABS[tabIndex + 1][1]} →</button>}</div><div className="scan-submit"><small>{needsBaseline ? 'Add the custom baseline path in Exclusions.' : !values.target_dir.trim() ? 'Choose a target directory to start.' : 'Ready to queue'}</small><button type="submit" className="btn btn-primary" disabled={!canSubmit}>{creating ? <><span className="spinner" /> Queueing…</> : 'Start Scan'}</button></div></div>
  </form>
}
