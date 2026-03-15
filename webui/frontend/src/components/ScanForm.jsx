const TOGGLE_INFO = {
  recon: {
    label: 'Reconnaissance',
    desc: 'Enumerate file types, directories, and technology stack before scanning. Useful for understanding the codebase surface area.',
  },
  estimate: {
    label: 'Effort Estimate',
    desc: 'Estimate manual review effort based on findings volume and complexity.',
  },
  analysis: {
    label: 'Inter-file Analysis',
    warn: true,
    desc: 'Trace taint flows across file and function boundaries to detect multi-hop vulnerabilities (e.g. user input in file A reaching a sink in file C). Runs after the base scan. Can be slow on large codebases — a 300-file / 1500-function cap is applied per language.',
  },
  loc: {
    label: 'Count Lines of Code',
    desc: 'Count source lines of code per file and language. Adds a LoC table to the report.',
  },
}

function InfoTooltip({ text }) {
  return (
    <span className="info-tip" tabIndex={0}>
      <svg width="13" height="13" viewBox="0 0 20 20" fill="currentColor">
        <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
      </svg>
      <span className="info-tip-text">{text}</span>
    </span>
  )
}

import RulesSelect from './RulesSelect'

export default function ScanForm({ values, setValues, onSubmit, onBrowse, creating }) {
  function upd(field, value) {
    setValues((p) => ({ ...p, [field]: value }))
  }

  function handleRulesChange(newRules) {
    // When switching back to auto, reset file_types to auto too
    const newFt = newRules === 'auto' ? 'auto' : values.file_types
    setValues((p) => ({ ...p, rules: newRules, file_types: newFt }))
  }

  return (
    <div className="scan-form-panel">
      <div className="scan-form-header">
        <span className="scan-form-title">New Scan</span>
        <span className="text-sm text-muted">CLI · API</span>
      </div>

      <div className="scan-form-body">
        {/* Project */}
        <div className="form-field">
          <label className="form-label">Project Name</label>
          <input
            className="form-input"
            value={values.project_name}
            onChange={(e) => upd('project_name', e.target.value)}
            placeholder="auto-generated if empty"
          />
        </div>

        {/* Target */}
        <div className="form-field">
          <label className="form-label">
            Target Directory <span className="form-required">*</span>
          </label>
          <div className="input-addon">
            <input
              className="form-input"
              value={values.target_dir}
              onChange={(e) => upd('target_dir', e.target.value)}
              placeholder="/path/to/source"
            />
            <button type="button" className="btn-addon" onClick={onBrowse}>
              Browse
            </button>
          </div>
        </div>

        {/* Rules */}
        <div className="form-field">
          <label className="form-label">Rules</label>
          <RulesSelect value={values.rules} onChange={handleRulesChange} />
        </div>

        {/* File Types */}
        <div className="form-field">
          <label className="form-label">
            File Types
            {values.rules === 'auto' && (
              <span className="form-label-hint">derived from detected platforms</span>
            )}
          </label>
          <input
            className="form-input"
            value={values.file_types}
            onChange={(e) => upd('file_types', e.target.value)}
            placeholder="auto"
            disabled={values.rules === 'auto'}
            style={values.rules === 'auto' ? { opacity: 0.5, cursor: 'not-allowed' } : undefined}
          />
        </div>

        {/* Report + Verbosity */}
        <div className="form-grid">
          <div className="form-field">
            <label className="form-label">Report Format</label>
            <select
              className="form-select"
              value={values.report_format}
              onChange={(e) => upd('report_format', e.target.value)}
            >
              <option value="html">HTML</option>
              <option value="html,pdf">HTML + PDF</option>
              <option value="pdf">PDF only</option>
            </select>
          </div>
          <div className="form-field">
            <label className="form-label">Verbosity</label>
            <select
              className="form-select"
              value={values.verbosity}
              onChange={(e) => upd('verbosity', Number(e.target.value))}
            >
              <option value={1}>-v (Normal)</option>
              <option value={2}>-vv (Verbose)</option>
              <option value={3}>-vvv (Debug)</option>
            </select>
          </div>
        </div>

        {/* Options */}
        <div>
          <div className="form-label" style={{ marginBottom: 8 }}>Options</div>

          {/* Always-on base scan */}
          <div className="base-scan-row">
            <span className="base-scan-dot" />
            <span className="base-scan-label">Pattern Scan</span>
            <span className="base-scan-tag">always on</span>
            <InfoTooltip text="The core scan — applies security rules to each file individually using pattern matching. Detects injection points, dangerous API usage, misconfigurations, and areas of interest. Always runs regardless of other options." />
          </div>

          {/* Optional toggles */}
          <div className="form-toggles" style={{ marginTop: 8 }}>
            {['recon', 'estimate', 'analysis', 'loc'].map((key) => {
              const { label, warn, desc } = TOGGLE_INFO[key]
              return (
                <label key={key} className={`toggle-item${warn ? ' toggle-warn' : ''}`}>
                  <input
                    type="checkbox"
                    checked={values[key]}
                    onChange={(e) => upd(key, e.target.checked)}
                  />
                  <span className="toggle-label-text">
                    {label}
                    {warn && <span className="toggle-warn-icon" title="Can be slow on large codebases">⚠</span>}
                  </span>
                  <InfoTooltip text={desc} />
                </label>
              )
            })}
          </div>
        </div>

        {/* Submit */}
        <button
          className="btn btn-primary w-full"
          style={{ justifyContent: 'center', marginTop: 2 }}
          disabled={creating || !values.target_dir.trim()}
          onClick={onSubmit}
        >
          {creating ? (
            <>
              <span className="spinner" />
              Queueing…
            </>
          ) : (
            <>
              <svg width="15" height="15" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM9.555 7.168A1 1 0 008 8v4a1 1 0 001.555.832l3-2a1 1 0 000-1.664l-3-2z" clipRule="evenodd" />
              </svg>
              Start Scan
            </>
          )}
        </button>
      </div>
    </div>
  )
}
