import { setDisplayPreferences } from '../lib/datetime'
import { useEffect, useId, useState } from 'react'
import { getSettings, saveSettings } from '../api'
import EffortAssumptions from './EffortAssumptions'

const SETTINGS_TABS = [
  { id: 'general', title: 'General', sections: ['project', 'display'], description: 'Project defaults and date and time preferences.' },
  { id: 'analysis', title: 'Analysis', sections: ['analysis'], description: 'Analysis coverage, framework rules and report appearance.' },
  { id: 'recovery', title: 'Scan recovery', sections: ['state_management'], description: 'Checkpoints and resume options for interrupted scans.' },
  { id: 'effort', title: 'Effort estimation', sections: ['estimation'], description: 'Default rates and planning assumptions for review estimates.' },
]

const TIMEZONES = [
  '', 'UTC',
  'America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles',
  'America/Sao_Paulo',
  'Europe/London', 'Europe/Paris', 'Europe/Berlin', 'Europe/Moscow',
  'Asia/Kolkata', 'Asia/Singapore', 'Asia/Tokyo', 'Asia/Shanghai', 'Asia/Dubai',
  'Australia/Sydney', 'Pacific/Auckland',
]

const REPORT_THEMES = [
  { value: 'hacker_mode', label: 'Hacker Mode (dark high-contrast)' },
  { value: 'professional_mode', label: 'Professional Mode (light)' },
  { value: 'both', label: 'Both (generate both variants)' },
]

const RESUME_MODES = [
  { value: 'manual', label: 'Manual (--resume-scan flag required)' },
  { value: 'auto', label: 'Auto (resume automatically if interrupted)' },
]

function SettingGroup({ title, children, defaultExpanded = true }) {
  const [expanded, setExpanded] = useState(defaultExpanded)
  const bodyId = useId()
  return (
    <section className="settings-group">
      <h3 className="settings-group-heading">
        <button type="button" className="settings-group-title" aria-expanded={expanded} aria-controls={bodyId} onClick={() => setExpanded(value => !value)}>
          <span>{title}</span><span className="settings-group-action">{expanded ? 'Collapse' : 'Expand'} <span aria-hidden="true">{expanded ? '−' : '+'}</span></span>
        </button>
      </h3>
      <div id={bodyId} className="settings-group-body" hidden={!expanded}>{children}</div>
    </section>
  )
}

function Field({ label, hint, children }) {
  return (
    <div className="settings-field">
      <label className="settings-label">
        {label}
        {hint && <span className="settings-hint">{hint}</span>}
      </label>
      <div className="settings-control">{children}</div>
    </div>
  )
}

function TextInput({ value, onChange, placeholder = '' }) {
  return (
    <input
      className="form-input"
      type="text"
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
    />
  )
}

function NumberInput({ value, onChange, min, max }) {
  return (
    <input
      className="form-input"
      type="number"
      value={value}
      min={min}
      max={max}
      onChange={(e) => onChange(Number(e.target.value))}
      style={{ width: '120px' }}
    />
  )
}

function SelectInput({ value, onChange, options }) {
  return (
    <select className="form-select" value={value} onChange={(e) => onChange(e.target.value)}>
      {options.map((o) => (
        <option key={o.value} value={o.value}>{o.label}</option>
      ))}
    </select>
  )
}

function Toggle({ checked, onChange, label }) {
  return (
    <label className="toggle-label" style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px' }}>
      <div className={`toggle-track${checked ? ' on' : ''}`} onClick={() => onChange(!checked)}>
        <div className="toggle-thumb" />
      </div>
      {label && <span className="settings-hint" style={{ margin: 0 }}>{label}</span>}
    </label>
  )
}

function ReadOnlyField({ label, value }) {
  return (
    <div className="settings-field">
      <label className="settings-label">{label}</label>
      <div className="settings-control"><span className="settings-readonly">{value}</span></div>
    </div>
  )
}

/* ─── Main component ─────────────────────────────────────────── */
export default function SettingsPanel({ onToast }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [baseline, setBaseline] = useState(null)
  const [activeTab, setActiveTab] = useState('general')
  const currentTab = SETTINGS_TABS.find(tab => tab.id === activeTab)
  const isDirty = tab => tab.sections.some(section => JSON.stringify(data?.[section]) !== JSON.stringify(baseline?.[section]))
  const dirty = isDirty(currentTab)

  useEffect(() => {
    getSettings()
      .then((d) => { setData(d); setBaseline(d); setLoading(false) })
      .catch((e) => {
        setLoading(false)
        onToast?.(e.message, 'error', 'Failed to load settings')
      })
  }, [])

  function update(section, key, value) {
    setData((prev) => ({ ...prev, [section]: { ...prev[section], [key]: value } }))
  }

  async function handleSave() {
    setSaving(true)
    try {
      const latest = await getSettings()
      const changes = Object.fromEntries(currentTab.sections.map(section => [section, data[section]]))
      const saved = await saveSettings({ ...latest, ...changes })
      setBaseline(saved)
      setData(previous => ({ ...previous, ...Object.fromEntries(currentTab.sections.map(section => [section, saved[section]])) }))
      if (currentTab.sections.includes('display')) setDisplayPreferences(saved.display)
      onToast?.(`${currentTab.title} settings saved`, 'success', 'Saved')
    } catch (e) {
      onToast?.(e.message, 'error', 'Save Failed')
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return <div className="settings-loading">Loading settings...</div>
  }

  if (!data) return null

  return (
    <div className="settings-shell">
      <div className="settings-header">
        <div>
          <div className="settings-title">Settings</div>
          <div className="settings-subtitle">Configure tool behaviour, analysis limits, and display preferences. Changes apply to the next scan run.</div>
        </div>

      </div>

      <div className="settings-tabs" role="tablist" aria-label="Settings categories" onKeyDown={event => {
        if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key) || saving) return
        event.preventDefault()
        const index = SETTINGS_TABS.findIndex(tab => tab.id === activeTab)
        const next = event.key === 'Home' ? SETTINGS_TABS[0] : event.key === 'End' ? SETTINGS_TABS.at(-1) : SETTINGS_TABS[(index + (event.key === 'ArrowRight' ? 1 : SETTINGS_TABS.length - 1)) % SETTINGS_TABS.length]
        setActiveTab(next.id); document.getElementById(`settings-tab-${next.id}`)?.focus()
      }}>
        {SETTINGS_TABS.map(tab => <button key={tab.id} type="button" role="tab" id={`settings-tab-${tab.id}`} aria-selected={activeTab === tab.id} aria-controls="settings-category-panel" tabIndex={activeTab === tab.id ? 0 : -1} disabled={saving} onClick={() => setActiveTab(tab.id)}>{tab.title}{isDirty(tab) && <span className="settings-unsaved" aria-label="Unsaved changes"> •</span>}</button>)}
      </div>
      <div role="tabpanel" id="settings-category-panel" aria-labelledby={`settings-tab-${activeTab}`}>
        <div className="settings-category-heading"><div><h2>{currentTab.title}</h2><p>{currentTab.description}</p></div><button type="button" className="btn btn-primary" disabled={saving || !dirty} onClick={handleSave}>{saving ? 'Saving…' : 'Save Changes'}</button></div>
        <p className="settings-save-note" role="status">{dirty ? 'Unsaved changes in this tab. Save Changes applies only to this category.' : 'No unsaved changes in this tab.'}</p>
      <fieldset className="settings-body settings-fields" disabled={saving}>

        {activeTab === 'general' && <>
        {/* Tool info - read only */}
        <SettingGroup title="Tool">
          <ReadOnlyField label="Name" value={data.tool_info.tool_name} />
          <ReadOnlyField label="Release" value={data.tool_info.release} />
        </SettingGroup>

        {/* Project defaults */}
        <SettingGroup title="Project Defaults">
          <Field label="Default project title" hint="Used in reports when no project name is provided">
            <TextInput value={data.project.title} onChange={(v) => update('project', 'title', v)} placeholder="e.g. Security Review" />
          </Field>
          <Field label="Default subtitle" hint="Shown below the project title in reports">
            <TextInput value={data.project.subtitle} onChange={(v) => update('project', 'subtitle', v)} placeholder="e.g. v1.0 / Client Name" />
          </Field>
        </SettingGroup>

        {/* Display */}
        <SettingGroup title="Global date and time">
          <Field label="Date format" hint="Used throughout the web UI, CLI and generated reports.">
            <select value={data.display.date_format || 'MM-DD-YYYY'} onChange={e => update('display', 'date_format', e.target.value)}>
              {['MM-DD-YYYY', 'DD-MM-YYYY', 'YYYY-MM-DD'].map(value => <option key={value}>{value}</option>)}
            </select>
          </Field>
          <Field label="Time format">
            <select value={data.display.time_format || '24h'} onChange={e => update('display', 'time_format', e.target.value)}>
              <option value="24h">24-hour</option><option value="12h">12-hour (AM/PM)</option>
            </select>
          </Field>
          <Field
            label="Timezone"
            hint="Timestamps in the web UI, CLI and reports use this timezone. Use an IANA time zone; UTC is the default."
          >
            <input list="global-timezones" value={data.display.timezone || 'UTC'}
              onChange={e => update('display', 'timezone', e.target.value)} aria-label="Time zone" />
            <datalist id="global-timezones">{TIMEZONES.filter(Boolean).map(tz => <option key={tz} value={tz} />)}</datalist>
          </Field>
          {data.display.timezone && (
            <div className="settings-callout">
              Timestamps will use <strong>{data.display.timezone}</strong>. Any valid IANA timezone name is accepted (e.g. <code>Asia/Kolkata</code>, <code>America/Chicago</code>).
            </div>
          )}
        </SettingGroup>

        </>}
        {activeTab === 'analysis' && <>
        {/* Analysis */}
        <SettingGroup title="Analysis">
          <Field label="Run by default" hint="Enable taint analysis automatically on every scan">
            <Toggle
              checked={data.analysis.run_by_default}
              onChange={(v) => update('analysis', 'run_by_default', v)}
              label={data.analysis.run_by_default ? 'Enabled' : 'Disabled (use --skip-analysis to override per scan)'}
            />
          </Field>
          <Field label="Include frameworks" hint="Include detected framework-specific rules in analysis output">
            <Toggle
              checked={data.analysis.include_frameworks}
              onChange={(v) => update('analysis', 'include_frameworks', v)}
              label={data.analysis.include_frameworks ? 'Enabled' : 'Disabled'}
            />
          </Field>
          <Field label="Report theme" hint="Visual theme for the analysis HTML report">
            <SelectInput
              value={data.analysis.report_theme}
              onChange={(v) => update('analysis', 'report_theme', v)}
              options={REPORT_THEMES}
            />
          </Field>
          <Field label="Max files per platform (0 = all)" hint="0 includes all files. A positive value deliberately limits coverage.">
            <NumberInput
              value={data.analysis.max_files_per_platform}
              onChange={(v) => update('analysis', 'max_files_per_platform', v)}
              min={0}
            />
          </Field>
          <Field label="Max functions per platform (0 = all)" hint="0 includes all functions. A positive value deliberately limits coverage.">
            <NumberInput
              value={data.analysis.max_functions_per_platform}
              onChange={(v) => update('analysis', 'max_functions_per_platform', v)}
              min={0}
            />
          </Field>
        </SettingGroup>

        </>}
        {activeTab === 'recovery' && <>
        {/* State management */}
        <SettingGroup title="Scan State Management">
          <Field label="Enable checkpointing" hint="Save scan progress to disk so interrupted scans can be resumed">
            <Toggle
              checked={data.state_management.enabled}
              onChange={(v) => update('state_management', 'enabled', v)}
              label={data.state_management.enabled ? 'Enabled' : 'Disabled'}
            />
          </Field>
          <Field label="Resume mode" hint="How a scan resumes after interruption">
            <SelectInput
              value={data.state_management.resume_mode}
              onChange={(v) => update('state_management', 'resume_mode', v)}
              options={RESUME_MODES}
            />
          </Field>
          <Field label="Checkpoint delay (seconds)" hint="Wait this many seconds after scan start before first checkpoint">
            <NumberInput
              value={data.state_management.persist_after_seconds}
              onChange={(v) => update('state_management', 'persist_after_seconds', v)}
              min={0} max={3600}
            />
          </Field>
          <Field label="Checkpoint interval (seconds)" hint="How often to write checkpoint updates during a scan">
            <NumberInput
              value={data.state_management.persist_interval_seconds}
              onChange={(v) => update('state_management', 'persist_interval_seconds', v)}
              min={5} max={600}
            />
          </Field>
          <Field label="Cleanup on success" hint="Delete the checkpoint file after a scan completes successfully">
            <Toggle
              checked={data.state_management.cleanup_on_success}
              onChange={(v) => update('state_management', 'cleanup_on_success', v)}
              label={data.state_management.cleanup_on_success ? 'Delete on success' : 'Keep checkpoint'}
            />
          </Field>
        </SettingGroup>

        </>}
        {activeTab === 'effort' && <>
        {/* Effort estimation */}
        <SettingGroup title="Effort Estimation">
          <p className="settings-intro">Organization-wide review baseline. Set separate issue rates for areas of interest, confirmed/RDL-supported findings and fully manual review. Enter the same low and high value for a fixed rate. These defaults apply unless a reviewer overrides them in Insights → Effort Estimate; planning assumptions are not measured productivity.</p>
          <EffortAssumptions values={data.estimation.assumptions} onChange={(values) => update('estimation', 'assumptions', values)} />
        </SettingGroup>

        </>}
      </fieldset>
      </div>
    </div>
  )
}
