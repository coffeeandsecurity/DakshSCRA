import { useEffect, useState } from 'react'
import { getSettings, saveSettings } from '../api'

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

function SettingGroup({ title, children }) {
  return (
    <div className="settings-group">
      <div className="settings-group-title">{title}</div>
      <div className="settings-group-body">{children}</div>
    </div>
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
      <div className="settings-control">
        <span className="settings-readonly">{value}</span>
      </div>
    </div>
  )
}

/* ─── Main component ─────────────────────────────────────────── */
export default function SettingsPanel({ onToast }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [dirty, setDirty] = useState(false)

  useEffect(() => {
    getSettings()
      .then((d) => { setData(d); setLoading(false) })
      .catch((e) => {
        setLoading(false)
        onToast?.(e.message, 'error', 'Failed to load settings')
      })
  }, [])

  function update(section, key, value) {
    setData((prev) => ({ ...prev, [section]: { ...prev[section], [key]: value } }))
    setDirty(true)
  }

  async function handleSave() {
    setSaving(true)
    try {
      const saved = await saveSettings(data)
      setData(saved)
      setDirty(false)
      onToast?.('Settings saved successfully', 'success', 'Saved')
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
        <button
          className={`btn btn-primary${dirty ? '' : ' btn-disabled'}`}
          onClick={handleSave}
          disabled={saving || !dirty}
        >
          {saving ? 'Saving...' : 'Save Changes'}
        </button>
      </div>

      <div className="settings-body">

        {/* Tool info — read only */}
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
        <SettingGroup title="Display">
          <Field
            label="Timezone"
            hint="Timestamps in CLI output and reports use this timezone. Leave empty to use the server's local time."
          >
            <select
              className="form-select"
              value={data.display.timezone}
              onChange={(e) => update('display', 'timezone', e.target.value)}
            >
              <option value="">Server local time (default)</option>
              <optgroup label="Common timezones">
                {TIMEZONES.filter(Boolean).map((tz) => (
                  <option key={tz} value={tz}>{tz}</option>
                ))}
              </optgroup>
            </select>
          </Field>
          {data.display.timezone && (
            <div className="settings-callout">
              Timestamps will use <strong>{data.display.timezone}</strong>. Any valid IANA timezone name is accepted (e.g. <code>Asia/Kolkata</code>, <code>America/Chicago</code>).
            </div>
          )}
        </SettingGroup>

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
          <Field label="Max files per platform" hint="Safety limit to prevent unbounded analysis on large codebases">
            <NumberInput
              value={data.analysis.max_files_per_platform}
              onChange={(v) => update('analysis', 'max_files_per_platform', v)}
              min={1} max={10000}
            />
          </Field>
          <Field label="Max functions per platform" hint="Safety limit on the number of functions parsed per platform">
            <NumberInput
              value={data.analysis.max_functions_per_platform}
              onChange={(v) => update('analysis', 'max_functions_per_platform', v)}
              min={1} max={50000}
            />
          </Field>
        </SettingGroup>

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

        {/* Effort estimation */}
        <SettingGroup title="Effort Estimation">
          <Field label="Efficiency factor (%)" hint="Reviewer efficiency percentage used in effort calculations">
            <NumberInput
              value={data.estimation.efficiency_factor}
              onChange={(v) => update('estimation', 'efficiency_factor', v)}
              min={1} max={100}
            />
          </Field>
          <Field label="Buffer (days)" hint="Extra days added to the estimated effort as a buffer">
            <NumberInput
              value={data.estimation.buffer}
              onChange={(v) => update('estimation', 'buffer', v)}
              min={0} max={30}
            />
          </Field>
        </SettingGroup>

      </div>
    </div>
  )
}
