import { useEffect, useMemo, useRef, useState } from 'react'

/* ─── Rule catalog ───────────────────────────────────────────── */
export const RULE_CATALOG = [
  // ── Platforms ──────────────────────────────────────────────
  { id: 'php',        label: 'PHP',                    group: 'Web Backend',   ext: '*.php',                     kind: 'platform' },
  { id: 'java',       label: 'Java',                   group: 'Web Backend',   ext: '*.java, *.jsp',             kind: 'platform' },
  { id: 'python',     label: 'Python',                 group: 'Web Backend',   ext: '*.py',                      kind: 'platform' },
  { id: 'javascript', label: 'JavaScript / TypeScript',group: 'Web Backend',   ext: '*.js, *.ts',                kind: 'platform' },
  { id: 'dotnet',     label: '.NET (C# / VB)',          group: 'Web Backend',   ext: '*.cs, *.vb, *.aspx',        kind: 'platform' },
  { id: 'ruby',       label: 'Ruby',                   group: 'Web Backend',   ext: '*.rb',                      kind: 'platform' },
  { id: 'go',         label: 'Go',                     group: 'Web Backend',   ext: '*.go',                      kind: 'platform' },
  { id: 'kotlin',     label: 'Kotlin',                 group: 'Web Backend',   ext: '*.kt',                      kind: 'platform' },
  { id: 'rust',       label: 'Rust',                   group: 'Web Backend',   ext: '*.rs',                      kind: 'platform' },
  { id: 'c',          label: 'C',                      group: 'Systems',       ext: '*.c, *.h',                  kind: 'platform' },
  { id: 'cpp',        label: 'C++',                    group: 'Systems',       ext: '*.cpp, *.hpp, *.cc',        kind: 'platform' },
  { id: 'android',    label: 'Android',                group: 'Mobile',        ext: 'AndroidManifest.xml, *.kt', kind: 'platform' },
  { id: 'ios',        label: 'iOS',                    group: 'Mobile',        ext: '*.swift, *.m, *.mm',        kind: 'platform' },
  { id: 'reactnative',label: 'React Native',           group: 'Mobile',        ext: '*.js, *.jsx, *.ts, *.tsx',  kind: 'platform' },
  { id: 'flutter',    label: 'Flutter',                group: 'Mobile',        ext: '*.dart',                    kind: 'platform' },
  { id: 'xamarin',    label: 'Xamarin / MAUI',          group: 'Mobile',        ext: '*.cs, *.csproj',            kind: 'platform' },
  { id: 'ionic',      label: 'Ionic',                  group: 'Mobile',        ext: '*.ts, *.js, *.html',        kind: 'platform' },
  { id: 'nativescript',label:'NativeScript',           group: 'Mobile',        ext: '*.js, *.ts',                kind: 'platform' },
  { id: 'cordova',    label: 'Cordova / PhoneGap',      group: 'Mobile',        ext: 'config.xml, *.js',          kind: 'platform' },
  { id: 'common',     label: 'Common (all languages)', group: 'Cross-Platform',ext: 'all source files',          kind: 'platform' },
  // ── PHP Frameworks ─────────────────────────────────────────
  { id: 'laravel',     label: 'Laravel',      group: 'PHP Frameworks',        ext: '*.php',  kind: 'framework', parent: 'php' },
  { id: 'symfony',     label: 'Symfony',      group: 'PHP Frameworks',        ext: '*.php',  kind: 'framework', parent: 'php' },
  { id: 'codeigniter', label: 'CodeIgniter',  group: 'PHP Frameworks',        ext: '*.php',  kind: 'framework', parent: 'php' },
  { id: 'wordpress',   label: 'WordPress',    group: 'PHP Frameworks',        ext: '*.php',  kind: 'framework', parent: 'php' },
  { id: 'drupal',      label: 'Drupal',       group: 'PHP Frameworks',        ext: '*.php',  kind: 'framework', parent: 'php' },
  // ── Python Frameworks ──────────────────────────────────────
  { id: 'django',   label: 'Django',   group: 'Python Frameworks', ext: '*.py', kind: 'framework', parent: 'python' },
  { id: 'flask',    label: 'Flask',    group: 'Python Frameworks', ext: '*.py', kind: 'framework', parent: 'python' },
  { id: 'fastapi',  label: 'FastAPI',  group: 'Python Frameworks', ext: '*.py', kind: 'framework', parent: 'python' },
  // ── Java Frameworks ────────────────────────────────────────
  { id: 'spring',      label: 'Spring',      group: 'Java Frameworks', ext: '*.java', kind: 'framework', parent: 'java' },
  { id: 'springboot',  label: 'Spring Boot', group: 'Java Frameworks', ext: '*.java', kind: 'framework', parent: 'java' },
  { id: 'hibernate',   label: 'Hibernate',   group: 'Java Frameworks', ext: '*.java', kind: 'framework', parent: 'java' },
  // ── JS / TS Frameworks ─────────────────────────────────────
  { id: 'express', label: 'Express',  group: 'JS Frameworks', ext: '*.js, *.ts', kind: 'framework', parent: 'javascript' },
  { id: 'nestjs',  label: 'NestJS',   group: 'JS Frameworks', ext: '*.ts',       kind: 'framework', parent: 'javascript' },
  { id: 'react',   label: 'React',    group: 'JS Frameworks', ext: '*.jsx, *.tsx', kind: 'framework', parent: 'javascript' },
  { id: 'nextjs',  label: 'Next.js',  group: 'JS Frameworks', ext: '*.js, *.ts', kind: 'framework', parent: 'javascript' },
  { id: 'vue',     label: 'Vue',      group: 'JS Frameworks', ext: '*.vue, *.js',kind: 'framework', parent: 'javascript' },
  { id: 'angular', label: 'Angular',  group: 'JS Frameworks', ext: '*.ts',       kind: 'framework', parent: 'javascript' },
  // ── .NET Frameworks ────────────────────────────────────────
  { id: 'aspnetcore',     label: 'ASP.NET Core',    group: '.NET Frameworks', ext: '*.cs', kind: 'framework', parent: 'dotnet' },
  { id: 'entityframework',label: 'Entity Framework', group: '.NET Frameworks', ext: '*.cs', kind: 'framework', parent: 'dotnet' },
  // ── Go Frameworks ──────────────────────────────────────────
  { id: 'gin',   label: 'Gin',   group: 'Go Frameworks', ext: '*.go', kind: 'framework', parent: 'go' },
  { id: 'echo',  label: 'Echo',  group: 'Go Frameworks', ext: '*.go', kind: 'framework', parent: 'go' },
  { id: 'fiber', label: 'Fiber', group: 'Go Frameworks', ext: '*.go', kind: 'framework', parent: 'go' },
  // ── Ruby Frameworks ────────────────────────────────────────
  { id: 'rails',   label: 'Rails',   group: 'Ruby Frameworks', ext: '*.rb', kind: 'framework', parent: 'ruby' },
  { id: 'sinatra', label: 'Sinatra', group: 'Ruby Frameworks', ext: '*.rb', kind: 'framework', parent: 'ruby' },
  // ── Rust Frameworks ────────────────────────────────────────
  { id: 'actix',  label: 'Actix',  group: 'Rust Frameworks', ext: '*.rs', kind: 'framework', parent: 'rust' },
  { id: 'rocket', label: 'Rocket', group: 'Rust Frameworks', ext: '*.rs', kind: 'framework', parent: 'rust' },
  { id: 'axum',   label: 'Axum',   group: 'Rust Frameworks', ext: '*.rs', kind: 'framework', parent: 'rust' },
  // ── Kotlin Frameworks ──────────────────────────────────────
  { id: 'ktor',         label: 'Ktor',          group: 'Kotlin Frameworks', ext: '*.kt', kind: 'framework', parent: 'kotlin' },
  { id: 'springkotlin', label: 'Spring Kotlin', group: 'Kotlin Frameworks', ext: '*.kt', kind: 'framework', parent: 'kotlin' },
  // ── C / C++ Frameworks ────────────────────────────────────
  { id: 'freertos', label: 'FreeRTOS', group: 'C / C++ Frameworks', ext: '*.c, *.h',   kind: 'framework', parent: 'c' },
  { id: 'qt',       label: 'Qt',       group: 'C / C++ Frameworks', ext: '*.cpp, *.hpp', kind: 'framework', parent: 'cpp' },
  { id: 'boost',    label: 'Boost',    group: 'C / C++ Frameworks', ext: '*.cpp, *.hpp', kind: 'framework', parent: 'cpp' },
]

const GROUP_ORDER = [
  'Web Backend', 'Systems', 'Mobile', 'Cross-Platform',
  'PHP Frameworks', 'Python Frameworks', 'Java Frameworks',
  'JS Frameworks', '.NET Frameworks', 'Go Frameworks',
  'Ruby Frameworks', 'Rust Frameworks', 'Kotlin Frameworks', 'C / C++ Frameworks',
]

const BY_ID = Object.fromEntries(RULE_CATALOG.map((r) => [r.id, r]))

/* ─── Helpers ────────────────────────────────────────────────── */
function parseValue(val) {
  if (!val || val === 'auto') return []
  return val.split(',').map((s) => s.trim()).filter(Boolean)
}

function serializeValue(ids) {
  if (!ids.length) return 'auto'
  return ids.join(',')
}

/* ─── Chip ───────────────────────────────────────────────────── */
function Chip({ id, onRemove }) {
  const rule = BY_ID[id]
  const isFramework = rule?.kind === 'framework'
  return (
    <span className={`rs-chip${isFramework ? ' framework' : ''}`}>
      {rule?.label || id}
      <button className="rs-chip-remove" onClick={() => onRemove(id)} tabIndex={-1} type="button">×</button>
    </span>
  )
}

/* ─── Main RulesSelect ───────────────────────────────────────── */
export default function RulesSelect({ value, onChange }) {
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState('')
  const wrapRef = useRef(null)
  const inputRef = useRef(null)

  const isAuto = !value || value === 'auto'
  const selected = useMemo(() => parseValue(value), [value])

  // Close on outside click
  useEffect(() => {
    function handler(e) {
      if (wrapRef.current && !wrapRef.current.contains(e.target)) {
        setOpen(false)
        setSearch('')
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  function toggleRule(id) {
    if (id === 'auto') {
      onChange('auto')
      setOpen(false)
      setSearch('')
      return
    }
    const next = selected.includes(id)
      ? selected.filter((s) => s !== id)
      : [...selected, id]
    onChange(serializeValue(next))
  }

  function removeChip(id) {
    const next = selected.filter((s) => s !== id)
    onChange(serializeValue(next))
  }

  function clearAll() {
    onChange('auto')
    setSearch('')
    if (inputRef.current) inputRef.current.focus()
  }

  // Filtered catalog
  const filtered = useMemo(() => {
    const q = search.toLowerCase()
    return q
      ? RULE_CATALOG.filter(
          (r) => r.label.toLowerCase().includes(q) || r.id.includes(q) || r.group.toLowerCase().includes(q)
        )
      : RULE_CATALOG
  }, [search])

  // Group the filtered results
  const groups = useMemo(() => {
    const map = new Map()
    for (const item of filtered) {
      if (!map.has(item.group)) map.set(item.group, [])
      map.get(item.group).push(item)
    }
    // Sort groups by canonical order
    return GROUP_ORDER.filter((g) => map.has(g)).map((g) => ({ group: g, items: map.get(g) }))
  }, [filtered])

  return (
    <div className="rs-wrap" ref={wrapRef}>
      {/* Input area */}
      <div
        className={`rs-input-area${open ? ' focused' : ''}`}
        onClick={() => { setOpen(true); inputRef.current?.focus() }}
      >
        {/* Auto badge OR chips */}
        {isAuto && !search ? (
          <span className="rs-auto-badge">
            <svg width="11" height="11" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M11.49 3.17c-.38-1.56-2.6-1.56-2.98 0a1.532 1.532 0 01-2.286.948c-1.372-.836-2.942.734-2.106 2.106.54.886.061 2.042-.947 2.287-1.561.379-1.561 2.6 0 2.978a1.532 1.532 0 01.947 2.287c-.836 1.372.734 2.942 2.106 2.106a1.532 1.532 0 012.287.947c.379 1.561 2.6 1.561 2.978 0a1.533 1.533 0 012.287-.947c1.372.836 2.942-.734 2.106-2.106a1.533 1.533 0 01.947-2.287c1.561-.379 1.561-2.6 0-2.978a1.532 1.532 0 01-.947-2.287c.836-1.372-.734-2.942-2.106-2.106a1.532 1.532 0 01-2.287-.947zM10 13a3 3 0 100-6 3 3 0 000 6z" clipRule="evenodd" />
            </svg>
            Auto-detect
          </span>
        ) : (
          selected.map((id) => <Chip key={id} id={id} onRemove={removeChip} />)
        )}

        {/* Search input */}
        <input
          ref={inputRef}
          className="rs-search-input"
          placeholder={isAuto && !selected.length ? 'Search or select rules…' : selected.length ? 'Add more…' : 'Search…'}
          value={search}
          onChange={(e) => { setSearch(e.target.value); setOpen(true) }}
          onFocus={() => setOpen(true)}
          onKeyDown={(e) => {
            if (e.key === 'Escape') { setOpen(false); setSearch('') }
            if (e.key === 'Backspace' && !search && selected.length) {
              removeChip(selected[selected.length - 1])
            }
          }}
        />

        {/* Clear / chevron */}
        <span className="rs-actions">
          {(!isAuto || selected.length > 0) && (
            <button className="rs-clear-btn" onClick={(e) => { e.stopPropagation(); clearAll() }} type="button" tabIndex={-1} title="Reset to auto">
              ×
            </button>
          )}
          <span className="rs-chevron" style={{ transform: open ? 'rotate(180deg)' : undefined }}>▾</span>
        </span>
      </div>

      {/* Dropdown */}
      {open && (
        <div className="rs-dropdown">
          {/* Auto option */}
          <div
            className={`rs-option rs-auto-option${isAuto ? ' selected' : ''}`}
            onClick={() => toggleRule('auto')}
          >
            <span className="rs-opt-check">{isAuto ? '●' : '○'}</span>
            <span className="rs-auto-star">
              <svg width="13" height="13" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M11.49 3.17c-.38-1.56-2.6-1.56-2.98 0a1.532 1.532 0 01-2.286.948c-1.372-.836-2.942.734-2.106 2.106.54.886.061 2.042-.947 2.287-1.561.379-1.561 2.6 0 2.978a1.532 1.532 0 01.947 2.287c-.836 1.372.734 2.942 2.106 2.106a1.532 1.532 0 012.287.947c.379 1.561 2.6 1.561 2.978 0a1.533 1.533 0 012.287-.947c1.372.836 2.942-.734 2.106-2.106a1.533 1.533 0 01.947-2.287c1.561-.379 1.561-2.6 0-2.978a1.532 1.532 0 01-.947-2.287c.836-1.372-.734-2.942-2.106-2.106a1.532 1.532 0 01-2.287-.947zM10 13a3 3 0 100-6 3 3 0 000 6z" clipRule="evenodd" />
              </svg>
            </span>
            <span className="rs-opt-label">
              Auto-detect
              <span className="rs-opt-sub">Detect platforms &amp; frameworks from codebase automatically</span>
            </span>
          </div>

          <div className="rs-divider" />

          {/* Grouped list */}
          {groups.length === 0 ? (
            <div className="rs-empty">No rules match "{search}"</div>
          ) : (
            groups.map(({ group, items }) => (
              <div key={group} className="rs-group">
                <div className="rs-group-header">{group}</div>
                {items.map((rule) => {
                  const isSel = selected.includes(rule.id)
                  return (
                    <div
                      key={rule.id}
                      className={`rs-option${isSel ? ' selected' : ''}${rule.kind === 'framework' ? ' framework' : ''}`}
                      onClick={() => toggleRule(rule.id)}
                    >
                      <span className="rs-opt-check">{isSel ? '●' : '○'}</span>
                      <span className="rs-opt-label">
                        {rule.label}
                        <span className="rs-opt-ext">{rule.ext}</span>
                      </span>
                      {rule.kind === 'framework' && (
                        <span className="rs-fw-tag">framework</span>
                      )}
                    </div>
                  )
                })}
              </div>
            ))
          )}
        </div>
      )}
    </div>
  )
}
