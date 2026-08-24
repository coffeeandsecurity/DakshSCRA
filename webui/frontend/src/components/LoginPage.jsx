import { useEffect, useRef, useState } from 'react'
import { getBootstrapInfo, login } from '../api'
import BrandLogo from './BrandLogo'

const FEATURES = [
  'Areas-of-interest detection across 20+ languages & mobile platforms',
  'RDL-gated findings, so obviously-mitigated matches are auto-suppressed',
  'Taint-flow analysis, effort estimation, and framework-aware scanning',
]

function CheckIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
      <path fillRule="evenodd" d="M16.704 5.29a1 1 0 010 1.415l-7.5 7.5a1 1 0 01-1.414 0l-3.5-3.5a1 1 0 111.414-1.414l2.793 2.793 6.793-6.793a1 1 0 011.414 0z" clipRule="evenodd" />
    </svg>
  )
}

export default function LoginPage({ onLoggedIn }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  const [firstTimeSetup, setFirstTimeSetup] = useState(false)
  const [defaultPassword, setDefaultPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const usernameRef = useRef(null)
  const passwordRef = useRef(null)

  useEffect(() => {
    // Bootstrap credentials are only returned while the configured admin is
    // still pending its mandatory first password change. No credential is
    // returned, populated, or retained after that state is cleared.
    getBootstrapInfo()
      .then((info) => {
        if (info.default_credentials_pending) {
          setUsername(info.default_username)
          setDefaultPassword(info.default_password || '')
          setPassword(info.default_password || '')
          setFirstTimeSetup(true)
          // autoFocus only fires on initial mount, and this state arrives
          // asynchronously after that - focus the password field manually
          // once we know the username is already filled in.
          passwordRef.current?.focus()
        }
      })
      .catch(() => {})
  }, [])

  async function handleSubmit(e) {
    e.preventDefault()
    if (!username.trim() || !password) {
      setError('Username and password are required.')
      return
    }
    setSubmitting(true)
    setError('')
    try {
      const user = await login(username.trim(), password)
      setPassword('')
      setDefaultPassword('')
      setShowPassword(false)
      onLoggedIn(user)
    } catch (err) {
      setError(err.message === 'invalid_credentials' ? 'Invalid username or password.' : err.message)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="auth-page">
      <div className="auth-brand-panel">
        <div className="auth-brand-content">
          <div className="auth-brand-logo">
            <BrandLogo size={64} />
          </div>
          <div className="auth-brand-name">DAKSH SCRA</div>
          <div className="auth-brand-sub">Code Security Review</div>
          <p className="auth-brand-tagline">
            Structured, framework-aware source code review that surfaces areas of
            interest for a human to confirm - not another wall of unreviewed alerts.
          </p>
          <div className="auth-brand-features">
            {FEATURES.map((f) => (
              <div className="auth-brand-feature" key={f}>
                <CheckIcon />
                <span>{f}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="auth-brand-footer">© {new Date().getFullYear()} Daksh SCRA - coffeeandsecurity.com</div>
      </div>

      <div className="auth-form-panel">
        <div className="auth-form-card">
          <div className="auth-form-logo-mobile">
            <BrandLogo size={48} />
          </div>
          <div className="auth-heading">Welcome back</div>
          <div className="auth-subheading">Sign in to your DAKSH SCRA account to continue.</div>

          <form onSubmit={handleSubmit}>
            {firstTimeSetup && !error && (
              <div className="auth-hint-banner">
                <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-8-4a1 1 0 100 2 1 1 0 000-2zm-1 4a1 1 0 112 0v3a1 1 0 11-2 0v-3z" clipRule="evenodd" />
                </svg>
                {defaultPassword ? (
                  <span>
                    First-time setup detected. The configured credentials have been prefilled.
                    Sign in as <strong>{username}</strong>, then set your own password.
                  </span>
                ) : (
                  <span>
                    First-time setup detected. Sign in as <strong>{username}</strong> using the
                    password printed to the API's startup log (no <code>DAKSH_ADMIN_PASSWORD</code>{' '}
                    was configured, so a random one-time password was generated). You'll be asked
                    to set your own password right after.
                  </span>
                )}
              </div>
            )}
            {error && (
              <div className="error-banner" style={{ marginBottom: 16 }}>
                <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                </svg>
                {error}
              </div>
            )}
            <div className="form-field">
              <label className="form-label" htmlFor="login-username">Username</label>
              <input
                id="login-username"
                ref={usernameRef}
                className="form-input"
                type="text"
                autoComplete="username"
                autoFocus
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                disabled={submitting}
              />
            </div>
            <div className="form-field" style={{ marginTop: 14 }}>
              <label className="form-label" htmlFor="login-password">Password</label>
              <div className="auth-password-field">
                <input
                  id="login-password"
                  ref={passwordRef}
                  className="form-input"
                  type={showPassword ? 'text' : 'password'}
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={submitting}
                />
                {firstTimeSetup && defaultPassword ? (
                  <button
                    type="button"
                    className="auth-password-toggle"
                    onClick={() => setShowPassword((visible) => !visible)}
                    aria-label={`${showPassword ? 'Hide' : 'Show'} password`}
                    aria-pressed={showPassword}
                  >
                    {showPassword ? 'Hide' : 'Show'}
                  </button>
                ) : null}
              </div>
            </div>
            <button
              type="submit"
              className="btn btn-primary"
              style={{ width: '100%', marginTop: 22, justifyContent: 'center', padding: '10px 14px' }}
              disabled={submitting}
            >
              {submitting ? 'Signing in…' : 'Sign in'}
            </button>
          </form>

          <div className="auth-form-footer">Access is restricted to authorized reviewers only.</div>
        </div>
      </div>
    </div>
  )
}
