import { useState } from 'react'
import { changePassword } from '../api'
import BrandLogo from './BrandLogo'

// Unskippable: rendered instead of the app shell whenever the logged-in
// user's password was assigned by someone/something else (initial admin
// bootstrap, an admin creating the account, or an admin password reset).
// There is no way to dismiss this without successfully changing the
// password - only `onChanged` (a successful submit) clears it.
export default function ChangePasswordGate({ user, onChanged, onLogout, voluntary = false, onCancel }) {
  // Username can only be changed during the mandatory first-time/reset flow
  // (voluntary === false) - once that's done, the admin username is fixed
  // unless reset again via exclude/scripts/reset_first_time_setup.py. The
  // backend enforces this independently (rejects new_username on a
  // voluntary change), so this is UX, not the actual boundary.
  const [newUsername, setNewUsername] = useState(user?.username || '')
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  async function handleSubmit(e) {
    e.preventDefault()
    if (!voluntary && !newUsername.trim()) {
      setError('Username cannot be empty.')
      return
    }
    if ((voluntary && !currentPassword) || !newPassword) {
      setError('All fields are required.')
      return
    }
    if (newPassword.length < 8) {
      setError('New password must be at least 8 characters.')
      return
    }
    if (newPassword !== confirmPassword) {
      setError('New password and confirmation do not match.')
      return
    }
    if (voluntary && newPassword === currentPassword) {
      setError('New password must be different from your current password.')
      return
    }
    setSubmitting(true)
    setError('')
    try {
      const trimmedUsername = newUsername.trim()
      const usernameChanged = !voluntary && trimmedUsername !== user?.username
      const updated = await changePassword(voluntary ? currentPassword : undefined, newPassword, usernameChanged ? trimmedUsername : undefined)
      onChanged(updated)
    } catch (err) {
      if (err.message === 'invalid_credentials') setError('Current password is incorrect.')
      else if (err.message === 'username_taken') setError('That username is already taken.')
      else setError(err.message)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div
      className={voluntary ? 'password-dialog-overlay' : ''}
      style={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: voluntary ? 'rgba(15, 23, 42, 0.55)' : 'var(--bg)',
      }}
    >
      <div className="card" style={{ width: 400, maxWidth: '90vw' }}>
        <div className="card-header" style={{ flexDirection: 'column', alignItems: 'center', textAlign: 'center', gap: 12 }}>
          <BrandLogo size={40} />
          <div>
            <div className="card-title">{voluntary ? 'Change Password' : 'Password Change Required'}</div>
            <div className="card-subtitle">
              {voluntary
                ? `Update the password for ${user?.username || 'your account'}.`
                : <>{user?.username ? `Hi ${user.username}, y` : 'Y'}our password was set by an administrator. You must choose your own password before continuing.</>}
            </div>
          </div>
        </div>
        <div className="card-body">
          <form onSubmit={handleSubmit}>
            {error && (
              <div className="error-banner" style={{ marginBottom: 16 }}>
                <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                </svg>
                {error}
              </div>
            )}
            {!voluntary && (
              <div className="form-field">
                <label className="form-label" htmlFor="account-username">Username (optional to change)</label>
                <input
                  id="account-username"
                  className="form-input"
                  type="text"
                  autoComplete="username"
                  autoFocus
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  disabled={submitting}
                />
              </div>
            )}
            {voluntary ? (
              <div className="form-field">
                <label className="form-label" htmlFor="current-password">Current Password</label>
                <input
                  id="current-password"
                  className="form-input"
                  type="password"
                  autoComplete="current-password"
                  autoFocus
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  disabled={submitting}
                />
              </div>
            ) : null}
            <div className="form-field">
              <label className="form-label" htmlFor="new-password">New Password</label>
              <input
                id="new-password"
                className="form-input"
                type="password"
                autoComplete="new-password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                disabled={submitting}
              />
            </div>
            <div className="form-field">
              <label className="form-label" htmlFor="confirm-new-password">Confirm New Password</label>
              <input
                id="confirm-new-password"
                className="form-input"
                type="password"
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                disabled={submitting}
              />
            </div>
            <button
              type="submit"
              className="btn btn-primary"
              style={{ width: '100%', marginTop: 8 }}
              disabled={submitting}
            >
              {submitting ? 'Updating…' : 'Change Password'}
            </button>
          </form>
          {onLogout && (
            <div style={{ textAlign: 'center', marginTop: 16 }}>
              <button className="btn btn-ghost btn-sm" onClick={onLogout} type="button">
                Log out instead
              </button>
            </div>
          )}
          {voluntary && onCancel ? (
            <div style={{ textAlign: 'center', marginTop: 12 }}>
              <button className="btn btn-ghost btn-sm" onClick={onCancel} type="button">Cancel</button>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  )
}
