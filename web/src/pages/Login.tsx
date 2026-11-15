import { t } from '../i18n'
import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { KeyRound, LogIn, ShieldCheck } from 'lucide-react'
import { api } from '../lib/api'
import type { SetupStatus } from '../lib/api'
import { Spinner } from '../ui/common'

export function Login({ onDone }: { onDone: () => void }) {
  const [setup, setSetup] = useState<SetupStatus | null>(null)
  const [checking, setChecking] = useState(true)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    let active = true
    api.get<SetupStatus>('/auth/setup')
      .then((res) => {
        if (!active) return
        setSetup(res)
        if (res.needs_setup) {
          setUsername(res.default_username || 'admin')
        }
      })
      .catch(() => {
        if (active) setSetup({ needs_setup: false, default_username: 'admin', min_password_length: 10 })
      })
      .finally(() => {
        if (active) setChecking(false)
      })
    return () => { active = false }
  }, [])

  const submitLogin = async (e: FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      await api.post('/auth/login', { username, password })
      onDone()
    } catch (e: any) {
      setErr(e.message)
      setPassword('')
    } finally {
      setBusy(false)
    }
  }

  const submitSetup = async (e: FormEvent) => {
    e.preventDefault()
    const minLen = setup?.min_password_length ?? 10
    if (password.length < minLen) {
      setErr(t('Password must have at least {0} characters.', minLen))
      return
    }
    if (password !== confirm) {
      setErr(t('Passwords do not match.'))
      return
    }
    setBusy(true)
    setErr('')
    try {
      await api.post('/auth/setup', { username: username.trim() || setup?.default_username || 'admin', password })
      onDone()
    } catch (e: any) {
      setErr(e.message)
    } finally {
      setBusy(false)
    }
  }

  if (checking) {
    return (
      <div className="login">
        <div className="login-card" style={{ alignItems: 'center', padding: 32 }}>
          <Spinner />
        </div>
      </div>
    )
  }

  if (setup?.needs_setup) {
    return (
      <div className="login">
        <form className="login-card" onSubmit={submitSetup}>
          <img className="brand-logo" style={{ width: 56, height: 56, alignSelf: 'center' }} src="/icon.svg" alt="" />
          <h2 style={{ textAlign: 'center', margin: 0 }}>{t('Initial Administrator Setup')}</h2>
          <p className="muted" style={{ textAlign: 'center' }}>
            {t('No administrator account exists yet. Set the admin username and password for this DuckSecrets instance.')}
          </p>
          <input
            autoFocus
            autoComplete="username"
            placeholder={t('Administrator username')}
            value={username}
            onChange={(e) => setUsername(e.currentTarget.value)}
          />
          <input
            type="password"
            autoComplete="new-password"
            placeholder={t('New password (min {0} chars)', setup.min_password_length)}
            value={password}
            onChange={(e) => setPassword(e.currentTarget.value)}
          />
          <input
            type="password"
            autoComplete="new-password"
            placeholder={t('Confirm password')}
            value={confirm}
            onChange={(e) => setConfirm(e.currentTarget.value)}
          />
          {err && <div className="alert alert-bad">{err}</div>}
          <button className="btn btn-primary" disabled={busy || !username.trim() || !password || !confirm}>
            {busy ? <Spinner /> : <KeyRound size={15} />} {t('Create Admin & Sign In')}
          </button>
          <div className="muted small" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6 }}>
            <ShieldCheck size={14} />
            <span>{t('This setup form locks automatically once the first admin is created.')}</span>
          </div>
        </form>
      </div>
    )
  }

  return (
    <div className="login">
      <form className="login-card" onSubmit={submitLogin}>
        <img className="brand-logo" style={{ width: 56, height: 56, alignSelf: 'center' }} src="/icon.svg" alt="" />
        <h2 style={{ textAlign: 'center', margin: 0 }}>Ducksecrets</h2>
        <p className="muted" style={{ textAlign: 'center' }}>{t('Sign in to continue.')}</p>
        <input autoFocus autoComplete="username" placeholder={t('user')} value={username} onChange={(e) => setUsername(e.currentTarget.value)} />
        <input type="password" autoComplete="current-password" placeholder={t('password')} value={password} onChange={(e) => setPassword(e.currentTarget.value)} />
        {err && <div className="alert alert-bad">{err}</div>}
        <button className="btn btn-primary" disabled={busy || !username || !password}>
          {busy ? <Spinner /> : <LogIn size={15} />} {t('Sign in')}
        </button>
      </form>
    </div>
  )
}
