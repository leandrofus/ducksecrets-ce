import { t } from '../i18n'
import { useState } from 'react'
import type { FormEvent } from 'react'
import { KeyRound, CheckCircle2, AlertCircle, Lock, RefreshCw, Trash2, Server, ShieldCheck, ArrowRight } from 'lucide-react'
import { api } from '../lib/api'
import type { LicenseStatus } from '../lib/api'
import { invalidate, useResource } from '../lib/store'
import { Field } from '../ui/Field'
import { Spinner, Tag } from '../ui/common'
import { confirm, toast } from '../ui/overlays'

export function LicenseOnboarding({ onDone }: { onDone: (skipped: boolean) => void }) {
  const [token, setToken] = useState('')
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')

  const activate = async (e: FormEvent) => {
    e.preventDefault()
    if (!token.trim() || busy) return
    setBusy(true)
    setErr('')
    try {
      await api.put<LicenseStatus>('/system/license', { token: token.trim() })
      invalidate('/system/license')
      onDone(false)
    } catch (error: any) {
      setErr(error?.message || String(error))
    } finally {
      setBusy(false)
    }
  }

  const skipToCE = async () => {
    if (busy) return
    setBusy(true)
    setErr('')
    try {
      await api.post<LicenseStatus>('/system/license/skip', {})
      invalidate('/system/license')
      onDone(true)
    } catch (error: any) {
      setErr(error?.message || String(error))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login">
      <form className="login-card" style={{ width: 520, maxWidth: '100%' }} onSubmit={activate}>
        <img className="brand-logo" style={{ width: 52, height: 52, alignSelf: 'center' }} src="/icon.svg" alt="" />
        <h2 style={{ textAlign: 'center', margin: 0 }}>{t('Choose Your DuckSecrets Edition')}</h2>
        <p className="muted" style={{ textAlign: 'center' }}>
          {t('Community Edition is free under Apache-2.0. Enter a license key for Pro or Business, or continue with Community Edition.')}
        </p>

        <div className="surface-box" style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
            <strong>DuckSecrets Community Edition</strong>
            <Tag tone="ok">{t('Free · Apache-2.0')}</Tag>
          </div>
          <span className="muted small">
            {t('Secrets, dynamic credentials, rotation, audit log, sharing, and up to 2 network sites.')}
          </span>
        </div>

        <Field
          label={t('Signed License Token (dkl1...)')}
          help={t('Optional. Checked locally offline.')}
        >
          <textarea
            rows={3}
            className="mono"
            placeholder="dkl1...."
            value={token}
            onChange={(e) => setToken(e.target.value)}
            disabled={busy}
          />
        </Field>

        {err && <div className="alert alert-bad">{err}</div>}

        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <button type="submit" className="btn btn-primary" disabled={busy || !token.trim()}>
            <KeyRound size={15} /> {busy && token.trim() ? t('Verifying…') : t('Activate License')}
          </button>
          <button type="button" className="btn btn-ghost" disabled={busy} onClick={skipToCE}>
            <ArrowRight size={15} /> {t('Skip — Continue with Community Edition')}
          </button>
        </div>

        <div className="muted small" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, textAlign: 'center' }}>
          <ShieldCheck size={14} style={{ flexShrink: 0 }} />
          <span>{t('You can upgrade to Pro or Business anytime later from Administration → License.')}</span>
        </div>
      </form>
    </div>
  )
}

function editionLabel(ed?: string) {
  if (ed === 'business') return 'Business'
  if (ed === 'pro') return 'Pro'
  return 'Community (Apache-2.0)'
}

function editionTone(ed?: string): 'ok' | 'accent' | 'bad' | 'muted' {
  if (ed === 'business') return 'accent'
  if (ed === 'pro') return 'ok'
  return 'muted'
}

export function License() {
  const { data: status, error, loading } = useResource<LicenseStatus>('/system/license')
  const [token, setToken] = useState('')
  const [busy, setBusy] = useState(false)

  const activate = async (e: FormEvent) => {
    e.preventDefault()
    if (!token.trim() || busy) return
    setBusy(true)
    try {
      await api.put<LicenseStatus>('/system/license', { token: token.trim() })
      setToken('')
      invalidate('/system/license')
      toast.ok(t('License activated'))
    } catch (err: any) {
      toast.err(err)
    } finally {
      setBusy(false)
    }
  }

  const remove = async () => {
    if (busy) return
    const ok = await confirm({
      title: t('Remove commercial license?'),
      body: t('Reverts to Community Edition (up to 2 network sites). Existing sites remain configured.'),
      danger: true,
      confirm: t('Remove License'),
    })
    if (!ok) return
    setBusy(true)
    try {
      await api.del<LicenseStatus>('/system/license')
      invalidate('/system/license')
      toast.ok(t('Reverted to Community Edition'))
    } catch (err: any) {
      toast.err(err)
    } finally {
      setBusy(false)
    }
  }

  const maxSitesText = status ? (status.max_sites < 0 ? t('Unlimited') : String(status.max_sites)) : '—'

  return (
    <div className="page narrow">
      <div className="page-head">
        <div className="page-title">
          <KeyRound size={22} />
          <h1>{t('Edition & License')}</h1>
          {loading && <Spinner />}
        </div>
      </div>

      <div className="page-body">
        {error && <div className="alert alert-bad">{error.message}</div>}

        {status?.expired && (
          <div className="alert alert-bad" style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
            <AlertCircle size={18} />
            <span>
              {t('Commercial license ({0}) has expired; running with Community Edition quotas.', status.licensed_edition || 'pro')}
            </span>
          </div>
        )}

        <div className="surface-box" style={{ padding: 20, marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
            <div>
              <h3 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <span>DuckSecrets {editionLabel(status?.edition)}</span>
                <Tag tone={editionTone(status?.edition)}>{status?.edition?.toUpperCase() || 'COMMUNITY'}</Tag>
                {status?.valid && (
                  <Tag tone="ok">
                    <CheckCircle2 size={12} style={{ marginRight: 4 }} /> {t('Verified Offline')}
                  </Tag>
                )}
              </h3>
              <p className="muted small" style={{ margin: '8px 0 0' }}>
                {status?.valid
                  ? t('Licensed to {0}{1}', status.customer || '—', status.org ? ` (${status.org})` : '')
                  : t('Community Edition (Apache-2.0). Paste a commercial license key below to unlock extra quotas and modules.')}
              </p>
              {status && (
                <div className="muted small" style={{ marginTop: 10, display: 'flex', gap: 18, flexWrap: 'wrap', alignItems: 'center' }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                    <Server size={14} /> {t('Network Sites')}: <strong>{status.used_sites} / {maxSitesText}</strong>
                  </span>
                  {status.expires_at && (
                    <span>
                      {t('Expires')}: <strong>{new Date(status.expires_at).toLocaleDateString()}</strong>
                    </span>
                  )}
                  <span>
                    {t('Source')}: <code>{status.source}</code>
                  </span>
                </div>
              )}
            </div>
            <div style={{ display: 'flex', gap: 6 }}>
              {status?.source === 'database' && (
                <button className="btn btn-sm btn-ghost" onClick={remove} disabled={busy} title={t('Remove License')}>
                  <Trash2 size={14} />
                </button>
              )}
              <button className="icon-btn" title={t('Refresh')} onClick={() => invalidate('/system/license')}>
                <RefreshCw size={15} />
              </button>
            </div>
          </div>
        </div>

        <form onSubmit={activate} className="surface-card" style={{ marginBottom: 24 }}>
          <h3 style={{ marginTop: 0 }}>{t('Activate Offline License Key')}</h3>
          {status?.source === 'env' ? (
            <div className="alert alert-ok" style={{ marginBottom: 0 }}>
              {t('This instance is configured via -license-key / $DUCKSECRETS_LICENSE_KEY. Update the environment variable and restart the daemon to change it.')}
            </div>
          ) : (
            <>
              <Field
                label={t('Signed License Token (dkl1...)')}
                help={t('Checked locally offline. No internet connection required.')}
              >
                <textarea
                  rows={3}
                  className="mono"
                  placeholder="dkl1...."
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  disabled={busy}
                />
              </Field>
              <div style={{ marginTop: 12, display: 'flex', justifyContent: 'flex-end' }}>
                <button type="submit" className="btn btn-primary" disabled={busy || !token.trim()}>
                  <KeyRound size={15} /> {busy ? t('Verifying…') : t('Activate License')}
                </button>
              </div>
            </>
          )}
        </form>

        <div className="surface-card">
          <h3 style={{ marginTop: 0, marginBottom: 12 }}>{t('Open-Core Entitlements')}</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {(status?.catalog || []).map((f) => (
              <div
                key={f.id}
                className="surface-box"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: 12,
                  padding: '10px 12px',
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <strong>{f.name}</strong>
                    <Tag tone={editionTone(f.min_edition)}>{f.min_edition.toUpperCase()}</Tag>
                  </div>
                  <div className="muted small" style={{ marginTop: 3 }}>{f.description}</div>
                </div>
                {f.enabled ? (
                  <Tag tone="ok">
                    <CheckCircle2 size={12} style={{ marginRight: 4 }} /> {t('Enabled')}
                  </Tag>
                ) : (
                  <Tag tone="muted">
                    <Lock size={12} style={{ marginRight: 4 }} /> {t('Locked')}
                  </Tag>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
