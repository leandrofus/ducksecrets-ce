import { t } from '../i18n'
import { useState } from 'react'
import type { FormEvent } from 'react'
import { KeyRound, CheckCircle2, AlertCircle, Lock, RefreshCw, Trash2, Server, DownloadCloud, Shield } from 'lucide-react'
import { api } from '../lib/api'
import type { LicenseStatus, UpdateStatus, ApplyUpdateResponse, TLSStatus } from '../lib/api'
import { invalidate, useResource } from '../lib/store'
import { Field } from '../ui/Field'
import { Spinner, Tag } from '../ui/common'
import { confirm, toast } from '../ui/overlays'

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
  const { data: updateInfo, loading: checkingUpdate } = useResource<UpdateStatus>('/system/update')
  const { data: tlsInfo, loading: loadingTLS } = useResource<TLSStatus>('/system/tls')
  const [token, setToken] = useState('')
  const [busy, setBusy] = useState(false)
  const [updating, setUpdating] = useState(false)
  const [certPEM, setCertPEM] = useState('')
  const [keyPEM, setKeyPEM] = useState('')
  const [tlsBusy, setTlsBusy] = useState(false)
  const [tlsHosts, setTlsHosts] = useState('')

  const uploadTLS = async (e: FormEvent) => {
    e.preventDefault()
    if (!certPEM.trim() || !keyPEM.trim() || tlsBusy) return
    setTlsBusy(true)
    try {
      const res = await api.put<TLSStatus>('/system/tls', { cert_pem: certPEM.trim(), key_pem: keyPEM.trim() })
      setCertPEM('')
      setKeyPEM('')
      invalidate('/system/tls')
      toast.ok(res.restart_required ? t('Custom certificate saved; restart daemon with TLS enabled to activate HTTPS.') : t('Custom TLS certificate activated cleanly (hot-reloaded).'))
    } catch (err: any) {
      toast.err(err)
    } finally {
      setTlsBusy(false)
    }
  }

  const regenerateSelfSigned = async () => {
    if (tlsBusy) return
    setTlsBusy(true)
    try {
      const hosts = tlsHosts.split(',').map((s) => s.trim()).filter(Boolean)
      const res = await api.post<TLSStatus>('/system/tls/self-signed', { hosts })
      invalidate('/system/tls')
      toast.ok(res.restart_required ? t('Self-signed certificate generated; restart daemon with TLS enabled to serve HTTPS.') : t('Self-signed TLS certificate regenerated and active.'))
    } catch (err: any) {
      toast.err(err)
    } finally {
      setTlsBusy(false)
    }
  }

  const applySelfUpdate = async () => {
    if (updating) return
    const ok = await confirm({
      title: t('Update DuckSecrets to {0}?', updateInfo?.latest_version || 'latest'),
      body: t('Downloads the verified release binary from {0}, checks SHA256SUMS, and atomically replaces the executable on disk. A daemon restart is required afterward.', updateInfo?.repo || 'leandrofus/ducksecrets-ce'),
      confirm: t('Install Update'),
    })
    if (!ok) return
    setUpdating(true)
    try {
      const res = await api.post<ApplyUpdateResponse>('/system/update', {})
      invalidate('/system/update')
      toast.ok(res.message)
    } catch (err: any) {
      toast.err(err)
    } finally {
      setUpdating(false)
    }
  }

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
      body: t('The instance will revert to Community Edition (unlimited core secrets, dynamic engines, rotation, and up to 2 network sites).'),
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
    <div className="page">
      <div className="page-head">
        <div className="page-title">
          <KeyRound size={22} />
          <h1>{t('Edition & License')}</h1>
          {loading && <Spinner />}
        </div>
      </div>

      <div className="page-body" style={{ maxWidth: 820 }}>
        {error && <div className="alert alert-bad">{error.message}</div>}

        {status?.expired && (
          <div className="alert alert-bad" style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
            <AlertCircle size={18} />
            <span>
              {t('Commercial license ({0}) has expired; running with Community Edition quotas.', status.licensed_edition || 'pro')}
            </span>
          </div>
        )}

        <div style={{ border: '1px solid var(--border)', borderRadius: 8, padding: 20, marginBottom: 20, background: 'var(--bg-subtle)' }}>
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
                  : t('Open-source core licensed under Apache-2.0. Offline Ed25519 licenses unlock commercial quotas and enterprise modules without telemetry or external network calls.')}
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

        <form onSubmit={activate} style={{ border: '1px solid var(--border)', borderRadius: 8, padding: 20, marginBottom: 24, background: 'var(--bg)' }}>
          <h3 style={{ marginTop: 0 }}>{t('Activate Offline License Key')}</h3>
          {status?.source === 'env' ? (
            <div className="alert alert-ok" style={{ marginBottom: 0 }}>
              {t('This instance is configured via -license-key / $DUCKSECRETS_LICENSE_KEY. Update the environment variable and restart the daemon to change it.')}
            </div>
          ) : (
            <>
              <Field
                label={t('Signed License Token (dkl1...)')}
                help={t('Verified locally against the embedded Ed25519 public key. No internet connection required.')}
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

        <div style={{ border: '1px solid var(--border)', borderRadius: 8, padding: 20, marginBottom: 20, background: 'var(--bg)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
            <div>
              <h3 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
                <DownloadCloud size={18} />
                <span>{t('System Auto-Update')}</span>
                {updateInfo?.update_available ? (
                  <Tag tone="accent">{t('Update available: {0}', updateInfo.latest_version)}</Tag>
                ) : updateInfo && !updateInfo.error ? (
                  <Tag tone="ok">{t('Up to date')}</Tag>
                ) : null}
              </h3>
              <p className="muted small" style={{ margin: '6px 0 0' }}>
                {t('Public repository')}: <code>{updateInfo?.repo || 'leandrofus/ducksecrets-ce'}</code> ·{' '}
                {t('Current')}: <code>{updateInfo?.current_version || '—'}</code> ·{' '}
                {t('Latest')}: <code>{updateInfo?.latest_version || '—'}</code>
              </p>
              {updateInfo?.error && (
                <p className="muted small" style={{ margin: '6px 0 0', color: 'var(--bad)' }}>
                  {updateInfo.error}
                </p>
              )}
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <button
                className="btn btn-sm btn-ghost"
                onClick={() => invalidate('/system/update')}
                disabled={checkingUpdate || updating}
              >
                <RefreshCw size={14} /> {t('Check Updates')}
              </button>
              {updateInfo?.update_available && (
                <button
                  className="btn btn-sm btn-primary"
                  onClick={applySelfUpdate}
                  disabled={updating}
                >
                  <DownloadCloud size={14} /> {updating ? t('Updating…') : t('Install Update')}
                </button>
              )}
            </div>
          </div>
        </div>

        <div style={{ border: '1px solid var(--border)', borderRadius: 8, padding: 20, marginBottom: 20, background: 'var(--bg)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
            <h3 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
              <Shield size={18} />
              <span>{t('TLS Certificate & Reverse Proxy')}</span>
              {loadingTLS && <Spinner />}
              {tlsInfo?.tls_active ? (
                <Tag tone={tlsInfo.mode === 'custom' ? 'ok' : 'accent'}>
                  HTTPS ({tlsInfo.mode})
                </Tag>
              ) : (
                <Tag tone="muted">
                  {t('HTTP (Reverse Proxy / Local Mode)')}
                </Tag>
              )}
            </h3>
            <span className="muted small">
              {t('Trusted reverse proxies')}: <strong>{tlsInfo?.trusted_proxies_count ?? 0}</strong>
            </span>
          </div>

          {tlsInfo?.has_cert && (
            <div style={{ padding: 12, borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-subtle)', marginBottom: 16 }} className="small">
              <div><strong>{t('Subject')}:</strong> <code>{tlsInfo.subject || '—'}</code> ({tlsInfo.self_signed ? t('Self-Signed') : t('Custom CA / Signed')})</div>
              <div style={{ marginTop: 4 }}><strong>SANs:</strong> <code>{[...(tlsInfo.san_dns || []), ...(tlsInfo.san_ips || [])].join(', ') || '—'}</code></div>
              <div style={{ marginTop: 4 }}>
                <strong>{t('Expires')}:</strong> {tlsInfo.not_after ? new Date(tlsInfo.not_after).toLocaleString() : '—'} ·{' '}
                <strong>SHA-256:</strong> <code>{tlsInfo.fingerprint_sha256 ? tlsInfo.fingerprint_sha256.slice(0, 24) + '…' : '—'}</code>
              </div>
            </div>
          )}

          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', marginBottom: 16 }}>
            <input
              placeholder={t('Extra SAN hosts/IPs (e.g. vault.internal,10.0.0.5)')}
              value={tlsHosts}
              onChange={(e) => setTlsHosts(e.target.value)}
              style={{ flex: 1, minWidth: 220 }}
              disabled={tlsBusy}
            />
            <button type="button" className="btn btn-sm btn-ghost" onClick={regenerateSelfSigned} disabled={tlsBusy}>
              <RefreshCw size={14} /> {t('Generate Self-Signed Certificate')}
            </button>
          </div>

          <form onSubmit={uploadTLS}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              <Field label={t('Custom Certificate PEM (cert_pem)')}>
                <textarea
                  rows={4}
                  className="mono"
                  placeholder="-----BEGIN CERTIFICATE-----"
                  value={certPEM}
                  onChange={(e) => setCertPEM(e.target.value)}
                  disabled={tlsBusy}
                />
              </Field>
              <Field label={t('Custom Private Key PEM (key_pem)')}>
                <textarea
                  rows={4}
                  className="mono"
                  placeholder="-----BEGIN PRIVATE KEY-----"
                  value={keyPEM}
                  onChange={(e) => setKeyPEM(e.target.value)}
                  disabled={tlsBusy}
                />
              </Field>
            </div>
            <div style={{ marginTop: 10, display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
              <span className="muted small">
                {t('Custom certificates hot-reload live when HTTPS is active. Behind Nginx/Caddy/Traefik, set DUCKSECRETS_TLS_MODE=off and DUCKSECRETS_TRUSTED_PROXIES.')}
              </span>
              <button type="submit" className="btn btn-primary btn-sm" disabled={tlsBusy || !certPEM.trim() || !keyPEM.trim()}>
                <Shield size={14} /> {tlsBusy ? t('Applying…') : t('Save Custom Certificate')}
              </button>
            </div>
          </form>
        </div>

        <div style={{ border: '1px solid var(--border)', borderRadius: 8, padding: 20, background: 'var(--bg)' }}>
          <h3 style={{ marginTop: 0, marginBottom: 12 }}>{t('Open-Core Entitlements')}</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {(status?.catalog || []).map((f) => (
              <div
                key={f.id}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: 12,
                  padding: '10px 12px',
                  borderRadius: 6,
                  border: '1px solid var(--border)',
                  background: 'var(--bg-subtle)',
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
