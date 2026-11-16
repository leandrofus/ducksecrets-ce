import { t } from '../i18n'
import { useState } from 'react'
import type { FormEvent } from 'react'
import { DownloadCloud, RefreshCw, Shield, CheckCircle2 } from 'lucide-react'
import { api } from '../lib/api'
import type { ApplyUpdateResponse, TLSStatus, UpdateStatus } from '../lib/api'
import { invalidate, useResource } from '../lib/store'
import { Field } from '../ui/Field'
import { Spinner, Tag } from '../ui/common'
import { confirm, toast } from '../ui/overlays'

export function SecurityTLS() {
  const { data: tlsInfo, error, loading } = useResource<TLSStatus>('/system/tls')
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
      toast.ok(
        res.restart_required
          ? t('Custom certificate saved; restart daemon with TLS enabled to activate HTTPS.')
          : t('Custom TLS certificate activated cleanly (hot-reloaded).'),
      )
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
      toast.ok(
        res.restart_required
          ? t('Self-signed certificate generated; restart daemon with TLS enabled to serve HTTPS.')
          : t('Self-signed TLS certificate regenerated and active.'),
      )
    } catch (err: any) {
      toast.err(err)
    } finally {
      setTlsBusy(false)
    }
  }

  return (
    <div className="page narrow">
      <div className="page-head">
        <div className="page-title">
          <Shield size={22} />
          <h1>{t('TLS Certificate & Reverse Proxy')}</h1>
          {loading && <Spinner />}
        </div>
        <div className="page-actions">
          <button className="icon-btn" title={t('Refresh')} onClick={() => invalidate('/system/tls')}>
            <RefreshCw size={15} />
          </button>
        </div>
      </div>

      <div className="page-body">
        {error && <div className="alert alert-bad">{error.message}</div>}

        <div className="surface-card" style={{ marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
            <h3 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
              <Shield size={18} />
              <span>{t('Transport Security')}</span>
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
            <div className="surface-box small" style={{ marginBottom: 16 }}>
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
            <div className="row" style={{ gap: 12 }}>
              <Field label={t('Custom Certificate PEM (cert_pem)')}>
                <textarea
                  rows={5}
                  className="mono"
                  placeholder="-----BEGIN CERTIFICATE-----"
                  value={certPEM}
                  onChange={(e) => setCertPEM(e.target.value)}
                  disabled={tlsBusy}
                />
              </Field>
              <Field label={t('Custom Private Key PEM (key_pem)')}>
                <textarea
                  rows={5}
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
                {t('Custom certificates reload live when HTTPS is enabled. Behind a reverse proxy, set DUCKSECRETS_TLS_MODE=off and DUCKSECRETS_TRUSTED_PROXIES.')}
              </span>
              <button type="submit" className="btn btn-primary btn-sm" disabled={tlsBusy || !certPEM.trim() || !keyPEM.trim()}>
                <Shield size={14} /> {tlsBusy ? t('Applying…') : t('Save Custom Certificate')}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  )
}

export function SystemUpdates() {
  const { data: updateInfo, error, loading: checkingUpdate } = useResource<UpdateStatus>('/system/update')
  const [updating, setUpdating] = useState(false)

  const applySelfUpdate = async () => {
    if (updating) return
    const ok = await confirm({
      title: t('Update DuckSecrets to {0}?', updateInfo?.latest_version || 'latest'),
      body: t(
        'Downloads the latest release from {0}, verifies SHA256SUMS, and replaces the binary on disk. Restart the daemon afterward.',
        updateInfo?.repo || 'leandrofus/ducksecrets-ce',
      ),
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

  return (
    <div className="page narrow">
      <div className="page-head">
        <div className="page-title">
          <DownloadCloud size={22} />
          <h1>{t('System Updates')}</h1>
          {checkingUpdate && <Spinner />}
        </div>
      </div>

      <div className="page-body">
        {error && <div className="alert alert-bad">{error.message}</div>}

        <div className="surface-card" style={{ marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
            <div>
              <h3 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
                <DownloadCloud size={18} />
                <span>{t('System Auto-Update')}</span>
                {updateInfo?.update_available ? (
                  <Tag tone="accent">{t('Update available: {0}', updateInfo.latest_version)}</Tag>
                ) : updateInfo && !updateInfo.error ? (
                  <Tag tone="ok">
                    <CheckCircle2 size={12} style={{ marginRight: 4 }} /> {t('Up to date')}
                  </Tag>
                ) : null}
              </h3>
              <p className="muted small" style={{ margin: '8px 0 0' }}>
                {t('Public repository')}: <code>{updateInfo?.repo || 'leandrofus/ducksecrets-ce'}</code> ·{' '}
                {t('Current')}: <code>{updateInfo?.current_version || '—'}</code> ·{' '}
                {t('Latest')}: <code>{updateInfo?.latest_version || '—'}</code>
              </p>
              {updateInfo?.error && (
                <p className="muted small" style={{ margin: '8px 0 0', color: 'var(--bad)' }}>
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
                <button className="btn btn-sm btn-primary" onClick={applySelfUpdate} disabled={updating}>
                  <DownloadCloud size={14} /> {updating ? t('Updating…') : t('Install Update')}
                </button>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
