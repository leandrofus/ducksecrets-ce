import { useState } from 'react'
import { Package, Check, Copy, Flame, Search, X, KeyRound, ShieldCheck } from 'lucide-react'
import { t } from '../../i18n'
import { api, enc, type Secret, type ShareCreated } from '../../lib/api'
import { encryptShare } from '../../lib/crypto'
import type { SecretBundlePayload } from '../../lib/env'
import { copy } from '../../lib/format'
import { Spinner } from '../../ui/common'
import { Modal, toast } from '../../ui/overlays'
import { Field } from '../../ui/Field'

export function ShareBundleModal({
  projectId,
  envSlug,
  allSecrets,
  initialSelectedIds,
  onClose,
}: {
  projectId: string
  envSlug: string
  allSecrets: Secret[]
  initialSelectedIds?: Set<string>
  onClose: () => void
}) {
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => {
    if (initialSelectedIds && initialSelectedIds.size > 0) {
      return new Set(initialSelectedIds)
    }
    return new Set(allSecrets.map((s) => s.id))
  })
  const [search, setSearch] = useState('')
  const [bundleTitle, setBundleTitle] = useState(`${envSlug.toUpperCase()} Secrets Bundle`)
  const [interpolate, setInterpolate] = useState(true)
  const [ttlSeconds, setTtlSeconds] = useState(86400) // 1 day
  const [maxViews, setMaxViews] = useState(1) // 1 view
  const [passphrase, setPassphrase] = useState('')
  const [generating, setGenerating] = useState(false)
  const [createdUrl, setCreatedUrl] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const filteredSecrets = allSecrets.filter((s) =>
    s.key.toLowerCase().includes(search.toLowerCase())
  )

  const toggleSecret = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const selectAll = () => {
    setSelectedIds(new Set(allSecrets.map((s) => s.id)))
  }

  const deselectAll = () => {
    setSelectedIds(new Set())
  }

  const selectedCount = selectedIds.size

  const handleGenerate = async () => {
    if (selectedCount === 0) {
      toast.err(t('Please select at least one secret to share.'))
      return
    }

    setGenerating(true)
    try {
      const selectedSecrets = allSecrets.filter((s) => selectedIds.has(s.id))
      const bundleItems: { key: string; value: string; comment?: string }[] = []

      for (const s of selectedSecrets) {
        let val = s.value
        if (val === '••••••••') {
          const fetched = await api.get<Secret>(
            `/projects/${enc(projectId)}/environments/${enc(envSlug)}/secrets/${enc(s.id)}`
          )
          val = interpolate ? fetched.value : (fetched.raw_value ?? fetched.value)
        } else if (!interpolate && s.raw_value !== undefined) {
          val = s.raw_value
        }
        bundleItems.push({
          key: s.key,
          value: val,
          comment: s.comment || undefined,
        })
      }

      const bundlePayload: SecretBundlePayload = {
        __ducksecrets_bundle: true,
        version: 1,
        title: bundleTitle.trim() || `${envSlug.toUpperCase()} Secrets Bundle`,
        project: projectId,
        environment: envSlug,
        created_at: new Date().toISOString(),
        secrets: bundleItems,
      }

      const encData = await encryptShare(JSON.stringify(bundlePayload), passphrase)
      const res = await api.post<ShareCreated>('/shares', {
        ciphertext: encData.ciphertext,
        nonce: encData.nonce,
        ttl_seconds: ttlSeconds,
        max_views: maxViews,
        has_passphrase: encData.hasPassphrase,
        passphrase_salt: encData.passphraseSalt || '',
      })

      const fullUrl = `${window.location.origin}/#/share/${enc(res.id)}?k=${encData.keyUrlSafe}`
      setCreatedUrl(fullUrl)
      toast.ok(t('Bundle share link generated!'))
    } catch (err: any) {
      toast.err(err.message || t('Failed to generate bundle share link'))
    } finally {
      setGenerating(false)
    }
  }

  const handleCopyLink = () => {
    if (createdUrl) {
      copy(createdUrl).then((ok) => {
        if (ok) {
          setCopied(true)
          toast.ok(t('Share link copied to clipboard!'))
          setTimeout(() => setCopied(false), 2000)
        }
      })
    }
  }

  return (
    <Modal
      title={
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
          <Package size={16} />
          {t('Share Secret Bundle: {0}', envSlug)}
        </span>
      }
      wide="xl"
      allowFullscreen
      onClose={onClose}
      footer={
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
          <span className="muted small">
            {selectedCount} {t('of')} {allSecrets.length} {t('secrets selected')}
          </span>
          <div style={{ display: 'flex', gap: 8 }}>
            <button type="button" className="btn btn-ghost" onClick={onClose}>{t('Close')}</button>
            {createdUrl ? (
              <button type="button" className="btn btn-primary" onClick={handleCopyLink}>
                {copied ? <Check size={14} /> : <Copy size={14} />}
                {copied ? t('Copied!') : t('Copy Link')}
              </button>
            ) : (
              <button
                type="button"
                className="btn btn-primary"
                onClick={handleGenerate}
                disabled={generating || selectedCount === 0}
              >
                {generating ? <Spinner /> : <Flame size={14} />}
                {generating ? t('Encrypting Bundle...') : t('Generate Share Link')}
              </button>
            )}
          </div>
        </div>
      }
    >
      <div className="modal-two-col">
        {/* Left Column: Secret Picker & Security Configuration */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <Field label={t('Bundle Title')} help={t('Descriptive label shown to recipient')}>
            <input
              value={bundleTitle}
              onChange={(e) => setBundleTitle(e.target.value)}
              placeholder="e.g. Production RDS & Stripe Keys"
            />
          </Field>

          {/* Secrets Checklist */}
          <div className="surface-box">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
              <span style={{ fontSize: 12, fontWeight: 600 }}>{t('Select Secrets to Include')}</span>
              <div style={{ display: 'flex', gap: 6 }}>
                <button type="button" className="btn btn-ghost btn-xs" onClick={selectAll}>
                  {t('Select All')}
                </button>
                <button type="button" className="btn btn-ghost btn-xs" onClick={deselectAll}>
                  {t('Deselect All')}
                </button>
              </div>
            </div>

            <div className="search" style={{ marginBottom: 8, width: '100%' }}>
              <Search size={13} />
              <input
                placeholder={t('Filter secrets…')}
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                style={{ fontSize: 12 }}
              />
              {search && <button className="icon-btn" onClick={() => setSearch('')}><X size={12} /></button>}
            </div>

            <div style={{ maxHeight: 180, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 4 }}>
              {filteredSecrets.length === 0 ? (
                <span className="muted small center" style={{ padding: '12px 0' }}>{t('No matching secrets')}</span>
              ) : (
                filteredSecrets.map((s) => {
                  const isChecked = selectedIds.has(s.id)
                  return (
                    <label
                      key={s.id}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 8,
                        padding: '5px 8px',
                        borderRadius: 6,
                        background: isChecked ? 'var(--surface)' : 'transparent',
                        cursor: 'pointer',
                        userSelect: 'none',
                        border: '1px solid',
                        borderColor: isChecked ? 'var(--border)' : 'transparent',
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => toggleSecret(s.id)}
                      />
                      <strong className="mono" style={{ fontSize: 12, flex: 1 }}>{s.key}</strong>
                      {s.raw_value && <span className="tag tag-accent mono" style={{ fontSize: 9, padding: '1px 4px' }}>REF</span>}
                      {s.comment && <span className="muted small ellipsis" style={{ fontSize: 11, maxWidth: 120 }}>{s.comment}</span>}
                    </label>
                  )
                })
              )}
            </div>
          </div>

          {/* Interpolation Option */}
          <label className="surface-box" style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, cursor: 'pointer', padding: '6px 8px' }}>
            <input
              type="checkbox"
              checked={interpolate}
              onChange={(e) => setInterpolate(e.target.checked)}
            />
            <div>
              <strong>{t('Interpolate dynamic and referenced secrets')}</strong>
              <span className="muted small" style={{ display: 'block' }}>
                {t('Resolves ${VAR} placeholders into decrypted values before encrypting.')}
              </span>
            </div>
          </label>

          {/* Ephemeral Settings Grid */}
          <div className="grid-2">
            <Field label={t('Duration / TTL')} help={t('Link auto-expires after')}>
              <select value={ttlSeconds} onChange={(e) => setTtlSeconds(Number(e.target.value))}>
                <option value={3600}>{t('1 hour')}</option>
                <option value={28800}>{t('8 hours')}</option>
                <option value={86400}>{t('24 hours (1 day)')}</option>
                <option value={604800}>{t('7 days')}</option>
                <option value={2592000}>{t('30 days')}</option>
              </select>
            </Field>

            <Field label={t('Max Views')} help={t('Burn on read limit')}>
              <select value={maxViews} onChange={(e) => setMaxViews(Number(e.target.value))}>
                <option value={1}>{t('1 view (Burn on read)')}</option>
                <option value={2}>{t('2 views')}</option>
                <option value={5}>{t('5 views')}</option>
                <option value={10}>{t('10 views')}</option>
              </select>
            </Field>
          </div>

          <Field label={t('Optional Passphrase')} help={t('Extra layer of decryption security')}>
            <div style={{ position: 'relative' }}>
              <input
                type="password"
                autoComplete="new-password"
                placeholder={t('Extra passphrase to unlock (optional)')}
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                style={{ paddingLeft: 30 }}
              />
              <KeyRound size={14} style={{ position: 'absolute', left: 10, top: 10, color: 'var(--muted)' }} />
            </div>
          </Field>
        </div>

        {/* Right Column: Live Summary, Preview & Generated Link */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {createdUrl ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div className="alert alert-ok" style={{ fontWeight: 500, alignItems: 'center', marginBottom: 0 }}>
                <ShieldCheck size={22} />
                <span>{t('Secret Bundle encrypted with AES-256-GCM and ready!')}</span>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 600, marginBottom: 6 }}>
                  {t('One-Time Share Link')}
                </label>
                <div style={{ display: 'flex', gap: 6 }}>
                  <input
                    type="text"
                    readOnly
                    value={createdUrl}
                    className="mono"
                    style={{ fontSize: 11, padding: '8px 10px', background: 'var(--surface-2)', flex: 1 }}
                  />
                  <button type="button" className="btn btn-primary" onClick={handleCopyLink}>
                    {copied ? <Check size={14} /> : <Copy size={14} />}
                    <span>{copied ? t('Copied!') : t('Copy')}</span>
                  </button>
                </div>
              </div>

              <div className="surface-box" style={{ fontSize: 11, lineHeight: 1.5 }}>
                <strong style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--accent)', marginBottom: 4 }}>
                  <Flame size={14} />
                  {maxViews === 1 ? t('Burn on Read Enabled') : t('Limited Views ({0})', maxViews)}
                </strong>
                <p className="muted small" style={{ margin: 0 }}>
                  {t('The link contains the decryption key in the hash fragment (#k=). Once opened and burned, the bundle payload cannot be recovered.')}
                </p>
              </div>

              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => setCreatedUrl(null)}
                style={{ marginTop: 8 }}
              >
                {t('Configure Another Bundle')}
              </button>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {/* Summary Card */}
              <div className="surface-box">
                <span style={{ fontSize: 12, fontWeight: 600, display: 'block', marginBottom: 8 }}>
                  {t('Bundle Summary')}
                </span>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span className="muted">{t('Selected Secrets')}:</span>
                    <strong className="mono">{selectedCount} {t('secrets')}</strong>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span className="muted">{t('Burn Policy')}:</span>
                    <strong style={{ color: 'var(--accent)' }}>
                      {maxViews === 1 ? t('Burn immediately on read') : t('{0} views allowed', maxViews)}
                    </strong>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span className="muted">{t('Passphrase')}:</span>
                    <strong>{passphrase ? t('Enabled') : t('None')}</strong>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span className="muted">{t('Interpolation')}:</span>
                    <strong>{interpolate ? t('Resolved (Ready to use)') : t('Raw templates')}</strong>
                  </div>
                </div>
              </div>

              {/* Selected Keys Preview List */}
              <div className="surface-box">
                <span style={{ fontSize: 12, fontWeight: 600, display: 'block', marginBottom: 6 }}>
                  {t('Bundle Payload Preview ({0})', selectedCount)}
                </span>
                <div style={{ maxHeight: 200, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {allSecrets.filter((s) => selectedIds.has(s.id)).map((s) => (
                    <div
                      key={s.id}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '4px 8px',
                        background: 'var(--surface)',
                        borderRadius: 4,
                        fontSize: 11,
                        border: '1px solid var(--border)',
                      }}
                    >
                      <span className="mono" style={{ fontWeight: 600 }}>{s.key}</span>
                      <span className="mono muted">••••••••••••</span>
                    </div>
                  ))}
                  {selectedCount === 0 && (
                    <span className="muted small center" style={{ padding: '12px 0' }}>
                      {t('No secrets selected')}
                    </span>
                  )}
                </div>
              </div>

              {/* Zero Knowledge Trust Badge */}
              <div className="surface-box" style={{ fontSize: 11, display: 'flex', alignItems: 'center', gap: 8 }}>
                <ShieldCheck size={18} className="tone-ok" style={{ flexShrink: 0 }} />
                <span className="muted small">
                  {t('Encrypted in your browser before upload. The server never sees the decryption key.')}
                </span>
              </div>
            </div>
          )}
        </div>
      </div>
    </Modal>
  )
}
