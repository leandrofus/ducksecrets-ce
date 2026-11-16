import { useState } from 'react'
import { Flame, KeyRound, Lock, Package, Plus, Trash2, Upload } from 'lucide-react'
import { api, enc, type ShareCreated } from '../../lib/api'
import { encryptShare } from '../../lib/crypto'
import { parseEnvContent, type SecretBundlePayload } from '../../lib/env'
import { t } from '../../i18n'
import { Spinner } from '../../ui/common'
import { Field } from '../../ui/Field'
import { toast } from '../../ui/overlays'

interface BundleItemInput {
  id: string
  key: string
  value: string
}

export function ShareCreateForm({
  onCreated,
}: {
  onCreated: (fullUrl: string) => void
}) {
  const [shareMode, setShareMode] = useState<'single' | 'bundle'>('single')

  // Create state - single secret
  const [secretText, setSecretText] = useState('')

  // Create state - bundle
  const [bundleTitle, setBundleTitle] = useState('')
  const [bundleItems, setBundleItems] = useState<BundleItemInput[]>([
    { id: '1', key: 'DATABASE_URL', value: '' },
    { id: '2', key: 'API_KEY', value: '' },
  ])
  const [showEnvPaste, setShowEnvPaste] = useState(false)
  const [envPasteText, setEnvPasteText] = useState('')

  // Shared settings
  const [ttlSeconds, setTtlSeconds] = useState(3600) // 1 hour default
  const [maxViews, setMaxViews] = useState(1) // 1 view default
  const [passphrase, setPassphrase] = useState('')
  const [creating, setCreating] = useState(false)

  const handleAddBundleRow = () => {
    setBundleItems((prev) => [
      ...prev,
      { id: String(Date.now() + Math.random()), key: '', value: '' },
    ])
  }

  const handleRemoveBundleRow = (id: string) => {
    setBundleItems((prev) => prev.filter((item) => item.id !== id))
  }

  const handleUpdateBundleRow = (id: string, field: 'key' | 'value', val: string) => {
    setBundleItems((prev) =>
      prev.map((item) => (item.id === id ? { ...item, [field]: val } : item))
    )
  }

  const handleParseEnvPaste = () => {
    if (!envPasteText.trim()) return
    const parsedItems = parseEnvContent(envPasteText)
    if (parsedItems.length > 0) {
      setBundleItems(
        parsedItems.map((p, idx) => ({
          id: `${idx}_${Date.now()}_${Math.random()}`,
          key: p.key.toUpperCase(),
          value: p.value,
        }))
      )
      setShowEnvPaste(false)
      setEnvPasteText('')
      toast.ok(t('{0} secrets parsed from .env', parsedItems.length))
    } else {
      toast.err(t('No valid KEY=VALUE pairs found in pasted text.'))
    }
  }

  const handleCreate = async () => {
    let payloadText = ''

    if (shareMode === 'bundle') {
      const validItems = bundleItems.filter((i) => i.key.trim().length > 0)
      if (validItems.length === 0) {
        toast.err(t('Please add at least one secret to the bundle.'))
        return
      }
      const bundlePayload: SecretBundlePayload = {
        __ducksecrets_bundle: true,
        version: 1,
        title: bundleTitle.trim() || t('Secret Bundle'),
        created_at: new Date().toISOString(),
        secrets: validItems.map((i) => ({ key: i.key.trim(), value: i.value })),
      }
      payloadText = JSON.stringify(bundlePayload)
    } else {
      if (!secretText.trim()) {
        toast.err(t('Please enter a secret to share.'))
        return
      }
      payloadText = secretText
    }

    setCreating(true)
    try {
      const encrypted = await encryptShare(payloadText, passphrase)
      const res = await api.post<ShareCreated>('/shares', {
        ciphertext: encrypted.ciphertext,
        nonce: encrypted.nonce,
        ttl_seconds: ttlSeconds,
        max_views: maxViews,
        has_passphrase: encrypted.hasPassphrase,
        passphrase_salt: encrypted.passphraseSalt || '',
      })

      const fullUrl = `${window.location.origin}/#/share/${enc(res.id)}?k=${encrypted.keyUrlSafe}`
      toast.ok(t('Share link generated!'))
      setSecretText('')
      setPassphrase('')
      onCreated(fullUrl)
    } catch (err: any) {
      toast.err(err.message || t('Failed to generate share link.'))
    } finally {
      setCreating(false)
    }
  }

  return (
    <form className="form" onSubmit={(e) => { e.preventDefault(); handleCreate() }}>
      {/* Mode Toggle: Single Secret vs Bundle */}
      <div
        className="surface-box"
        style={{
          display: 'flex',
          gap: 8,
          padding: 4,
        }}
      >
        <button
          type="button"
          className={`btn btn-sm ${shareMode === 'single' ? 'btn-primary' : 'btn-ghost'}`}
          style={{ flex: 1, justifyContent: 'center' }}
          onClick={() => setShareMode('single')}
        >
          <Lock size={14} />
          <span>{t('Single Secret')}</span>
        </button>
        <button
          type="button"
          className={`btn btn-sm ${shareMode === 'bundle' ? 'btn-primary' : 'btn-ghost'}`}
          style={{ flex: 1, justifyContent: 'center' }}
          onClick={() => setShareMode('bundle')}
        >
          <Package size={14} />
          <span>{t('Secret Bundle (Multiple)')}</span>
        </button>
      </div>

      {shareMode === 'single' ? (
        <Field label={t('Secret Text / Password / Key')}>
          <textarea
            rows={5}
            className="mono"
            placeholder={t('Paste secret value here (passwords, tokens, private keys, .env snippets)...')}
            value={secretText}
            onChange={(e) => setSecretText(e.target.value)}
            style={{ background: 'var(--surface-2)' }}
          />
        </Field>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span className="label" style={{ margin: 0 }}>
              {t('Bundle Secrets & Key-Values')}
            </span>
            <button
              type="button"
              className="btn btn-ghost btn-xs"
              onClick={() => setShowEnvPaste(!showEnvPaste)}
            >
              <Upload size={12} />
              {showEnvPaste ? t('Cancel Paste') : t('Paste .env')}
            </button>
          </div>

          {showEnvPaste && (
            <div className="surface-box">
              <span className="muted small" style={{ display: 'block', marginBottom: 4 }}>
                {t('Paste KEY=VALUE environment file content:')}
              </span>
              <textarea
                rows={4}
                className="mono small"
                value={envPasteText}
                onChange={(e) => setEnvPasteText(e.target.value)}
                placeholder={'DATABASE_URL=postgres://...\nSTRIPE_KEY=sk_test_...'}
              />
              <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 6 }}>
                <button
                  type="button"
                  className="btn btn-sm btn-primary"
                  onClick={handleParseEnvPaste}
                >
                  {t('Import into Bundle')}
                </button>
              </div>
            </div>
          )}

          <input
            type="text"
            placeholder={t('Bundle Title / Label (e.g. Staging DB & Payment Credentials)')}
            value={bundleTitle}
            onChange={(e) => setBundleTitle(e.target.value)}
            style={{ background: 'var(--surface-2)' }}
          />

          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {bundleItems.map((item) => (
              <div key={item.id} style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                <input
                  type="text"
                  className="mono"
                  placeholder="KEY_NAME"
                  value={item.key}
                  onChange={(e) => handleUpdateBundleRow(item.id, 'key', e.target.value.toUpperCase())}
                  style={{ flex: '0 0 35%', background: 'var(--surface-2)' }}
                />
                <input
                  type="text"
                  className="mono"
                  placeholder="secret_value"
                  value={item.value}
                  onChange={(e) => handleUpdateBundleRow(item.id, 'value', e.target.value)}
                  style={{ flex: 1, background: 'var(--surface-2)' }}
                />
                <button
                  type="button"
                  className="icon-btn tone-bad"
                  onClick={() => handleRemoveBundleRow(item.id)}
                  title={t('Remove row')}
                >
                  <Trash2 size={14} />
                </button>
              </div>
            ))}
          </div>

          <div>
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              onClick={handleAddBundleRow}
            >
              <Plus size={13} />
              {t('Add Secret to Bundle')}
            </button>
          </div>
        </div>
      )}

      <div className="grid-2">
        <Field label={t('Expiration Time')}>
          <select
            value={ttlSeconds}
            onChange={(e) => setTtlSeconds(Number(e.target.value))}
            style={{ background: 'var(--surface-2)' }}
          >
            <option value={300}>{t('5 minutes')}</option>
            <option value={3600}>{t('1 hour')}</option>
            <option value={86400}>{t('24 hours (1 day)')}</option>
            <option value={604800}>{t('7 days')}</option>
            <option value={2592000}>{t('30 days')}</option>
          </select>
        </Field>

        <Field label={t('Maximum Views')}>
          <select
            value={maxViews}
            onChange={(e) => setMaxViews(Number(e.target.value))}
            style={{ background: 'var(--surface-2)' }}
          >
            <option value={1}>{t('1 view (Burn immediately on read)')}</option>
            <option value={2}>{t('2 views')}</option>
            <option value={5}>{t('5 views')}</option>
            <option value={10}>{t('10 views')}</option>
          </select>
        </Field>
      </div>

      <Field
        label={
          <span>
            <KeyRound size={13} style={{ display: 'inline', marginRight: 4, verticalAlign: 'text-bottom' }} />
            {t('Optional Passphrase Protection')}
          </span>
        }
        help={t('Recipient will have to enter this passphrase in addition to opening the link.')}
      >
        <input
          type="password"
          autoComplete="new-password"
          placeholder={t('Require an extra passphrase to unlock (optional)')}
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          style={{ background: 'var(--surface-2)' }}
        />
      </Field>

      <button
        type="submit"
        className="btn btn-primary"
        disabled={creating}
        style={{ width: '100%', height: 38, justifyContent: 'center', fontWeight: 600 }}
      >
        {creating ? (
          <>
            <Spinner />
            <span>{t('Encrypting & Creating Link...')}</span>
          </>
        ) : (
          <>
            <Flame size={16} />
            <span>{shareMode === 'bundle' ? t('Generate Encrypted Bundle Link') : t('Generate Secure Share Link')}</span>
          </>
        )}
      </button>
    </form>
  )
}
