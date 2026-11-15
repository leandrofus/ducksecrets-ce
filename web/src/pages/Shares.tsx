import { useEffect, useState } from 'react'
import { Check, Copy, Flame, KeyRound, Lock, Package, Plus, ShieldCheck, Trash2, Upload } from 'lucide-react'
import { api, enc, type ShareCreated, type ShareMetadata } from '../lib/api'
import { encryptShare } from '../lib/crypto'
import { copy } from '../lib/format'
import { t } from '../i18n'
import { Spinner } from '../ui/common'
import { confirm, toast } from '../ui/overlays'
import { useMenu, type MenuEntry } from '../ui/ContextMenu'
import type { SecretBundlePayload } from './ShareView'

interface BundleItemInput {
  id: string
  key: string
  value: string
}

export function Shares() {
  const [tab, setTab] = useState<'create' | 'active'>('create')
  const [shareMode, setShareMode] = useState<'single' | 'bundle'>('single')
  const menu = useMenu()

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
  const [createdUrl, setCreatedUrl] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  // Active shares state
  const [activeShares, setActiveShares] = useState<ShareMetadata[]>([])
  const [loadingShares, setLoadingShares] = useState(false)

  const loadActiveShares = () => {
    setLoadingShares(true)
    api
      .get<ShareMetadata[]>('/shares')
      .then((data) => {
        setActiveShares(data)
        setLoadingShares(false)
      })
      .catch(() => {
        setLoadingShares(false)
      })
  }

  useEffect(() => {
    if (tab === 'active') {
      loadActiveShares()
    }
  }, [tab])

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
    const lines = envPasteText.split('\n')
    const parsed: BundleItemInput[] = []
    for (const rawLine of lines) {
      const line = rawLine.trim()
      if (!line || line.startsWith('#')) continue
      const eqIdx = line.indexOf('=')
      if (eqIdx > 0) {
        const key = line.slice(0, eqIdx).trim()
        let val = line.slice(eqIdx + 1).trim()
        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
          val = val.slice(1, -1)
        }
        parsed.push({
          id: String(Date.now() + Math.random()),
          key: key.toUpperCase(),
          value: val,
        })
      }
    }
    if (parsed.length > 0) {
      setBundleItems(parsed)
      setShowEnvPaste(false)
      setEnvPasteText('')
      toast.ok(t('{0} secrets parsed from .env', parsed.length))
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

      // Form full URL with hash fragment query
      const fullUrl = `${window.location.origin}/#/share/${enc(res.id)}?k=${encrypted.keyUrlSafe}`
      setCreatedUrl(fullUrl)
      toast.ok(t('Share link generated!'))
      setSecretText('')
      setPassphrase('')
    } catch (err: any) {
      toast.err(err.message || t('Failed to generate share link.'))
    } finally {
      setCreating(false)
    }
  }

  const handleCopyLink = () => {
    if (createdUrl) {
      copy(createdUrl).then((ok) => {
        if (ok) {
          setCopied(true)
          setTimeout(() => setCopied(false), 2000)
          toast.ok(t('Link copied to clipboard!'))
        }
      })
    }
  }

  const handleDeleteShare = async (id: string) => {
    const ok = await confirm({
      title: t('Revoke share?'),
      body: t('Are you sure you want to revoke this secret share immediately?'),
      danger: true,
      confirm: t('Revoke & Burn'),
    })
    if (!ok) return

    try {
      await api.del(`/shares/${enc(id)}`)
      toast.ok(t('Share revoked successfully.'))
      setActiveShares((prev) => prev.filter((s) => s.id !== id))
    } catch (err: any) {
      toast.err(err.message || t('Failed to revoke share.'))
    }
  }

  const shareActions = (s: ShareMetadata): MenuEntry[] => [
    { header: s.id },
    {
      label: t('Copy Share Link Base'),
      icon: <Copy size={14} />,
      onClick: () => {
        copy(`${window.location.origin}/#/share/${enc(s.id)}`).then((ok) => {
          if (ok) toast.ok(t('Share link base copied'))
        })
      },
    },
    'sep',
    {
      label: t('Revoke & Burn immediately'),
      icon: <Trash2 size={14} />,
      danger: true,
      onClick: () => handleDeleteShare(s.id),
    },
  ]

  return (
    <div className="page">
      <div className="page-head">
        <div className="page-title">
          <Flame size={20} style={{ color: 'var(--accent)' }} />
          <h1>{t('Ephemeral Secret Sharing')}</h1>
        </div>
        <div className="page-actions">
          <button
            className={`btn btn-sm ${tab === 'create' ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => setTab('create')}
          >
            <Plus size={14} />
            <span>{t('New Share')}</span>
          </button>
          <button
            className={`btn btn-sm ${tab === 'active' ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => setTab('active')}
          >
            <Flame size={14} />
            <span>{t('Active Shares')}</span>
          </button>
        </div>
      </div>

      <div className="page-body">
        <div style={{ maxWidth: 860, margin: '0 auto' }}>

      {tab === 'create' ? (
        <div className="card" style={{ padding: '1.75rem', borderRadius: '10px', background: 'var(--surface)', border: '1px solid var(--border)' }}>
          {createdUrl ? (
            <div>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  padding: '1rem',
                  borderRadius: '8px',
                  backgroundColor: 'rgba(16, 185, 129, 0.1)',
                  color: '#10b981',
                  marginBottom: '1.5rem',
                  fontWeight: 500,
                  border: '1px solid rgba(16, 185, 129, 0.2)',
                }}
              >
                <ShieldCheck size={20} />
                <span>{t('Secure Share Link Created and Encrypted!')}</span>
              </div>

              <div style={{ marginBottom: '1.5rem' }}>
                <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 500, marginBottom: '0.5rem' }}>
                  {t('Shareable Link')}
                </label>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <input
                    type="text"
                    readOnly
                    value={createdUrl}
                    style={{
                      flex: 1,
                      fontFamily: 'monospace',
                      fontSize: '0.85rem',
                      padding: '0.65rem 0.75rem',
                      borderRadius: '6px',
                      border: '1px solid var(--border)',
                      backgroundColor: 'var(--surface-2)',
                      color: 'var(--text)',
                    }}
                  />
                  <button
                    className="btn btn-primary"
                    onClick={handleCopyLink}
                    style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}
                  >
                    {copied ? <Check size={16} /> : <Copy size={16} />}
                    <span>{copied ? t('Copied!') : t('Copy')}</span>
                  </button>
                </div>
              </div>

              <div
                style={{
                  padding: '1rem',
                  borderRadius: '8px',
                  backgroundColor: 'var(--surface-2)',
                  border: '1px solid var(--border)',
                  marginBottom: '1.5rem',
                  fontSize: '0.85rem',
                  color: 'var(--muted)',
                  lineHeight: 1.5,
                }}
              >
                <strong style={{ color: 'var(--text)', display: 'block', marginBottom: '0.25rem' }}>
                  <Lock size={13} style={{ display: 'inline', marginRight: '4px', verticalAlign: 'text-bottom' }} />
                  {t('Client-Side Encryption')}
                </strong>
                {t(
                  'The decryption key stays in the #k= URL fragment, so the browser never sends it to the server.'
                )}
              </div>

              <button
                className="btn btn-subtle"
                onClick={() => setCreatedUrl(null)}
                style={{ width: '100%' }}
              >
                {t('Create Another Secret Link')}
              </button>
            </div>
          ) : (
            <div>
              {/* Mode Toggle: Single Secret vs Bundle */}
              <div
                style={{
                  display: 'flex',
                  gap: 8,
                  padding: '4px',
                  background: 'var(--surface-2)',
                  borderRadius: 8,
                  marginBottom: '1.25rem',
                  border: '1px solid var(--border)',
                }}
              >
                <button
                  type="button"
                  className={`btn btn-sm ${shareMode === 'single' ? 'btn-primary' : 'btn-ghost'}`}
                  style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6 }}
                  onClick={() => setShareMode('single')}
                >
                  <Lock size={14} />
                  <span>{t('Single Secret')}</span>
                </button>
                <button
                  type="button"
                  className={`btn btn-sm ${shareMode === 'bundle' ? 'btn-primary' : 'btn-ghost'}`}
                  style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6 }}
                  onClick={() => setShareMode('bundle')}
                >
                  <Package size={14} />
                  <span>{t('Secret Bundle (Multiple)')}</span>
                </button>
              </div>

              {shareMode === 'single' ? (
                /* Single secret textarea */
                <div style={{ marginBottom: '1.25rem' }}>
                  <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 500, marginBottom: '0.5rem' }}>
                    {t('Secret Text / Password / Key')}
                  </label>
                  <textarea
                    rows={5}
                    placeholder={t('Paste secret value here (passwords, tokens, private keys, .env snippets)...')}
                    value={secretText}
                    onChange={(e) => setSecretText(e.target.value)}
                    style={{
                      width: '100%',
                      fontFamily: 'monospace',
                      fontSize: '0.9rem',
                      padding: '0.75rem',
                      borderRadius: '6px',
                      border: '1px solid var(--border)',
                      backgroundColor: 'var(--surface-2)',
                      color: 'var(--text)',
                      boxSizing: 'border-box',
                      resize: 'vertical',
                    }}
                  />
                </div>
              ) : (
                /* Bundle mode: Multiple Key-Value pairs */
                <div style={{ marginBottom: '1.25rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                    <label style={{ fontSize: '0.85rem', fontWeight: 500, margin: 0 }}>
                      {t('Bundle Secrets & Key-Values')}
                    </label>
                    <button
                      type="button"
                      className="btn btn-ghost btn-sm"
                      style={{ fontSize: 11, padding: '2px 8px' }}
                      onClick={() => setShowEnvPaste(!showEnvPaste)}
                    >
                      <Upload size={12} style={{ marginRight: 4 }} />
                      {showEnvPaste ? t('Cancel Paste') : t('Paste .env')}
                    </button>
                  </div>

                  {showEnvPaste && (
                    <div
                      style={{
                        padding: '10px',
                        background: 'var(--surface-2)',
                        border: '1px solid var(--border)',
                        borderRadius: 8,
                        marginBottom: 10,
                      }}
                    >
                      <span className="muted small" style={{ display: 'block', marginBottom: 4 }}>
                        {t('Paste KEY=VALUE environment file content:')}
                      </span>
                      <textarea
                        rows={4}
                        className="mono"
                        style={{
                          width: '100%',
                          fontSize: 12,
                          padding: '6px',
                          background: 'var(--surface)',
                          color: 'var(--text)',
                          border: '1px solid var(--border)',
                          borderRadius: 6,
                        }}
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

                  <div style={{ marginBottom: 10 }}>
                    <input
                      type="text"
                      placeholder={t('Bundle Title / Label (e.g. Staging DB & Payment Credentials)')}
                      value={bundleTitle}
                      onChange={(e) => setBundleTitle(e.target.value)}
                      style={{
                        width: '100%',
                        padding: '0.55rem 0.75rem',
                        borderRadius: '6px',
                        border: '1px solid var(--border)',
                        backgroundColor: 'var(--surface-2)',
                        color: 'var(--text)',
                        fontSize: '0.85rem',
                        boxSizing: 'border-box',
                      }}
                    />
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 8 }}>
                    {bundleItems.map((item) => (
                      <div key={item.id} style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                        <input
                          type="text"
                          className="mono"
                          placeholder="KEY_NAME"
                          value={item.key}
                          onChange={(e) => handleUpdateBundleRow(item.id, 'key', e.target.value.toUpperCase())}
                          style={{
                            flex: '0 0 35%',
                            padding: '0.5rem 0.65rem',
                            borderRadius: 6,
                            border: '1px solid var(--border)',
                            backgroundColor: 'var(--surface-2)',
                            color: 'var(--text)',
                            fontSize: 12,
                          }}
                        />
                        <input
                          type="text"
                          className="mono"
                          placeholder="secret_value"
                          value={item.value}
                          onChange={(e) => handleUpdateBundleRow(item.id, 'value', e.target.value)}
                          style={{
                            flex: 1,
                            padding: '0.5rem 0.65rem',
                            borderRadius: 6,
                            border: '1px solid var(--border)',
                            backgroundColor: 'var(--surface-2)',
                            color: 'var(--text)',
                            fontSize: 12,
                          }}
                        />
                        <button
                          type="button"
                          className="icon-btn"
                          style={{ color: 'var(--bad, #ef4444)' }}
                          onClick={() => handleRemoveBundleRow(item.id)}
                          title={t('Remove row')}
                        >
                          <Trash2 size={14} />
                        </button>
                      </div>
                    ))}
                  </div>

                  <button
                    type="button"
                    className="btn btn-ghost btn-sm"
                    onClick={handleAddBundleRow}
                    style={{ fontSize: 12 }}
                  >
                    <Plus size={13} style={{ marginRight: 4 }} />
                    {t('Add Secret to Bundle')}
                  </button>
                </div>
              )}

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.25rem' }}>
                <div>
                  <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 500, marginBottom: '0.5rem' }}>
                    {t('Expiration Time')}
                  </label>
                  <select
                    value={ttlSeconds}
                    onChange={(e) => setTtlSeconds(Number(e.target.value))}
                    style={{
                      width: '100%',
                      padding: '0.6rem 0.75rem',
                      borderRadius: '6px',
                      border: '1px solid var(--border)',
                      backgroundColor: 'var(--surface-2)',
                      color: 'var(--text)',
                      fontSize: '0.9rem',
                    }}
                  >
                    <option value={300}>{t('5 minutes')}</option>
                    <option value={3600}>{t('1 hour')}</option>
                    <option value={86400}>{t('24 hours (1 day)')}</option>
                    <option value={604800}>{t('7 days')}</option>
                    <option value={2592000}>{t('30 days')}</option>
                  </select>
                </div>

                <div>
                  <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 500, marginBottom: '0.5rem' }}>
                    {t('Maximum Views')}
                  </label>
                  <select
                    value={maxViews}
                    onChange={(e) => setMaxViews(Number(e.target.value))}
                    style={{
                      width: '100%',
                      padding: '0.6rem 0.75rem',
                      borderRadius: '6px',
                      border: '1px solid var(--border)',
                      backgroundColor: 'var(--surface-2)',
                      color: 'var(--text)',
                      fontSize: '0.9rem',
                    }}
                  >
                    <option value={1}>{t('1 view (Burn immediately on read)')}</option>
                    <option value={2}>{t('2 views')}</option>
                    <option value={5}>{t('5 views')}</option>
                    <option value={10}>{t('10 views')}</option>
                  </select>
                </div>
              </div>

              <div style={{ marginBottom: '1.5rem' }}>
                <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 500, marginBottom: '0.5rem' }}>
                  <KeyRound size={14} style={{ display: 'inline', marginRight: '4px', verticalAlign: 'text-bottom' }} />
                  {t('Optional Passphrase Protection')}
                </label>
                <input
                  type="password"
                  placeholder={t('Require an extra passphrase to unlock (optional)')}
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '0.65rem 0.75rem',
                    borderRadius: '6px',
                    border: '1px solid var(--border)',
                    backgroundColor: 'var(--surface-2)',
                    color: 'var(--text)',
                    fontSize: '0.9rem',
                    boxSizing: 'border-box',
                  }}
                />
                <span className="muted small" style={{ display: 'block', marginTop: '0.25rem' }}>
                  {t('Recipient will have to enter this passphrase in addition to opening the link.')}
                </span>
              </div>

              <button
                className="btn btn-primary"
                disabled={creating}
                onClick={handleCreate}
                style={{
                  width: '100%',
                  padding: '0.75rem',
                  fontSize: '0.95rem',
                  fontWeight: 600,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '0.5rem',
                }}
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
            </div>
          )}
        </div>
      ) : (
        <div className="card" style={{ padding: '1.5rem', borderRadius: '10px', background: 'var(--surface)', border: '1px solid var(--border)' }}>
          <h2 style={{ fontSize: '1.1rem', fontWeight: 600, marginBottom: '1rem' }}>
            {t('Your Active Shares')}
          </h2>

          {loadingShares ? (
            <div className="center" style={{ padding: '2rem' }}>
              <Spinner />
            </div>
          ) : activeShares.length === 0 ? (
            <div className="muted center" style={{ padding: '2rem' }}>
              <Flame size={32} style={{ opacity: 0.3, marginBottom: '0.5rem' }} />
              <p>{t('No active shares. All previous shares have been burned or expired.')}</p>
            </div>
          ) : (
            <table className="table" style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)', textAlign: 'left' }}>
                  <th style={{ padding: '0.6rem 0.75rem' }}>{t('Share ID')}</th>
                  <th style={{ padding: '0.6rem 0.75rem' }}>{t('Views Remaining')}</th>
                  <th style={{ padding: '0.6rem 0.75rem' }}>{t('Protection')}</th>
                  <th style={{ padding: '0.6rem 0.75rem' }}>{t('Expires')}</th>
                  <th style={{ padding: '0.6rem 0.75rem', textAlign: 'right' }}>{t('Actions')}</th>
                </tr>
              </thead>
              <tbody>
                {activeShares.map((s) => (
                  <tr key={s.id} onContextMenu={menu(() => shareActions(s))} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '0.6rem 0.75rem', fontFamily: 'monospace', fontSize: '0.85rem' }}>
                      {s.id}
                    </td>
                    <td style={{ padding: '0.6rem 0.75rem' }}>
                      <span
                        style={{
                          display: 'inline-block',
                          padding: '0.2rem 0.5rem',
                          borderRadius: '4px',
                          fontSize: '0.75rem',
                          fontWeight: 600,
                          backgroundColor:
                            s.max_views - s.view_count > 0 ? 'rgba(234, 88, 12, 0.1)' : 'rgba(100, 116, 139, 0.1)',
                          color: s.max_views - s.view_count > 0 ? 'var(--accent, #ea580c)' : 'var(--muted)',
                        }}
                      >
                        {Math.max(0, s.max_views - s.view_count)} / {s.max_views}
                      </span>
                    </td>
                    <td style={{ padding: '0.6rem 0.75rem', fontSize: '0.85rem' }}>
                      {s.has_passphrase ? (
                        <span style={{ color: '#10b981', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                          <Lock size={12} /> {t('Passphrase')}
                        </span>
                      ) : (
                        <span className="muted">{t('Standard')}</span>
                      )}
                    </td>
                    <td style={{ padding: '0.6rem 0.75rem', fontSize: '0.85rem' }}>
                      {new Date(s.expires_at).toLocaleString()}
                    </td>
                    <td style={{ padding: '0.6rem 0.75rem', textAlign: 'right' }}>
                      <button
                        className="icon-btn"
                        title={t('Revoke & Burn immediately')}
                        onClick={() => handleDeleteShare(s.id)}
                        style={{ color: '#ef4444' }}
                      >
                        <Trash2 size={16} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
        </div>
      </div>
    </div>
  )
}
