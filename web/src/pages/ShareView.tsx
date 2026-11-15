import { useEffect, useState } from 'react'
import {
  AlertCircle,
  Check,
  Copy,
  Eye,
  EyeOff,
  Flame,
  KeyRound,
  Lock,
  Package,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react'
import { api, ApiError, enc, type ShareMetadata, type ShareReveal } from '../lib/api'
import { decryptShare } from '../lib/crypto'
import { copy } from '../lib/format'
import { useRoute } from '../lib/router'
import { Spinner, Tag } from '../ui/common'
import { toast } from '../ui/overlays'
import { t } from '../i18n'

export interface SecretBundleItem {
  key: string
  value: string
  comment?: string
}

export interface SecretBundlePayload {
  __ducksecrets_bundle: boolean
  version?: number
  title?: string
  project?: string
  environment?: string
  created_at?: string
  secrets: SecretBundleItem[]
}

export function ShareView() {
  const route = useRoute()
  const shareId = route.id || ''
  const keyUrlSafe = route.query.get('k') || ''

  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [metadata, setMetadata] = useState<ShareMetadata | null>(null)

  const [revealing, setRevealing] = useState(false)
  const [revealed, setRevealed] = useState(false)
  const [cachedReveal, setCachedReveal] = useState<ShareReveal | null>(null)
  const [passphrase, setPassphrase] = useState('')
  const [passphraseError, setPassphraseError] = useState<string | null>(null)
  const [secretText, setSecretText] = useState<string | null>(null)

  // Single secret display state
  const [showSingleText, setShowSingleText] = useState(false)
  const [copiedSingle, setCopiedSingle] = useState(false)

  // Bundle display state
  const [bundle, setBundle] = useState<SecretBundlePayload | null>(null)
  const [revealedKeys, setRevealedKeys] = useState<Record<string, boolean>>({})
  const [copiedKeys, setCopiedKeys] = useState<Record<string, boolean>>({})
  const [revealAllBundle, setRevealAllBundle] = useState(false)
  const [copiedAllEnv, setCopiedAllEnv] = useState(false)
  const [copiedAllJson, setCopiedAllJson] = useState(false)

  useEffect(() => {
    setLoading(true)
    setError(null)
    setMetadata(null)
    setRevealed(false)
    setCachedReveal(null)
    setPassphrase('')
    setPassphraseError(null)
    setSecretText(null)
    setBundle(null)
    setShowSingleText(false)
    setCopiedSingle(false)
    setRevealedKeys({})
    setCopiedKeys({})
    setRevealAllBundle(false)
    setCopiedAllEnv(false)
    setCopiedAllJson(false)

    if (!shareId) {
      setError(t('Invalid share link: missing secret ID.'))
      setLoading(false)
      return
    }

    let cancelled = false
    api
      .get<ShareMetadata>(`/shares/${enc(shareId)}`)
      .then((data) => {
        if (cancelled) return
        setMetadata(data)
        setLoading(false)
      })
      .catch(() => {
        if (cancelled) return
        setError(t('This secret has already been viewed and destroyed, or it has expired.'))
        setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [shareId, keyUrlSafe])

  const handleReveal = async () => {
    if (!keyUrlSafe) {
      setError(t('Decryption key missing from URL fragment. The secret cannot be decrypted without the original link.'))
      return
    }

    if (metadata?.has_passphrase && !passphrase.trim()) {
      setPassphraseError(t('Please enter the passphrase required for this secret.'))
      return
    }

    setRevealing(true)
    setPassphraseError(null)

    try {
      let data = cachedReveal
      if (!data) {
        data = await api.post<ShareReveal>(`/shares/${enc(shareId)}/reveal`, {})
        setCachedReveal(data)
      }
      const plain = await decryptShare(
        data.ciphertext,
        data.nonce,
        keyUrlSafe,
        passphrase,
        data.passphrase_salt
      )
      setSecretText(plain)

      // Detect if the payload is a bundle
      try {
        const parsed = JSON.parse(plain)
        if (
          parsed &&
          typeof parsed === 'object' &&
          !Array.isArray(parsed) &&
          parsed.__ducksecrets_bundle === true &&
          Array.isArray(parsed.secrets)
        ) {
          setBundle(parsed)
        } else {
          setBundle(null)
        }
      } catch {
        setBundle(null)
      }

      setRevealed(true)
    } catch (err: any) {
      if (err instanceof ApiError && err.status === 404) {
        setError(t('This secret has already been viewed and destroyed, or it has expired.'))
      } else {
        setPassphraseError(err.message || t('Decryption failed. Please check your passphrase.'))
      }
    } finally {
      setRevealing(false)
    }
  }

  const handleCopySingle = () => {
    if (secretText) {
      copy(secretText).then((ok) => {
        if (ok) {
          setCopiedSingle(true)
          toast.ok(t('Secret copied to clipboard!'))
          setTimeout(() => setCopiedSingle(false), 2000)
        }
      })
    }
  }

  const handleCopyBundleItem = (key: string, value: string) => {
    copy(value).then((ok) => {
      if (ok) {
        setCopiedKeys((prev) => ({ ...prev, [key]: true }))
        toast.ok(t('{0} copied to clipboard', key))
        setTimeout(() => {
          setCopiedKeys((prev) => ({ ...prev, [key]: false }))
        }, 2000)
      }
    })
  }

  const handleCopyBundleAsEnv = () => {
    if (!bundle) return
    const lines = bundle.secrets.map((s) => {
      const val = s.value.includes('\n') || s.value.includes(' ') || s.value.includes('"')
        ? `"${s.value.replace(/"/g, '\\"')}"`
        : s.value
      return `${s.key}=${val}`
    })
    const envText = lines.join('\n')
    copy(envText).then((ok) => {
      if (ok) {
        setCopiedAllEnv(true)
        toast.ok(t('All {0} secrets copied as .env', bundle.secrets.length))
        setTimeout(() => setCopiedAllEnv(false), 2000)
      }
    })
  }

  const handleCopyBundleAsJson = () => {
    if (!bundle) return
    const obj: Record<string, string> = {}
    bundle.secrets.forEach((s) => {
      obj[s.key] = s.value
    })
    const jsonText = JSON.stringify(obj, null, 2)
    copy(jsonText).then((ok) => {
      if (ok) {
        setCopiedAllJson(true)
        toast.ok(t('All {0} secrets copied as JSON', bundle.secrets.length))
        setTimeout(() => setCopiedAllJson(false), 2000)
      }
    })
  }

  const toggleRevealBundleItem = (key: string) => {
    setRevealedKeys((prev) => ({ ...prev, [key]: !prev[key] }))
  }

  const toggleRevealAllBundle = () => {
    const next = !revealAllBundle
    setRevealAllBundle(next)
    if (bundle) {
      const map: Record<string, boolean> = {}
      bundle.secrets.forEach((s) => {
        map[s.key] = next
      })
      setRevealedKeys(map)
    }
  }

  if (loading) {
    return (
      <div className="center page" style={{ minHeight: '80vh' }}>
        <Spinner />
      </div>
    )
  }

  return (
    <div className="center page" style={{ minHeight: '80vh', padding: '2rem 1rem' }}>
      <div
        className="card"
        style={{
          width: '100%',
          maxWidth: bundle ? '720px' : '580px',
          padding: '2rem',
          borderRadius: '12px',
          background: 'var(--surface)',
          border: '1px solid var(--border)',
          boxShadow: '0 8px 32px rgba(0,0,0,0.2)',
          transition: 'max-width 0.2s ease',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
          <div
            style={{
              width: '42px',
              height: '42px',
              borderRadius: '10px',
              backgroundColor: 'var(--accent-subtle, rgba(234, 88, 12, 0.15))',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--accent, #ea580c)',
              flexShrink: 0,
            }}
          >
            {bundle ? <Package size={24} /> : <Flame size={24} />}
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              <h2 style={{ margin: 0, fontSize: '1.25rem', fontWeight: 600 }}>
                {bundle ? bundle.title || t('DuckSecrets — Secret Bundle') : t('DuckSecrets — Ephemeral Share')}
              </h2>
              {bundle && <Tag tone="accent" mono>{bundle.secrets.length} {t('secrets')}</Tag>}
              {bundle?.environment && <Tag>{bundle.environment}</Tag>}
            </div>
            <p style={{ margin: '2px 0 0', fontSize: '0.85rem', color: 'var(--muted)' }}>
              {t('End-to-End Encrypted')}
            </p>
          </div>
        </div>

        {error ? (
          <div
            style={{
              padding: '1.25rem',
              borderRadius: '8px',
              backgroundColor: 'rgba(239, 68, 68, 0.1)',
              border: '1px solid rgba(239, 68, 68, 0.25)',
              color: '#ef4444',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem', fontWeight: 600 }}>
              <ShieldAlert size={20} />
              <span>{t('Secret Destroyed or Unavailable')}</span>
            </div>
            <p style={{ margin: 0, fontSize: '0.9rem', lineHeight: 1.5 }}>
              {error}
            </p>
          </div>
        ) : revealed && secretText !== null ? (
          <div>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.75rem 1rem',
                borderRadius: '8px',
                backgroundColor: 'rgba(234, 88, 12, 0.1)',
                color: 'var(--accent, #ea580c)',
                fontSize: '0.85rem',
                marginBottom: '1.25rem',
                fontWeight: 500,
                border: '1px solid rgba(234, 88, 12, 0.2)',
              }}
            >
              <Flame size={16} />
              <span>
                {cachedReveal?.burned
                  ? t('This secret has been permanently burned and deleted from the server.')
                  : t('View recorded. Remaining views: {0}', Math.max(0, (cachedReveal?.max_views ?? metadata?.max_views ?? 1) - (cachedReveal?.view_count ?? metadata?.view_count ?? 0)))}
              </span>
            </div>

            {bundle ? (
              /* ================== BUNDLE VIEW ================== */
              <div>
                {/* Master Action Toolbar */}
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: 8,
                    flexWrap: 'wrap',
                    padding: '8px 12px',
                    borderRadius: 8,
                    background: 'var(--surface-2)',
                    border: '1px solid var(--border)',
                    marginBottom: '1rem',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <button
                      className="btn btn-sm btn-primary"
                      onClick={handleCopyBundleAsEnv}
                      title={t('Copy all secrets formatted as .env')}
                    >
                      {copiedAllEnv ? <Check size={13} /> : <Copy size={13} />}
                      <span>{copiedAllEnv ? t('Copied .env!') : t('Copy All as .env')}</span>
                    </button>
                    <button
                      className="btn btn-sm"
                      onClick={handleCopyBundleAsJson}
                      title={t('Copy all secrets as JSON')}
                    >
                      {copiedAllJson ? <Check size={13} /> : <Copy size={13} />}
                      <span>{copiedAllJson ? t('Copied JSON!') : t('Copy All as JSON')}</span>
                    </button>
                  </div>

                  <button
                    className="btn btn-sm btn-ghost"
                    onClick={toggleRevealAllBundle}
                  >
                    {revealAllBundle ? <EyeOff size={13} /> : <Eye size={13} />}
                    <span>{revealAllBundle ? t('Mask All') : t('Reveal All')}</span>
                  </button>
                </div>

                {/* Secrets Vault List */}
                <div
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: 8,
                    maxHeight: '440px',
                    overflowY: 'auto',
                    marginBottom: '1.25rem',
                    paddingRight: 4,
                  }}
                >
                  {bundle.secrets.map((item, idx) => {
                    const isRevealed = revealAllBundle || revealedKeys[item.key]
                    const isCopied = copiedKeys[item.key]
                    return (
                      <div
                        key={item.key || idx}
                        style={{
                          padding: '10px 12px',
                          background: 'var(--surface-2)',
                          border: '1px solid var(--border)',
                          borderRadius: '8px',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: 6,
                        }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <strong className="mono" style={{ fontSize: 13, color: 'var(--text)' }}>
                              {item.key}
                            </strong>
                            {item.comment && (
                              <span className="muted small" style={{ fontSize: 11 }}>
                                {item.comment}
                              </span>
                            )}
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                            <button
                              type="button"
                              className="btn btn-sm btn-ghost"
                              style={{ padding: '2px 8px', height: 'auto', fontSize: 11 }}
                              onClick={() => toggleRevealBundleItem(item.key)}
                              title={isRevealed ? t('Mask value') : t('Reveal value')}
                            >
                              {isRevealed ? <EyeOff size={12} /> : <Eye size={12} />}
                            </button>
                            <button
                              type="button"
                              className="btn btn-sm btn-primary"
                              style={{ padding: '2px 8px', height: 'auto', fontSize: 11 }}
                              onClick={() => handleCopyBundleItem(item.key, item.value)}
                              title={t('Copy {0}', item.key)}
                            >
                              {isCopied ? <Check size={12} /> : <Copy size={12} />}
                              <span>{isCopied ? t('Copied!') : t('Copy')}</span>
                            </button>
                          </div>
                        </div>

                        {/* Value area: Masked or Revealed */}
                        {isRevealed ? (
                          <pre
                            className="mono"
                            style={{
                              margin: 0,
                              padding: '6px 10px',
                              background: 'var(--surface)',
                              border: '1px solid var(--border)',
                              borderRadius: 6,
                              fontSize: 12,
                              lineHeight: 1.45,
                              whiteSpace: 'pre-wrap',
                              wordBreak: 'break-all',
                              maxHeight: '160px',
                              overflowY: 'auto',
                            }}
                          >
                            {item.value}
                          </pre>
                        ) : (
                          <div
                            className="mono"
                            style={{
                              padding: '6px 10px',
                              background: 'var(--surface)',
                              border: '1px solid var(--border)',
                              borderRadius: 6,
                              fontSize: 12,
                              color: 'var(--muted)',
                              letterSpacing: 2,
                              userSelect: 'none',
                            }}
                          >
                            ••••••••••••••••••••••••
                          </div>
                        )}
                      </div>
                    )
                  })}
                </div>
              </div>
            ) : (
              /* ================== SINGLE SECRET VIEW ================== */
              <div>
                <div
                  style={{
                    borderRadius: '8px',
                    border: '1px solid var(--border)',
                    background: 'var(--surface-2)',
                    overflow: 'hidden',
                    marginBottom: '1rem',
                  }}
                >
                  {/* Vault Header */}
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '8px 12px',
                      borderBottom: '1px solid var(--border)',
                      background: 'rgba(0,0,0,0.15)',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.85rem', fontWeight: 500 }}>
                      <Lock size={13} style={{ color: 'var(--accent)' }} />
                      <span>{t('Encrypted Secret Payload')}</span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span className="muted small mono">{secretText.length} {t('chars')}</span>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        style={{ padding: '2px 8px', height: 'auto', fontSize: 11 }}
                        onClick={() => setShowSingleText(!showSingleText)}
                      >
                        {showSingleText ? <EyeOff size={12} /> : <Eye size={12} />}
                        <span style={{ marginLeft: 4 }}>{showSingleText ? t('Mask') : t('Reveal')}</span>
                      </button>
                    </div>
                  </div>

                  {/* Vault Body: Masked by default, or revealed on demand */}
                  {showSingleText ? (
                    <textarea
                      readOnly
                      value={secretText}
                      rows={Math.min(10, Math.max(4, secretText.split('\n').length))}
                      className="mono"
                      style={{
                        width: '100%',
                        fontSize: '0.9rem',
                        padding: '0.75rem',
                        backgroundColor: 'var(--surface-2)',
                        color: 'var(--text)',
                        border: 'none',
                        boxSizing: 'border-box',
                        resize: 'vertical',
                        outline: 'none',
                        lineHeight: 1.5,
                      }}
                    />
                  ) : (
                    <div
                      className="mono"
                      style={{
                        padding: '1.5rem 1rem',
                        textAlign: 'center',
                        color: 'var(--muted)',
                        letterSpacing: '4px',
                        fontSize: '1.15rem',
                        userSelect: 'none',
                      }}
                    >
                      ••••••••••••••••••••••••••••••••
                    </div>
                  )}
                </div>

                {/* Big Primary Action: Copy to Clipboard */}
                <button
                  className="btn btn-primary"
                  onClick={handleCopySingle}
                  style={{
                    width: '100%',
                    padding: '0.85rem',
                    fontSize: '1rem',
                    fontWeight: 600,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    gap: '0.5rem',
                    borderRadius: '8px',
                    cursor: 'pointer',
                  }}
                >
                  {copiedSingle ? <Check size={18} /> : <Copy size={18} />}
                  <span>{copiedSingle ? t('Secret Copied to Clipboard!') : t('Copy Secret to Clipboard')}</span>
                </button>
              </div>
            )}

            <div
              style={{
                fontSize: '0.8rem',
                color: 'var(--muted)',
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
                marginTop: '1.25rem',
              }}
            >
              <ShieldCheck size={14} color="#10b981" />
              <span>{t('Decrypted in your browser.')}</span>
            </div>
          </div>
        ) : (
          /* ================== UNREVEALED / METADATA STATE ================== */
          <div>
            <div
              style={{
                padding: '1rem',
                borderRadius: '8px',
                backgroundColor: 'var(--surface-2)',
                border: '1px solid var(--border)',
                marginBottom: '1.5rem',
                fontSize: '0.9rem',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                <span className="muted">{t('Max Views')}:</span>
                <strong>{metadata?.max_views} {metadata?.max_views === 1 ? t('(Burn on read)') : ''}</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                <span className="muted">{t('Views Remaining')}:</span>
                <strong style={{ color: 'var(--accent, #ea580c)' }}>
                  {Math.max(0, (metadata?.max_views ?? 1) - (metadata?.view_count ?? 0))}
                </strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span className="muted">{t('Expires')}:</span>
                <span>{metadata?.expires_at ? new Date(metadata.expires_at).toLocaleString() : ''}</span>
              </div>
            </div>

            {metadata?.has_passphrase && (
              <div style={{ marginBottom: '1.25rem' }}>
                <label style={{ display: 'block', fontSize: '0.85rem', fontWeight: 500, marginBottom: '0.5rem' }}>
                  <KeyRound size={14} style={{ display: 'inline', marginRight: '4px', verticalAlign: 'text-bottom' }} />
                  {t('Passphrase Required')}
                </label>
                <input
                  type="password"
                  placeholder={t('Enter passphrase to decrypt')}
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
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') handleReveal()
                  }}
                />
              </div>
            )}

            {passphraseError && (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.4rem',
                  fontSize: '0.85rem',
                  color: '#ef4444',
                  marginBottom: '1rem',
                }}
              >
                <AlertCircle size={14} />
                <span>{passphraseError}</span>
              </div>
            )}

            <button
              className="btn btn-primary"
              disabled={revealing}
              onClick={handleReveal}
              style={{
                width: '100%',
                padding: '0.75rem',
                fontSize: '1rem',
                fontWeight: 600,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '0.5rem',
                borderRadius: '6px',
                cursor: 'pointer',
              }}
            >
              {revealing ? (
                <>
                  <Spinner />
                  <span>{t('Decrypting...')}</span>
                </>
              ) : (
                <>
                  <Flame size={18} />
                  <span>{t('Reveal & Burn Secret')}</span>
                </>
              )}
            </button>

            <p
              style={{
                textAlign: 'center',
                fontSize: '0.75rem',
                color: 'var(--muted)',
                marginTop: '1rem',
                marginBottom: 0,
              }}
            >
              <Lock size={12} style={{ display: 'inline', marginRight: '3px', verticalAlign: 'text-bottom' }} />
              {t('The server only stores encrypted data; the key stays in your link.')}
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
