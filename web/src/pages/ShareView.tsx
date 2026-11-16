import { useEffect, useState } from 'react'
import {
  AlertCircle,
  Flame,
  KeyRound,
  Lock,
  Package,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react'
import { api, ApiError, enc, type ShareMetadata, type ShareReveal } from '../lib/api'
import { decryptShare } from '../lib/crypto'
import { isSecretBundlePayload, type SecretBundlePayload } from '../lib/env'
import { useRoute } from '../lib/router'
import { Spinner, Tag } from '../ui/common'
import { Field } from '../ui/Field'
import { t } from '../i18n'
import { ShareBundleViewer } from './shares/ShareBundleViewer'
import { ShareSingleViewer } from './shares/ShareSingleViewer'

export type { SecretBundleItem, SecretBundlePayload } from '../lib/env'

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
  const [bundle, setBundle] = useState<SecretBundlePayload | null>(null)

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

      try {
        const parsed = JSON.parse(plain)
        setBundle(isSecretBundlePayload(parsed) ? parsed : null)
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

  if (loading) {
    return (
      <div className="share-shell">
        <Spinner />
      </div>
    )
  }

  return (
    <div className="share-shell">
      <div className={`share-card ${bundle ? 'wide' : ''}`}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20 }}>
          <div
            style={{
              width: 42,
              height: 42,
              borderRadius: 10,
              background: 'var(--accent-soft)',
              display: 'grid',
              placeItems: 'center',
              color: 'var(--accent)',
              flexShrink: 0,
            }}
          >
            {bundle ? <Package size={22} /> : <Flame size={22} />}
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              <h2 style={{ margin: 0, fontSize: 18, fontWeight: 600 }}>
                {bundle ? bundle.title || t('DuckSecrets — Secret Bundle') : t('DuckSecrets — Ephemeral Share')}
              </h2>
              {bundle && <Tag tone="accent" mono>{bundle.secrets.length} {t('secrets')}</Tag>}
              {bundle?.environment && <Tag>{bundle.environment}</Tag>}
            </div>
            <p className="muted small" style={{ margin: '2px 0 0' }}>
              {t('End-to-End Encrypted')}
            </p>
          </div>
        </div>

        {error ? (
          <div className="alert alert-bad" style={{ flexDirection: 'column', gap: 6, marginBottom: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontWeight: 600 }}>
              <ShieldAlert size={18} />
              <span>{t('Secret Destroyed or Unavailable')}</span>
            </div>
            <p style={{ margin: 0, lineHeight: 1.5 }}>{error}</p>
          </div>
        ) : revealed && secretText !== null ? (
          <div>
            <div className="alert alert-warn" style={{ alignItems: 'center', fontWeight: 500, marginBottom: 16 }}>
              <Flame size={16} />
              <span>
                {cachedReveal?.burned
                  ? t('This secret has been permanently burned and deleted from the server.')
                  : t('View recorded. Remaining views: {0}', Math.max(0, (cachedReveal?.max_views ?? metadata?.max_views ?? 1) - (cachedReveal?.view_count ?? metadata?.view_count ?? 0)))}
              </span>
            </div>

            {bundle ? (
              <ShareBundleViewer bundle={bundle} />
            ) : (
              <ShareSingleViewer secretText={secretText} />
            )}

            <div className="muted small" style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 16 }}>
              <ShieldCheck size={14} className="tone-ok" />
              <span>{t('Decrypted in your browser.')}</span>
            </div>
          </div>
        ) : (
          <form className="form" onSubmit={(e) => { e.preventDefault(); handleReveal() }}>
            <div className="surface-box" style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 13 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span className="muted">{t('Max Views')}:</span>
                <strong>{metadata?.max_views} {metadata?.max_views === 1 ? t('(Burn on read)') : ''}</strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span className="muted">{t('Views Remaining')}:</span>
                <strong style={{ color: 'var(--accent)' }}>
                  {Math.max(0, (metadata?.max_views ?? 1) - (metadata?.view_count ?? 0))}
                </strong>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span className="muted">{t('Expires')}:</span>
                <span>{metadata?.expires_at ? new Date(metadata.expires_at).toLocaleString() : ''}</span>
              </div>
            </div>

            {metadata?.has_passphrase && (
              <Field
                label={
                  <span>
                    <KeyRound size={13} style={{ display: 'inline', marginRight: 4, verticalAlign: 'text-bottom' }} />
                    {t('Passphrase Required')}
                  </span>
                }
              >
                <input
                  type="password"
                  autoComplete="current-password"
                  placeholder={t('Enter passphrase to decrypt')}
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  style={{ background: 'var(--surface-2)' }}
                />
              </Field>
            )}

            {passphraseError && (
              <div className="alert alert-bad" style={{ alignItems: 'center', marginBottom: 0 }}>
                <AlertCircle size={15} />
                <span>{passphraseError}</span>
              </div>
            )}

            <button
              type="submit"
              className="btn btn-primary"
              disabled={revealing}
              style={{ width: '100%', height: 40, fontSize: 14, fontWeight: 600, justifyContent: 'center' }}
            >
              {revealing ? (
                <>
                  <Spinner />
                  <span>{t('Decrypting...')}</span>
                </>
              ) : (
                <>
                  <Flame size={17} />
                  <span>{t('Reveal & Burn Secret')}</span>
                </>
              )}
            </button>

            <p className="muted small" style={{ textAlign: 'center', margin: 0 }}>
              <Lock size={12} style={{ display: 'inline', marginRight: 4, verticalAlign: 'text-bottom' }} />
              {t('The server only stores encrypted data; the key stays in your link.')}
            </p>
          </form>
        )}
      </div>
    </div>
  )
}
