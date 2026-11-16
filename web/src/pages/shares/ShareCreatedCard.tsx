import { useState } from 'react'
import { Check, Copy, Lock, ShieldCheck } from 'lucide-react'
import { copy } from '../../lib/format'
import { t } from '../../i18n'
import { toast } from '../../ui/overlays'

export function ShareCreatedCard({
  createdUrl,
  onReset,
}: {
  createdUrl: string
  onReset: () => void
}) {
  const [copied, setCopied] = useState(false)

  const handleCopyLink = () => {
    copy(createdUrl).then((ok) => {
      if (ok) {
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
        toast.ok(t('Link copied to clipboard!'))
      }
    })
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div className="alert alert-ok" style={{ fontWeight: 500, alignItems: 'center', marginBottom: 0 }}>
        <ShieldCheck size={20} />
        <span>{t('Secure Share Link Created and Encrypted!')}</span>
      </div>

      <div>
        <label className="label" style={{ display: 'block' }}>
          {t('Shareable Link')}
        </label>
        <div style={{ display: 'flex', gap: 8 }}>
          <input
            type="text"
            readOnly
            value={createdUrl}
            className="mono"
            style={{
              flex: 1,
              fontSize: 13,
              padding: '8px 10px',
              background: 'var(--surface-2)',
            }}
          />
          <button
            className="btn btn-primary"
            onClick={handleCopyLink}
          >
            {copied ? <Check size={15} /> : <Copy size={15} />}
            <span>{copied ? t('Copied!') : t('Copy')}</span>
          </button>
        </div>
      </div>

      <div className="surface-box" style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.5 }}>
        <strong style={{ color: 'var(--text)', display: 'block', marginBottom: 4 }}>
          <Lock size={13} style={{ display: 'inline', marginRight: 4, verticalAlign: 'text-bottom' }} />
          {t('Client-Side Encryption')}
        </strong>
        {t(
          'The decryption key stays in the #k= URL fragment, so the browser never sends it to the server.'
        )}
      </div>

      <button
        className="btn btn-subtle"
        onClick={onReset}
        style={{ width: '100%', justifyContent: 'center' }}
      >
        {t('Create Another Secret Link')}
      </button>
    </div>
  )
}
