import { useState } from 'react'
import { Check, Copy, Eye, EyeOff, Lock } from 'lucide-react'
import { copy } from '../../lib/format'
import { t } from '../../i18n'
import { toast } from '../../ui/overlays'

export function ShareSingleViewer({ secretText }: { secretText: string }) {
  const [showSingleText, setShowSingleText] = useState(false)
  const [copiedSingle, setCopiedSingle] = useState(false)

  const handleCopySingle = () => {
    copy(secretText).then((ok) => {
      if (ok) {
        setCopiedSingle(true)
        toast.ok(t('Secret copied to clipboard!'))
        setTimeout(() => setCopiedSingle(false), 2000)
      }
    })
  }

  return (
    <div>
      <div className="bundle-item-card" style={{ marginBottom: 16 }}>
        <div className="bundle-item-head">
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 13, fontWeight: 500 }}>
            <Lock size={13} style={{ color: 'var(--accent)' }} />
            <span>{t('Encrypted Secret Payload')}</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span className="muted small mono">{secretText.length} {t('chars')}</span>
            <button
              type="button"
              className="btn btn-ghost btn-xs"
              onClick={() => setShowSingleText(!showSingleText)}
            >
              {showSingleText ? <EyeOff size={12} /> : <Eye size={12} />}
              <span>{showSingleText ? t('Mask') : t('Reveal')}</span>
            </button>
          </div>
        </div>

        {showSingleText ? (
          <textarea
            readOnly
            value={secretText}
            rows={Math.min(10, Math.max(4, secretText.split('\n').length))}
            className="mono"
            style={{
              width: '100%',
              fontSize: 13,
              padding: 12,
              background: 'var(--surface-2)',
              border: 0,
              borderRadius: 0,
              boxShadow: 'none',
              lineHeight: 1.5,
            }}
          />
        ) : (
          <div
            className="mono muted"
            style={{
              padding: '24px 16px',
              textAlign: 'center',
              letterSpacing: 4,
              fontSize: 16,
              userSelect: 'none',
            }}
          >
            ••••••••••••••••••••••••••••••••
          </div>
        )}
      </div>

      <button
        className="btn btn-primary"
        onClick={handleCopySingle}
        style={{
          width: '100%',
          height: 40,
          fontSize: 14,
          fontWeight: 600,
          justifyContent: 'center',
        }}
      >
        {copiedSingle ? <Check size={17} /> : <Copy size={17} />}
        <span>{copiedSingle ? t('Secret Copied to Clipboard!') : t('Copy Secret to Clipboard')}</span>
      </button>
    </div>
  )
}
