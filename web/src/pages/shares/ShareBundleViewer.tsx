import { useState } from 'react'
import { Check, Copy, Eye, EyeOff } from 'lucide-react'
import { formatBundleAsEnv, formatBundleAsJson, type SecretBundlePayload } from '../../lib/env'
import { copy } from '../../lib/format'
import { t } from '../../i18n'
import { toast } from '../../ui/overlays'

export function ShareBundleViewer({ bundle }: { bundle: SecretBundlePayload }) {
  const [revealedKeys, setRevealedKeys] = useState<Record<string, boolean>>({})
  const [copiedKeys, setCopiedKeys] = useState<Record<string, boolean>>({})
  const [revealAllBundle, setRevealAllBundle] = useState(false)
  const [copiedAllEnv, setCopiedAllEnv] = useState(false)
  const [copiedAllJson, setCopiedAllJson] = useState(false)

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
    const envText = formatBundleAsEnv(bundle.secrets)
    copy(envText).then((ok) => {
      if (ok) {
        setCopiedAllEnv(true)
        toast.ok(t('All {0} secrets copied as .env', bundle.secrets.length))
        setTimeout(() => setCopiedAllEnv(false), 2000)
      }
    })
  }

  const handleCopyBundleAsJson = () => {
    const jsonText = formatBundleAsJson(bundle.secrets)
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
    const map: Record<string, boolean> = {}
    bundle.secrets.forEach((s) => {
      map[s.key] = next
    })
    setRevealedKeys(map)
  }

  return (
    <div>
      {/* Master Action Toolbar */}
      <div
        className="surface-box"
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 8,
          flexWrap: 'wrap',
          padding: '8px 12px',
          marginBottom: 16,
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
          maxHeight: 440,
          overflowY: 'auto',
          marginBottom: 18,
          paddingRight: 4,
        }}
      >
        {bundle.secrets.map((item, idx) => {
          const isRevealed = revealAllBundle || revealedKeys[item.key]
          const isCopied = copiedKeys[item.key]
          return (
            <div key={item.key || idx} className="bundle-item-card">
              <div className="bundle-item-head">
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <strong className="mono" style={{ fontSize: 13 }}>
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
                    className="btn btn-xs btn-ghost"
                    onClick={() => toggleRevealBundleItem(item.key)}
                    title={isRevealed ? t('Mask value') : t('Reveal value')}
                  >
                    {isRevealed ? <EyeOff size={12} /> : <Eye size={12} />}
                  </button>
                  <button
                    type="button"
                    className="btn btn-xs btn-primary"
                    onClick={() => handleCopyBundleItem(item.key, item.value)}
                    title={t('Copy {0}', item.key)}
                  >
                    {isCopied ? <Check size={12} /> : <Copy size={12} />}
                    <span>{isCopied ? t('Copied!') : t('Copy')}</span>
                  </button>
                </div>
              </div>

              {isRevealed ? (
                <pre className="bundle-item-body">
                  {item.value}
                </pre>
              ) : (
                <div
                  className="bundle-item-body muted"
                  style={{ letterSpacing: 2, userSelect: 'none' }}
                >
                  ••••••••••••••••••••••••
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
