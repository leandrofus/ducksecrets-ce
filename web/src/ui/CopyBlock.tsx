import { t } from '../i18n'
import { useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { copy } from '../lib/format'
import { Tag } from './common'
import { toast } from './overlays'

export function CopyBlock({
  title,
  subtitle,
  code,
  badge,
}: {
  title: string
  subtitle?: string
  code: string
  badge?: string
}) {
  const [copied, setCopied] = useState(false)

  const handleCopy = () => {
    copy(code).then((ok) => {
      if (!ok) return
      setCopied(true)
      toast.ok(t('Copied to clipboard'))
      setTimeout(() => setCopied(false), 1800)
    })
  }

  return (
    <div className="surface-card">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, marginBottom: 8 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <strong>{title}</strong>
            {badge && <Tag tone="muted">{badge}</Tag>}
          </div>
          {subtitle && (
            <div className="muted small" style={{ marginTop: 2 }}>
              {subtitle}
            </div>
          )}
        </div>
        <button type="button" className="btn btn-sm btn-ghost" onClick={handleCopy}>
          {copied ? <Check size={14} /> : <Copy size={14} />} {copied ? t('Copied') : t('Copy')}
        </button>
      </div>
      <pre className="mono code-block">{code}</pre>
    </div>
  )
}
