import { useState, useEffect, useRef } from 'react'
import { Download, Check, Copy, Sparkles } from 'lucide-react'
import { t } from '../../i18n'
import { enc, triggerUnauthorized } from '../../lib/api'
import { copy } from '../../lib/format'
import { Spinner } from '../../ui/common'
import { Modal, toast } from '../../ui/overlays'

export function ExportModal({
  projectId,
  envSlug,
  onClose,
}: {
  projectId: string
  envSlug: string
  onClose: () => void
}) {
  const [format, setFormat] = useState<'dotenv' | 'json' | 'yaml'>('dotenv')
  const [content, setContent] = useState<string>('')
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState(false)
  const abortRef = useRef<AbortController | null>(null)

  const fetchExport = (fmt: 'dotenv' | 'json' | 'yaml') => {
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller

    setFormat(fmt)
    setLoading(true)
    fetch(`/api/v1/projects/${enc(projectId)}/environments/${enc(envSlug)}/secrets/export?format=${fmt}`, {
      signal: controller.signal,
      credentials: 'same-origin',
    })
      .then(async (res) => {
        if (res.status === 401) {
          triggerUnauthorized()
        }
        if (!res.ok) throw new Error(res.statusText)
        const text = await res.text()
        if (!controller.signal.aborted) {
          setContent(text)
        }
      })
      .catch((err) => {
        if (err?.name === 'AbortError') return
        toast.err(err)
      })
      .finally(() => {
        if (abortRef.current === controller) {
          setLoading(false)
        }
      })
  }

  useEffect(() => {
    fetchExport('dotenv')
    return () => abortRef.current?.abort()
  }, [])

  const copyExport = () => {
    copy(content).then((ok) => {
      if (ok) {
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
        toast.ok(t('Export copied to clipboard'))
      }
    })
  }

  const download = () => {
    const ext = format === 'json' ? 'json' : format === 'yaml' ? 'yaml' : 'env'
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${envSlug}.${ext}`
    a.click()
    URL.revokeObjectURL(url)
  }

  const lineCount = content ? content.trim().split('\n').length : 0

  return (
    <Modal
      title={t('Export Secrets: {0}', envSlug)}
      wide="xl"
      allowFullscreen
      onClose={onClose}
      footer={
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
          <span className="muted small">
            {lineCount} {t('entries')} • {content.length} {t('characters')}
          </span>
          <div style={{ display: 'flex', gap: 8 }}>
            <button type="button" className="btn btn-ghost" onClick={onClose}>{t('Close')}</button>
            <button type="button" className="btn btn-primary" onClick={download} disabled={loading || !content}>
              <Download size={13} /> {t('Download {0}', format === 'dotenv' ? '.env' : format.toUpperCase())}
            </button>
          </div>
        </div>
      }
    >
      <div className="modal-two-col">
        {/* Left Column: Format Picker & Export Options */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div className="surface-box">
            <span style={{ fontSize: 12, fontWeight: 600, display: 'block', marginBottom: 8 }}>
              {t('Output Format')}
            </span>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {[
                { id: 'dotenv' as const, label: '.env (Key=Value)', desc: t('Ideal for Docker, local process runtimes, Node.js, Python, and Go') },
                { id: 'json' as const, label: 'JSON Object', desc: t('Structured key-value object for cloud configurations and CI pipelines') },
                { id: 'yaml' as const, label: 'YAML Format', desc: t('Kubernetes ConfigMap / Secret format and Ansible automation') },
              ].map((item) => (
                <label
                  key={item.id}
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: 10,
                    padding: '8px 10px',
                    borderRadius: 6,
                    border: format === item.id ? '1px solid var(--accent)' : '1px solid var(--border)',
                    background: format === item.id ? 'var(--bg)' : 'transparent',
                    cursor: 'pointer',
                  }}
                >
                  <input
                    type="radio"
                    name="export-format"
                    checked={format === item.id}
                    onChange={() => fetchExport(item.id)}
                    style={{ marginTop: 2 }}
                  />
                  <div>
                    <strong style={{ fontSize: 13, display: 'block' }}>{item.label}</strong>
                    <span className="muted small">{item.desc}</span>
                  </div>
                </label>
              ))}
            </div>
          </div>

          <div className="surface-box">
            <span style={{ fontSize: 12, fontWeight: 600, display: 'block', marginBottom: 6 }}>
              {t('Actions')}
            </span>
            <div style={{ display: 'flex', gap: 8 }}>
              <button
                type="button"
                className="btn btn-sm btn-subtle"
                style={{ flex: 1, justifyContent: 'center' }}
                onClick={copyExport}
                disabled={loading || !content}
              >
                {copied ? <Check size={13} /> : <Copy size={13} />}
                {copied ? t('Copied!') : t('Copy to Clipboard')}
              </button>
              <button
                type="button"
                className="btn btn-sm btn-subtle"
                style={{ flex: 1, justifyContent: 'center' }}
                onClick={download}
                disabled={loading || !content}
              >
                <Download size={13} />
                {t('Download File')}
              </button>
            </div>
          </div>

          {/* Interpolation Resolution Info Card */}
          <div className="surface-box" style={{ fontSize: 11 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
              <Sparkles size={14} style={{ color: 'var(--accent)' }} />
              <strong>{t('Full Interpolation Applied')}</strong>
            </div>
            <p className="muted small" style={{ margin: 0, lineHeight: 1.4 }}>
              {t('All variable references (${VAR}) have been dynamically resolved into concrete values for the {0} environment.', envSlug)}
            </p>
          </div>
        </div>

        {/* Right Column: Code & Content Preview */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: 12, fontWeight: 600 }}>{t('Export Preview')}</span>
            <span className="muted mono small">
              {format === 'dotenv' ? '.env' : format === 'json' ? '.json' : '.yaml'}
            </span>
          </div>

          {loading ? (
            <div className="center" style={{ height: 260, border: '1px solid var(--border)', borderRadius: 8, background: 'var(--bg)' }}>
              <Spinner />
            </div>
          ) : (
            <textarea
              readOnly
              className="mono"
              rows={16}
              value={content}
              style={{
                width: '100%',
                fontSize: 12,
                lineHeight: 1.4,
                background: 'var(--bg)',
                borderRadius: 8,
                resize: 'vertical',
                minHeight: 280,
              }}
            />
          )}
        </div>
      </div>
    </Modal>
  )
}
