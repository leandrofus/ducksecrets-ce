import { useMemo, useState, useEffect, useRef } from 'react'
import { Eye, EyeOff, Sparkles, Copy, KeyRound, ShieldCheck } from 'lucide-react'
import { t } from '../../i18n'
import { api, enc, type Secret } from '../../lib/api'
import { invalidate } from '../../lib/store'
import { copy } from '../../lib/format'
import { Spinner, Tag } from '../../ui/common'
import { Modal, toast } from '../../ui/overlays'
import { Field } from '../../ui/Field'

export function SecretModal({
  projectId,
  envSlug,
  initial,
  existingSecrets = [],
  onClose,
}: {
  projectId: string
  envSlug: string
  initial?: Secret
  existingSecrets?: Secret[]
  onClose: () => void
}) {
  const [key, setKey] = useState(initial?.key ?? '')
  const [value, setValue] = useState(initial?.raw_value || (initial?.value && initial?.value !== '••••••••' ? initial.value : '') || '')
  const [comment, setComment] = useState(initial?.comment ?? '')
  const [path, setPath] = useState(initial?.path ?? '/')
  const [showVal, setShowVal] = useState(true)
  const [busy, setBusy] = useState(false)
  const [loadingInitial, setLoadingInitial] = useState(false)
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  useEffect(() => {
    if (initial && (!value || value === '••••••••')) {
      setLoadingInitial(true)
      api
        .get<Secret>(`/projects/${enc(projectId)}/environments/${enc(envSlug)}/secrets/${enc(initial.id)}`)
        .then((res) => {
          setValue(res.raw_value || res.value || '')
        })
        .catch(toast.err)
        .finally(() => setLoadingInitial(false))
    }
  }, [initial?.id])

  const availableKeys = useMemo(() => {
    return existingSecrets
      .filter((s) => s.id !== initial?.id && s.key !== key)
      .map((s) => s.key)
  }, [existingSecrets, initial?.id, key])

  const insertVariable = (varName: string) => {
    const token = `\${${varName}}`
    const el = textareaRef.current
    if (!el) {
      setValue((prev) => prev + token)
      return
    }
    const start = el.selectionStart
    const end = el.selectionEnd
    const next = value.substring(0, start) + token + value.substring(end)
    setValue(next)
    setTimeout(() => {
      el.focus()
      el.setSelectionRange(start + token.length, start + token.length)
    }, 0)
  }

  const refMatches = useMemo(() => {
    const matches = value.match(/\$\{([a-zA-Z0-9_]+)\}|\{\{([a-zA-Z0-9_]+)\}\}/g) || []
    return Array.from(new Set(matches.map((m) => m.replace(/[\$\{\}]/g, ''))))
  }, [value])

  const resolvedPreview = useMemo(() => {
    if (refMatches.length === 0) return null
    let res = value
    for (const varName of refMatches) {
      const found = existingSecrets.find((s) => s.key === varName)
      const repl = found
        ? found.value && found.value !== '••••••••'
          ? found.value
          : `[${varName}]`
        : `[MISSING: ${varName}]`
      res = res.replaceAll(`\${${varName}}`, repl).replaceAll(`{{${varName}}}`, repl)
    }
    return res
  }, [value, refMatches, existingSecrets])

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    try {
      if (initial) {
        const patch: Record<string, string> = { comment }
        if (value) patch.value = value
        await api.patch(`/projects/${enc(projectId)}/environments/${enc(envSlug)}/secrets/${enc(initial.id)}`, patch)
        toast.ok(t('Secret updated (new version recorded)'))
      } else {
        await api.post(`/projects/${enc(projectId)}/environments/${enc(envSlug)}/secrets`, {
          key: key.trim(),
          value,
          comment,
          path,
        })
        toast.ok(t('Secret encrypted and created'))
      }
      invalidate('/projects')
      onClose()
    } catch (err) {
      toast.err(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      title={initial ? t('Edit Secret: {0}', initial.key) : t('Add Secret to {0}', envSlug)}
      wide="xl"
      allowFullscreen
      onClose={onClose}
      footer={
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, width: '100%' }}>
          <button type="button" className="btn btn-ghost" onClick={onClose}>{t('Cancel')}</button>
          <button type="submit" form="secret-form" className="btn btn-primary" disabled={busy}>
            {busy ? <Spinner /> : initial ? t('Update Secret') : t('Encrypt & Save')}
          </button>
        </div>
      }
    >
      <form id="secret-form" onSubmit={submit}>
        <div className="modal-two-col">
          {/* Left Column: Form Inputs & Primary Editor */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {!initial && (
              <Field required label={t('Secret Key')} help={t('Environment variable name (e.g. DATABASE_URL, STRIPE_SECRET_KEY)')}>
                <input
                  required
                  autoFocus
                  className="mono"
                  value={key}
                  onChange={(e) => setKey(e.target.value.toUpperCase())}
                  placeholder="KEY_NAME"
                />
              </Field>
            )}

            <Field
              required={!initial}
              optional={!!initial}
              label={
                <div style={{ display: 'flex', justifyContent: 'space-between', width: '100%' }}>
                  <span>{t('Value / Template')} {loadingInitial && <Spinner />}</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span className="muted small mono">{value.length} {t('chars')}</span>
                    <button
                      type="button"
                      className="btn btn-ghost btn-xs"
                      onClick={() => setShowVal(!showVal)}
                    >
                      {showVal ? <EyeOff size={12} /> : <Eye size={12} />} {showVal ? t('Hide') : t('Show')}
                    </button>
                  </div>
                </div>
              }
              help={initial ? t('Leave empty to keep existing value and only update comment') : undefined}
            >
              <textarea
                ref={textareaRef}
                required={!initial}
                rows={9}
                className="mono"
                style={{
                  fontSize: 13,
                  lineHeight: 1.5,
                  minHeight: 180,
                  resize: 'vertical',
                  ...(showVal ? {} : ({ WebkitTextSecurity: 'disc' } as React.CSSProperties)),
                }}
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder={initial ? (loadingInitial ? t('Loading decrypted value...') : t('Enter new value or template...')) : t('Secret value or composite template (e.g. postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}/${DB_NAME})')}
              />
            </Field>

            <div className="grid-2">
              <Field optional label={t('Path / Folder')} help={initial ? t('Path cannot be moved when editing') : t('Default root path /')}>
                <input value={path} disabled={!!initial} onChange={(e) => setPath(e.target.value)} placeholder="/" />
              </Field>
              <Field optional label={t('Comment')} help={t('Optional note')}>
                <input value={comment} onChange={(e) => setComment(e.target.value)} placeholder="e.g. Production RDS connection string" />
              </Field>
            </div>
          </div>

          {/* Right Column: Context, Intelligence & Interpolation Inspector */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {/* Live Resolved Preview Card */}
            <div className="surface-box">
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                <span style={{ fontSize: 12, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Sparkles size={14} style={{ color: 'var(--accent)' }} />
                  {t('Live Resolved Preview')}
                </span>
                {resolvedPreview && (
                  <button
                    type="button"
                    className="btn btn-ghost btn-xs"
                    onClick={() => {
                      copy(resolvedPreview).then((ok) => {
                        if (ok) toast.ok(t('Resolved preview copied to clipboard'))
                      })
                    }}
                    title={t('Copy resolved preview')}
                  >
                    <Copy size={11} /> {t('Copy')}
                  </button>
                )}
              </div>

              {refMatches.length > 0 ? (
                <div>
                  <div
                    className="mono"
                    style={{
                      fontSize: 12,
                      padding: '8px 10px',
                      background: 'var(--bg)',
                      borderRadius: 6,
                      border: '1px solid var(--border)',
                      wordBreak: 'break-all',
                      maxHeight: 120,
                      overflowY: 'auto',
                    }}
                  >
                    {resolvedPreview}
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap', marginTop: 8 }}>
                    <span className="muted small" style={{ fontSize: 11 }}>{t('Referenced:')}</span>
                    {refMatches.map((varName) => {
                      const exists = availableKeys.includes(varName)
                      return (
                        <Tag key={varName} tone={exists ? 'good' : 'bad'} mono>
                          {exists ? `✓ ${varName}` : `⚠ ${varName} (${t('missing')})`}
                        </Tag>
                      )
                    })}
                  </div>
                </div>
              ) : (
                <p className="muted small" style={{ margin: 0, fontSize: 12, lineHeight: 1.4 }}>
                  {t('No variable references detected. Use ${KEY} or {{KEY}} to dynamically reference other secrets.')}
                </p>
              )}
            </div>

            {/* Sibling Variables Palette */}
            <div className="surface-box">
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{ fontSize: 12, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <KeyRound size={13} style={{ color: 'var(--accent)' }} />
                  {t('Available Environment Secrets')}
                </span>
                <span className="muted small mono" style={{ fontSize: 11 }}>{availableKeys.length}</span>
              </div>
              <p className="muted small" style={{ margin: '0 0 8px 0', fontSize: 11, lineHeight: 1.4 }}>
                {t('Click any variable below to insert ${VARIABLE} at cursor position in the editor:')}
              </p>
              {availableKeys.length > 0 ? (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, maxHeight: 160, overflowY: 'auto', padding: '2px 0' }}>
                  {availableKeys.map((k) => (
                    <button
                      key={k}
                      type="button"
                      className="btn btn-ghost btn-xs mono"
                      style={{
                        border: '1px dashed var(--border)',
                        background: 'var(--bg)',
                      }}
                      onClick={() => insertVariable(k)}
                      title={t('Click to insert ${0}', `\${${k}}`)}
                    >
                      + {`\${${k}}`}
                    </button>
                  ))}
                </div>
              ) : (
                <p className="muted small" style={{ margin: 0, fontSize: 11 }}>
                  {t('No other secrets available in {0} to reference yet.', envSlug)}
                </p>
              )}
            </div>

            {/* Storage & Security Meta Card */}
            <div className="surface-box" style={{ fontSize: 11 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                <ShieldCheck size={14} className="tone-ok" />
                <strong>{t('Project Encryption')}</strong>
              </div>
              <p className="muted small" style={{ margin: 0, lineHeight: 1.4 }}>
                {t('Secrets are encrypted with a per-project key and decrypted only when read or exported.')}
              </p>
            </div>
          </div>
        </div>
      </form>
    </Modal>
  )
}
