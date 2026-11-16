import { useState } from 'react'
import { Eye, EyeOff, Copy, History, RotateCcw, ShieldCheck } from 'lucide-react'
import { t } from '../../i18n'
import { api, enc, type Secret, type SecretVersionList } from '../../lib/api'
import { invalidate, useResource } from '../../lib/store'
import { ago, dateTime, copy } from '../../lib/format'
import { Spinner, Tag } from '../../ui/common'
import { Modal, confirm, toast } from '../../ui/overlays'

export function SecretVersionModal({
  projectId,
  envSlug,
  secret,
  onClose,
}: {
  projectId: string
  envSlug: string
  secret: Secret
  onClose: () => void
}) {
  const { data, error, loading } = useResource<SecretVersionList>(
    `/projects/${enc(projectId)}/environments/${enc(envSlug)}/secrets/${enc(secret.id)}/versions?reveal=1`
  )
  const [busy, setBusy] = useState<number | null>(null)
  const [revealed, setRevealed] = useState<Record<number, boolean>>({})
  const [selectedVerNum, setSelectedVerNum] = useState<number | null>(null)
  const [revealAll, setRevealAll] = useState(false)

  const items = data?.items || []
  const activeSelectedNum = selectedVerNum ?? (items[0]?.version ?? secret.version)
  const selectedVersion = items.find((v) => v.version === activeSelectedNum) || items[0]

  const toggleReveal = (v: number) => {
    setRevealed((prev) => ({ ...prev, [v]: !prev[v] }))
  }

  const toggleRevealAll = () => {
    const next = !revealAll
    setRevealAll(next)
    const map: Record<number, boolean> = {}
    items.forEach((item) => {
      map[item.version] = next
    })
    setRevealed(map)
  }

  const rollback = async (version: number) => {
    if (
      !(await confirm({
        title: t('Rollback to version {0}?', version),
        body: t('This will create a new version with the historic value.'),
        confirm: t('Rollback'),
      }))
    ) {
      return
    }
    setBusy(version)
    try {
      await api.post(`/projects/${enc(projectId)}/environments/${enc(envSlug)}/secrets/${enc(secret.id)}/rollback`, { version })
      toast.ok(t('Rolled back successfully'))
      invalidate('/projects')
      onClose()
    } catch (err) {
      toast.err(err)
    } finally {
      setBusy(null)
    }
  }

  return (
    <Modal
      title={t('Version History: {0}', secret.key)}
      wide="xl"
      allowFullscreen
      onClose={onClose}
      footer={
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
          <span className="muted small">
            {t('{0} total version(s) recorded in project vault', items.length)}
          </span>
          <button type="button" className="btn btn-ghost" onClick={onClose}>{t('Close')}</button>
        </div>
      }
    >
      <div className="modal-two-col">
        {/* Left Column: Version Timeline */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 2 }}>
            <span style={{ fontSize: 12, fontWeight: 600 }}>{t('Audit Timeline')}</span>
            <button
              type="button"
              className="btn btn-ghost btn-xs"
              onClick={toggleRevealAll}
            >
              {revealAll ? <EyeOff size={12} /> : <Eye size={12} />}
              {revealAll ? t('Hide All Values') : t('Reveal All Values')}
            </button>
          </div>

          {loading && <div className="center" style={{ padding: 24 }}><Spinner /></div>}
          {error && <div className="alert alert-bad">{error.message}</div>}

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: '60vh', overflowY: 'auto' }}>
            {items.map((v) => {
              const isCurrent = v.version === secret.version
              const isSelected = selectedVersion && selectedVersion.version === v.version
              const isValRevealed = revealAll || !!revealed[v.version]

              return (
                <div
                  key={v.id}
                  onClick={() => setSelectedVerNum(v.version)}
                  style={{
                    border: isSelected ? '1px solid var(--accent)' : '1px solid var(--border)',
                    borderRadius: 8,
                    padding: '10px 12px',
                    background: isSelected ? 'var(--surface-2)' : 'var(--bg)',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <strong className="mono" style={{ fontSize: 13 }}>v{v.version}</strong>
                      {isCurrent && <Tag tone="accent">{t('Current')}</Tag>}
                      {isSelected && !isCurrent && <Tag tone="good">{t('Selected')}</Tag>}
                    </div>
                    <span className="muted small" style={{ fontSize: 11 }}>{ago(v.created_at)}</span>
                  </div>

                  <div className="muted small" style={{ fontSize: 11, marginBottom: 6 }}>
                    {v.created_by ? t('by {0} • {1}', v.created_by, dateTime(v.created_at)) : dateTime(v.created_at)}
                  </div>

                  {v.comment && (
                    <div style={{ fontSize: 12, marginBottom: 6, color: 'var(--text)' }}>
                      {v.comment}
                    </div>
                  )}

                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 4 }}>
                    <span className="mono muted" style={{ fontSize: 12 }}>
                      {isValRevealed ? (v.value.length > 28 ? v.value.substring(0, 28) + '...' : v.value) : '••••••••••••••••'}
                    </span>
                    <div style={{ display: 'flex', gap: 4 }} onClick={(e) => e.stopPropagation()}>
                      <button
                        type="button"
                        className="icon-btn icon-btn-xs"
                        title={isValRevealed ? t('Hide') : t('Reveal')}
                        onClick={() => toggleReveal(v.version)}
                      >
                        {isValRevealed ? <EyeOff size={12} /> : <Eye size={12} />}
                      </button>
                      <button
                        type="button"
                        className="icon-btn icon-btn-xs"
                        title={t('Copy value')}
                        onClick={() => {
                          copy(v.value).then((ok) => {
                            if (ok) toast.ok(t('v{0} value copied to clipboard', v.version))
                          })
                        }}
                      >
                        <Copy size={12} />
                      </button>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Right Column: Version Inspector & Diff / Rollback */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {selectedVersion ? (
            <>
              <div className="surface-box" style={{ padding: '14px 16px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <History size={16} style={{ color: 'var(--accent)' }} />
                    <span style={{ fontSize: 13, fontWeight: 600 }}>
                      {t('Version Inspector: v{0}', selectedVersion.version)}
                    </span>
                  </div>
                  {selectedVersion.version === secret.version ? (
                    <Tag tone="accent">{t('Active in Environment')}</Tag>
                  ) : (
                    <Tag>{t('Historical Snapshot')}</Tag>
                  )}
                </div>

                <div className="grid-2" style={{ fontSize: 12, marginBottom: 12 }}>
                  <div>
                    <span className="muted small" style={{ display: 'block' }}>{t('Created Date')}</span>
                    <strong>{dateTime(selectedVersion.created_at)}</strong>
                  </div>
                  <div>
                    <span className="muted small" style={{ display: 'block' }}>{t('Recorded By')}</span>
                    <strong>{selectedVersion.created_by || t('System')}</strong>
                  </div>
                </div>

                {selectedVersion.comment && (
                  <div style={{ marginBottom: 12, fontSize: 12 }}>
                    <span className="muted small" style={{ display: 'block', marginBottom: 2 }}>{t('Commit Note')}</span>
                    <div style={{ padding: '6px 8px', background: 'var(--bg)', borderRadius: 4, border: '1px solid var(--border)' }}>
                      {selectedVersion.comment}
                    </div>
                  </div>
                )}

                <div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span className="muted small">{t('Stored Value')}</span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <button
                        type="button"
                        className="btn btn-ghost btn-xs"
                        onClick={() => toggleReveal(selectedVersion.version)}
                      >
                        {revealAll || revealed[selectedVersion.version] ? (
                          <><EyeOff size={11} /> {t('Mask')}</>
                        ) : (
                          <><Eye size={11} /> {t('Reveal')}</>
                        )}
                      </button>
                      <button
                        type="button"
                        className="btn btn-ghost btn-xs"
                        onClick={() => {
                          copy(selectedVersion.value).then((ok) => {
                            if (ok) toast.ok(t('v{0} value copied to clipboard', selectedVersion.version))
                          })
                        }}
                      >
                        <Copy size={11} /> {t('Copy')}
                      </button>
                    </div>
                  </div>

                  <div
                    className="mono"
                    style={{
                      padding: '10px 12px',
                      borderRadius: 6,
                      background: 'var(--bg)',
                      border: '1px solid var(--border)',
                      fontSize: 12,
                      maxHeight: 180,
                      overflowY: 'auto',
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-all',
                    }}
                  >
                    {revealAll || revealed[selectedVersion.version] ? selectedVersion.value : '••••••••••••••••••••••••••••••••'}
                  </div>
                </div>

                {selectedVersion.version !== secret.version && (
                  <div style={{ marginTop: 16, paddingTop: 12, borderTop: '1px solid var(--border)' }}>
                    <button
                      type="button"
                      className="btn btn-primary"
                      style={{ width: '100%', justifyContent: 'center' }}
                      onClick={() => rollback(selectedVersion.version)}
                      disabled={busy !== null}
                    >
                      <RotateCcw size={13} />
                      {busy === selectedVersion.version ? <Spinner /> : t('Restore & Rollback to v{0}', selectedVersion.version)}
                    </button>
                    <span className="muted small" style={{ display: 'block', textAlign: 'center', marginTop: 4 }}>
                      {t('Creates a new version v{0} restoring this historic secret value.', (items[0]?.version || secret.version) + 1)}
                    </span>
                  </div>
                )}
              </div>

              <div className="surface-box" style={{ fontSize: 11 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                  <ShieldCheck size={14} className="tone-ok" />
                  <strong>{t('Version History')}</strong>
                </div>
                <p className="muted small" style={{ margin: 0, lineHeight: 1.4 }}>
                  {t('Previous versions stay read-only and encrypted in history.')}
                </p>
              </div>
            </>
          ) : (
            <div className="center" style={{ padding: 40 }}>
              <p className="muted small">{t('Select a version to inspect details.')}</p>
            </div>
          )}
        </div>
      </div>
    </Modal>
  )
}
