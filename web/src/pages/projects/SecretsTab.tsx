import { useMemo, useState, useEffect } from 'react'
import {
  Folder,
  Plus,
  Search,
  X,
  Trash2,
  Pencil,
  Copy,
  Eye,
  EyeOff,
  History,
  Download,
  Upload,
  Layers,
  Flame,
  RefreshCw,
  Code,
} from 'lucide-react'
import { t } from '../../i18n'
import { api, enc, type Environment, type Secret, type SecretList, type ShareCreated } from '../../lib/api'
import { encryptShare } from '../../lib/crypto'
import { invalidate } from '../../lib/store'
import { ago, dateTime, copy } from '../../lib/format'
import type { MenuEntry } from '../../ui/ContextMenu'
import { DataTable, Empty, Spinner, Tabs } from '../../ui/common'
import { confirm, openDialog, toast } from '../../ui/overlays'
import { EnvironmentModal } from './ProjectModals'
import { SecretModal } from './SecretModal'
import { SecretVersionModal } from './SecretVersionModal'
import { ExportModal } from './ExportModal'
import { ImportModal } from './ImportModal'
import { ShareBundleModal } from './ShareBundleModal'
import { RotationPolicyModal } from './RotationTab'

export function SecretsTab({
  projectId,
  envSlug,
  envs,
  onSelectEnv,
  revealAll,
  onToggleRevealAll,
  secretsData,
  sErr,
}: {
  projectId: string
  envSlug: string
  envs: Environment[]
  onSelectEnv: (slug: string) => void
  revealAll: boolean
  onToggleRevealAll: () => void
  secretsData?: SecretList
  sErr?: Error | null
}) {
  const [q, setQ] = useState('')
  const [pathFilter, setPathFilter] = useState<string>('')
  const [selectedSecretIds, setSelectedSecretIds] = useState<Set<string>>(new Set())

  useEffect(() => {
    setSelectedSecretIds(new Set())
    setPathFilter('')
  }, [projectId, envSlug])

  const availablePaths = useMemo(() => {
    const s = new Set<string>()
    for (const item of secretsData?.items || []) {
      s.add(item.path || '/')
    }
    return Array.from(s).sort()
  }, [secretsData?.items])

  const rows = useMemo(() => {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean)
    return (secretsData?.items || []).filter((s) => {
      const sPath = s.path || '/'
      if (pathFilter && sPath !== pathFilter) return false
      return words.every((w) => `${s.key} ${s.comment} ${sPath}`.toLowerCase().includes(w))
    })
  }, [secretsData?.items, q, pathFilter])

  const copyToClipboard = (text: string, label: string) => {
    copy(text).then((ok) => {
      if (ok) {
        toast.ok(t('{0} copied to clipboard', label))
      } else {
        toast.err(t('Could not copy to clipboard'))
      }
    })
  }

  const secretActions = (s: Secret): MenuEntry[] => [
    { header: s.key },
    { label: t('Copy Key'), icon: <Copy size={14} />, onClick: () => copyToClipboard(s.key, s.key) },
    {
      label: t('Copy Value'),
      icon: <Copy size={14} />,
      onClick: () => {
        if (s.value === '••••••••') {
          api.get<Secret>(`/projects/${enc(projectId)}/environments/${enc(envSlug)}/secrets/${enc(s.id)}`).then((res) => {
            copyToClipboard(res.value, s.key)
          }, toast.err)
        } else {
          copyToClipboard(s.value, s.key)
        }
      },
    },
    { label: t('Edit…'), icon: <Pencil size={14} />, onClick: () => openDialog((c) => <SecretModal projectId={projectId} envSlug={envSlug} initial={s} existingSecrets={secretsData?.items || []} onClose={c} />) },
    { label: t('Share as Bundle…'), icon: <Flame size={14} />, onClick: () => openDialog((c) => <ShareBundleModal projectId={projectId} envSlug={envSlug} allSecrets={secretsData?.items || []} initialSelectedIds={new Set([s.id])} onClose={c} />) },
    { label: t('Version History…'), icon: <History size={14} />, onClick: () => openDialog((c) => <SecretVersionModal projectId={projectId} envSlug={envSlug} secret={s} onClose={c} />) },
    { label: t('Auto-Rotation…'), icon: <RefreshCw size={14} />, onClick: () => openDialog((c) => <RotationPolicyModal projectId={projectId} envSlug={envSlug} secret={s} onClose={c} />) },
    'sep',
    { label: t('Delete'), icon: <Trash2 size={14} />, danger: true, onClick: () => removeSecret(projectId, envSlug, s) },
  ]

  return (
    <>
      {envs.length > 0 && (
        <div className="vault-subnav">
          <Tabs
            tabs={envs.map((e) => ({ id: e.slug, label: e.name }))}
            active={envSlug}
            onChange={onSelectEnv}
          />
          <button className="btn btn-sm btn-ghost" onClick={() => openDialog((c) => <EnvironmentModal projectId={projectId} onClose={c} />)}>
            <Plus size={13} /> {t('Environment')}
          </button>
        </div>
      )}

      <div className="vault-toolbar">
        <div className="vault-toolbar-left">
          <div className="search">
            <Search size={14} />
            <input placeholder={t('Filter secrets…')} value={q} onChange={(e) => setQ(e.currentTarget.value)} />
            {q && <button className="icon-btn" onClick={() => setQ('')}><X size={13} /></button>}
          </div>

          {availablePaths.length > 1 && (
            <div className="path-filter-wrap">
              <Folder size={12} className="muted" />
              <select
                value={pathFilter}
                onChange={(e) => setPathFilter(e.target.value)}
                title={t('Filter by secret folder path')}
              >
                <option value="">{t('All paths ({0})', availablePaths.length)}</option>
                {availablePaths.map((p) => (
                  <option key={p} value={p}>{p}</option>
                ))}
              </select>
              {pathFilter && (
                <button className="icon-btn icon-btn-xs" title={t('Clear path filter')} onClick={() => setPathFilter('')}>
                  <X size={11} />
                </button>
              )}
            </div>
          )}

          <button className={`btn btn-sm ${revealAll ? 'on' : ''}`} onClick={onToggleRevealAll} title={revealAll ? t('Hide all values') : t('Reveal all values')}>
            {revealAll ? <EyeOff size={14} /> : <Eye size={14} />} {revealAll ? t('Hide All') : t('Reveal All')}
          </button>
        </div>

        <div className="vault-toolbar-right">
          <button className="btn btn-sm" onClick={() => openDialog((c) => <ExportModal projectId={projectId} envSlug={envSlug} onClose={c} />)}>
            <Download size={14} /> {t('Export')}
          </button>

          <button
            className={`btn btn-sm ${selectedSecretIds.size > 0 ? 'btn-primary' : ''}`}
            onClick={() =>
              openDialog((c) => (
                <ShareBundleModal
                  projectId={projectId}
                  envSlug={envSlug}
                  allSecrets={secretsData?.items || []}
                  initialSelectedIds={selectedSecretIds}
                  onClose={c}
                />
              ))
            }
            title={t('Share multiple secrets as an encrypted one-time bundle link')}
          >
            <Flame size={14} style={{ color: selectedSecretIds.size > 0 ? undefined : 'var(--accent)' }} />
            <span>{selectedSecretIds.size > 0 ? t('Share Bundle ({0})', selectedSecretIds.size) : t('Share Bundle')}</span>
          </button>

          <button
            className="btn btn-sm"
            onClick={() =>
              openDialog((c) => (
                <ImportModal
                  projectId={projectId}
                  envSlug={envSlug}
                  existingSecrets={secretsData?.items || []}
                  onClose={c}
                />
              ))
            }
          >
            <Upload size={14} /> {t('Import .env')}
          </button>

          <button className="btn btn-primary btn-sm" onClick={() => openDialog((c) => <SecretModal projectId={projectId} envSlug={envSlug} existingSecrets={secretsData?.items || []} onClose={c} />)}>
            <Plus size={14} /> {t('Add Secret')}
          </button>
        </div>
      </div>

      <div className="page-body">
        {sErr && <div className="alert alert-bad">{sErr.message}</div>}
        {secretsData && secretsData.total === 0 ? (
          <Empty
            icon={<Layers size={32} />}
            title={t('No secrets in {0}', envSlug)}
            action={
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn btn-primary" onClick={() => openDialog((c) => <SecretModal projectId={projectId} envSlug={envSlug} existingSecrets={secretsData?.items || []} onClose={c} />)}>
                  <Plus size={14} /> {t('Add Secret')}
                </button>
                <button
                  className="btn btn-ghost"
                  onClick={() =>
                    openDialog((c) => (
                      <ImportModal
                        projectId={projectId}
                        envSlug={envSlug}
                        existingSecrets={[]}
                        onClose={c}
                      />
                    ))
                  }
                >
                  <Upload size={14} /> {t('Import .env')}
                </button>
              </div>
            }
          >
            {t('Store environment variables, API tokens, and credentials securely encrypted with AES-256-GCM.')}
          </Empty>
        ) : (
          <DataTable
            rows={rows}
            rowKey={(s) => s.id}
            rowMenu={secretActions}
            selected={selectedSecretIds}
            setSelected={setSelectedSecretIds}
            bulkMenu={(items) => [
              {
                label: t('Share Bundle ({0})', items.length),
                icon: <Flame size={14} />,
                onClick: () =>
                  openDialog((c) => (
                    <ShareBundleModal
                      projectId={projectId}
                      envSlug={envSlug}
                      allSecrets={secretsData?.items || []}
                      initialSelectedIds={new Set(items.map((i) => i.id))}
                      onClose={c}
                    />
                  )),
              },
              {
                label: t('Clear Selection'),
                icon: <X size={14} />,
                onClick: () => setSelectedSecretIds(new Set()),
              },
            ]}
            defaultSort={{ key: 'key', dir: 1 }}
            columns={[
              {
                key: 'key',
                label: t('Key'),
                sort: (s) => s.key.toLowerCase(),
                render: (s) => (
                  <div className="secret-cell-key">
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <strong className="mono secret-key-title">{s.key}</strong>
                      <button
                        className="icon-btn icon-btn-xs"
                        title={t('Copy key: {0}', s.key)}
                        onClick={(e) => {
                          e.stopPropagation()
                          copyToClipboard(s.key, s.key)
                        }}
                      >
                        <Copy size={12} />
                      </button>
                    </div>
                    {s.comment && <div className="secret-cell-comment muted small ellipsis">{s.comment}</div>}
                  </div>
                ),
              },
              {
                key: 'path',
                label: t('Path'),
                width: 140,
                sort: (s) => (s.path || '/').toLowerCase(),
                render: (s) => (
                  <span
                    className="secret-path-chip"
                    title={t('Path: {0} (click to filter)', s.path || '/')}
                    onClick={(e) => {
                      e.stopPropagation()
                      setPathFilter(s.path || '/')
                    }}
                  >
                    <Folder size={11} className="muted" />
                    <span>{s.path || '/'}</span>
                  </span>
                ),
              },
              {
                key: 'value',
                label: t('Value'),
                render: (s) => <SecretValueCell secret={s} projectId={projectId} envSlug={envSlug} revealAll={revealAll} onCopy={copyToClipboard} />,
              },
              {
                key: 'version',
                label: t('Version'),
                width: 90,
                sort: (s) => s.version,
                render: (s) => (
                  <button
                    className="version-badge-btn"
                    title={t('View version history (v{0})', s.version)}
                    onClick={(e) => {
                      e.stopPropagation()
                      openDialog((c) => <SecretVersionModal projectId={projectId} envSlug={envSlug} secret={s} onClose={c} />)
                    }}
                  >
                    <History size={11} /> v{s.version}
                  </button>
                ),
              },
              {
                key: 'updated',
                label: t('Updated'),
                width: 150,
                sort: (s) => s.updated_at,
                render: (s) => (
                  <div className="secret-cell-meta" title={dateTime(s.updated_at)}>
                    <span className="muted small">{ago(s.updated_at)}</span>
                    {Boolean((s as any).updated_by || (s as any).created_by) && (
                      <span className="muted small meta-author ellipsis">
                        {t('by {0}', (s as any).updated_by || (s as any).created_by)}
                      </span>
                    )}
                  </div>
                ),
              },
            ]}
          />
        )}
      </div>
    </>
  )
}

export function SecretValueCell({
  secret,
  projectId,
  envSlug,
  revealAll,
  onCopy,
}: {
  secret: Secret
  projectId: string
  envSlug: string
  revealAll: boolean
  onCopy: (text: string, label: string) => void
}) {
  const [revealed, setRevealed] = useState(false)
  const [decryptedValue, setDecryptedValue] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [sharing, setSharing] = useState(false)

  useEffect(() => {
    setDecryptedValue(null)
    setRevealed(false)
  }, [secret.id, secret.version, secret.updated_at])

  const isRevealed = revealAll || revealed
  const displayValue = isRevealed ? (decryptedValue !== null ? decryptedValue : secret.value) : '••••••••'

  const toggleReveal = () => {
    if (revealed) {
      setRevealed(false)
      return
    }
    if (decryptedValue !== null) {
      setRevealed(true)
      return
    }
    setLoading(true)
    api
      .get<Secret>(`/projects/${enc(projectId)}/environments/${enc(envSlug)}/secrets/${enc(secret.id)}`)
      .then((res) => {
        setDecryptedValue(res.value)
        setRevealed(true)
      })
      .catch(toast.err)
      .finally(() => setLoading(false))
  }

  const handleCopy = () => {
    if (decryptedValue !== null) {
      onCopy(decryptedValue, secret.key)
      return
    }
    if (secret.value !== '••••••••') {
      onCopy(secret.value, secret.key)
      return
    }
    setLoading(true)
    api
      .get<Secret>(`/projects/${enc(projectId)}/environments/${enc(envSlug)}/secrets/${enc(secret.id)}`)
      .then((res) => {
        setDecryptedValue(res.value)
        onCopy(res.value, secret.key)
      })
      .catch(toast.err)
      .finally(() => setLoading(false))
  }

  const handleShare = async () => {
    let val = decryptedValue
    if (val === null) {
      if (secret.value !== '••••••••') {
        val = secret.value
      } else {
        setSharing(true)
        try {
          const res = await api.get<Secret>(`/projects/${enc(projectId)}/environments/${enc(envSlug)}/secrets/${enc(secret.id)}`)
          val = res.value
          setDecryptedValue(val)
        } catch (err: any) {
          toast.err(err.message || 'Failed to fetch secret value')
          setSharing(false)
          return
        }
      }
    }
    setSharing(true)
    try {
      const encData = await encryptShare(val)
      const res = await api.post<ShareCreated>('/shares', {
        ciphertext: encData.ciphertext,
        nonce: encData.nonce,
        ttl_seconds: 86400,
        max_views: 1,
        has_passphrase: false,
        passphrase_salt: '',
      })
      const fullUrl = `${window.location.origin}/#/share/${enc(res.id)}?k=${encData.keyUrlSafe}`
      const ok = await copy(fullUrl)
      if (ok) {
        toast.ok(t('One-time share link copied to clipboard! (Burns after 1 view)'))
      } else {
        toast.ok(t('Share link created: {0}', fullUrl))
      }
    } catch (err: any) {
      toast.err(err.message || 'Failed to create share link')
    } finally {
      setSharing(false)
    }
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <span className="mono" style={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {displayValue}
      </span>
      {secret.raw_value && (
        <span
          className="tag tag-accent mono"
          style={{ fontSize: 10, padding: '1px 5px', cursor: 'help' }}
          title={t('Interpolated template: {0}', secret.raw_value)}
        >
          {t('REF')}
        </span>
      )}
      <button className="icon-btn" title={isRevealed ? t('Hide') : t('Reveal')} onClick={toggleReveal} disabled={loading}>
        {loading ? <Spinner /> : isRevealed ? <EyeOff size={12} /> : <Eye size={12} />}
      </button>
      <button className="icon-btn" title={t('Copy value')} onClick={handleCopy} disabled={loading}>
        <Copy size={12} />
      </button>
      {secret.raw_value && (
        <button
          className="icon-btn"
          title={t('Copy unexpanded template ({0})', secret.raw_value)}
          onClick={() => onCopy(secret.raw_value || '', `${secret.key} (template)`)}
        >
          <Code size={12} />
        </button>
      )}
      <button
        className="icon-btn"
        title={t('Create one-time share link (Burn on read)')}
        onClick={handleShare}
        disabled={loading || sharing}
        style={{ color: 'var(--accent)' }}
      >
        {sharing ? <Spinner /> : <Flame size={12} />}
      </button>
    </div>
  )
}

export async function removeSecret(projectId: string, envSlug: string, s: Secret) {
  if (
    !(await confirm({
      title: t('Delete {0}?', s.key),
      body: t('This will permanently delete the secret and all its version history.'),
      danger: true,
      confirm: t('Delete Secret'),
    }))
  ) {
    return
  }
  api.del(`/projects/${enc(projectId)}/environments/${enc(envSlug)}/secrets/${enc(s.id)}`).then(() => {
    invalidate('/projects')
    toast.ok(t('Secret deleted'))
  }, toast.err)
}
