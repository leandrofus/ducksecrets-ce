import { t } from '../i18n'
import { useMemo, useState, useEffect, useRef } from 'react'
import {
  FolderKey,
  Folder,
  ChevronRight,
  Settings2,
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
  RotateCcw,
  Check,
  Layers,
  KeyRound,
  Flame,
  Database,
  RefreshCw,
  Server,
  Clock,
  Activity,
  Play,
  AlertCircle,
  Network,
  ShieldCheck,
  Sparkles,
  Code,
  Package,
  User as UserIcon,
  UsersRound,
} from 'lucide-react'
import { api, enc, triggerUnauthorized } from '../lib/api'
import { allowed } from '../lib/access'
import type {
  Page,
  Project,
  ProjectList,
  ProjectPolicy,
  Environment,
  Secret,
  SecretList,
  SecretVersionList,
  ServiceToken,
  CreatedServiceToken,
  ShareCreated,
  DynamicProvider,
  DynamicLease,
  IssuedLease,
  TestProviderResponse,
  RotationPolicy,
  RotationRunResponse,
  ImportSecretsResponse,
  ImportSecretItem,
  Site,
  CreatedSite,
  User,
  Role,
} from '../lib/api'
import { encryptShare } from '../lib/crypto'
import { invalidate, useResource } from '../lib/store'
import { go } from '../lib/router'
import { ago, dateTime, copy } from '../lib/format'
import { useMenu, type MenuEntry } from '../ui/ContextMenu'
import { DataTable, Empty, Spinner, Tabs, Tag } from '../ui/common'
import { Modal, confirm, openDialog, toast } from '../ui/overlays'
import { Field } from '../ui/Field'
import {
  DynamicEngineConfigForm,
  HttpProbeConfigForm,
  TcpProbeConfigForm,
  ScriptProbeConfigForm,
} from './ConfigForms'
import type { SecretBundlePayload } from './ShareView'

export function Projects({ id }: { id?: string }) {
  if (id) {
    return <ProjectDetail id={id} />
  }
  return <ProjectListView />
}

function ProjectListView() {
  const { data, error, loading } = useResource<ProjectList>('/projects')
  const [q, setQ] = useState('')

  const rows = useMemo(() => {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean)
    return (data?.items || []).filter((p) => words.every((w) => `${p.name} ${p.slug} ${p.description}`.toLowerCase().includes(w)))
  }, [data?.items, q])

  const projectActions = (p: Project): MenuEntry[] => [
    { header: p.name },
    { label: t('Open Vault'), onClick: () => go('projects', p.id) },
    { label: t('Edit…'), icon: <Pencil size={14} />, onClick: () => openDialog((c) => <ProjectModal initial={p} onClose={c} />) },
    'sep',
    { label: t('Delete'), icon: <Trash2 size={14} />, danger: true, onClick: () => removeProject(p) },
  ]

  return (
    <div className="page">
      <div className="page-head">
        <div className="page-title">
          <FolderKey size={20} />
          <h1>{t('Projects')}</h1>
          <span className="count">{data?.total ?? 0}</span>
          {loading && <Spinner />}
        </div>
        <div className="page-actions">
          <div className="search">
            <Search size={14} />
            <input placeholder={t('Search projects…')} value={q} onChange={(e) => setQ(e.currentTarget.value)} />
            {q && <button className="icon-btn" onClick={() => setQ('')}><X size={13} /></button>}
          </div>
          <button className="btn btn-primary btn-sm" onClick={() => openDialog((c) => <ProjectModal onClose={c} />)}>
            <Plus size={14} /> {t('New Project')}
          </button>
        </div>
      </div>

      <div className="page-body">
        {error && <div className="alert alert-bad">{error.message}</div>}
        {data && data.total === 0 ? (
          <Empty
            icon={<FolderKey size={32} />}
            title={t('No projects yet')}
            action={
              <button className="btn btn-primary" onClick={() => openDialog((c) => <ProjectModal onClose={c} />)}>
                <Plus size={14} /> {t('Create your first project')}
              </button>
            }
          >
            {t('Projects contain isolated vaults and environments (dev, staging, prod) for your secrets.')}
          </Empty>
        ) : (
          <DataTable
            rows={rows}
            rowKey={(p) => p.id}
            onOpen={(p) => go('projects', p.id)}
            rowMenu={projectActions}
            defaultSort={{ key: 'name', dir: 1 }}
            columns={[
              {
                key: 'name',
                label: t('Name'),
                sort: (p) => p.name.toLowerCase(),
                render: (p) => (
                  <div>
                    <strong>{p.name}</strong>
                    <div className="muted small mono">{p.slug}</div>
                  </div>
                ),
              },
              {
                key: 'description',
                label: t('Description'),
                render: (p) => <span className="muted small">{p.description || '—'}</span>,
              },
              {
                key: 'updated',
                label: t('Updated'),
                sort: (p) => p.updated_at,
                render: (p) => <span className="muted small" title={dateTime(p.updated_at)}>{ago(p.updated_at)}</span>,
              },
            ]}
          />
        )}
      </div>
    </div>
  )
}

function ProjectDetail({ id }: { id: string }) {
  const { data: project, error: pErr } = useResource<Project>(`/projects/${enc(id)}`)
  const { data: envs } = useResource<Environment[]>(`/projects/${enc(id)}/environments`)

  const [tab, setTab] = useState<'secrets' | 'tokens' | 'dynamic' | 'rotation' | 'sites' | 'policies'>('secrets')
  const [activeEnv, setActiveEnv] = useState<string>('dev')
  const [revealAll, setRevealAll] = useState(false)
  const [q, setQ] = useState('')
  const [pathFilter, setPathFilter] = useState<string>('')
  const [selectedSecretIds, setSelectedSecretIds] = useState<Set<string>>(new Set())

  const envSlug = envs && envs.length > 0 ? (envs.some((e) => e.slug === activeEnv) ? activeEnv : envs[0].slug) : 'dev'

  useEffect(() => {
    setSelectedSecretIds(new Set())
    setPathFilter('')
  }, [id, envSlug])

  const { data: secretsData, error: sErr, loading: sLoading } = useResource<SecretList>(
    `/projects/${enc(id)}/environments/${enc(envSlug)}/secrets${revealAll ? '?reveal=1' : ''}`
  )

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

  if (pErr) {
    return (
      <div className="page">
        <div className="alert alert-bad">{pErr.message}</div>
        <button className="btn btn-sm" onClick={() => go('projects')}>← {t('Back to projects')}</button>
      </div>
    )
  }

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
        // Fetch decrypted secret if currently masked
        if (s.value === '••••••••') {
          api.get<Secret>(`/projects/${enc(id)}/environments/${enc(envSlug)}/secrets/${enc(s.id)}`).then((res) => {
            copyToClipboard(res.value, s.key)
          }, toast.err)
        } else {
          copyToClipboard(s.value, s.key)
        }
      },
    },
    { label: t('Edit…'), icon: <Pencil size={14} />, onClick: () => openDialog((c) => <SecretModal projectId={id} envSlug={envSlug} initial={s} existingSecrets={secretsData?.items || []} onClose={c} />) },
    { label: t('Share as Bundle…'), icon: <Flame size={14} />, onClick: () => openDialog((c) => <ShareBundleModal projectId={id} envSlug={envSlug} allSecrets={secretsData?.items || []} initialSelectedIds={new Set([s.id])} onClose={c} />) },
    { label: t('Version History…'), icon: <History size={14} />, onClick: () => openDialog((c) => <SecretVersionModal projectId={id} envSlug={envSlug} secret={s} onClose={c} />) },
    { label: t('Auto-Rotation…'), icon: <RefreshCw size={14} />, onClick: () => openDialog((c) => <RotationPolicyModal projectId={id} envSlug={envSlug} secret={s} onClose={c} />) },
    'sep',
    { label: t('Delete'), icon: <Trash2 size={14} />, danger: true, onClick: () => removeSecret(id, envSlug, s) },
  ]

  return (
    <div className="page">
      <div className="page-head" style={{ marginBottom: 12 }}>
        <div>
          <div className="vault-breadcrumb">
            <a href="#projects" onClick={(e) => { e.preventDefault(); go('projects'); }}>
              <FolderKey size={13} />
              <span>{t('Projects')}</span>
            </a>
            <ChevronRight size={13} className="breadcrumb-sep" />
            <span className="breadcrumb-cur">{project?.name || t('Project Vault')}</span>
          </div>
          <div className="page-title">
            <FolderKey size={22} style={{ color: 'var(--accent)' }} />
            <h1>{project?.name || t('Project Vault')}</h1>
            {project?.slug && <Tag mono tone="accent">{project.slug}</Tag>}
            {sLoading && <Spinner />}
          </div>
          {project?.description && <p className="muted small" style={{ marginTop: 4 }}>{project.description}</p>}
        </div>

        <div className="page-actions">
          <button
            className="btn btn-sm btn-ghost"
            onClick={() => openDialog((c) => <ProjectModal initial={project} onClose={c} />)}
            title={t('Edit Project Settings')}
          >
            <Settings2 size={14} /> {t('Project Settings')}
          </button>
        </div>
      </div>

      <div style={{ borderBottom: '1px solid var(--border)', marginBottom: 16 }}>
        <Tabs
          tabs={[
            { id: 'secrets', label: t('Secrets') },
            { id: 'tokens', label: t('Service Tokens') },
            { id: 'dynamic', label: t('Dynamic Secrets') },
            { id: 'rotation', label: t('Auto-Rotation') },
            { id: 'sites', label: t('Network Sites') },
            { id: 'policies', label: t('Access & Policies') },
          ]}
          active={tab}
          onChange={(t) => setTab(t as any)}
        />
      </div>

      {tab === 'tokens' ? (
        <TokensView projectId={id} envs={envs || []} />
      ) : tab === 'dynamic' ? (
        <DynamicView projectId={id} envSlug={envSlug} envs={envs || []} />
      ) : tab === 'rotation' ? (
        <RotationView projectId={id} envSlug={envSlug} />
      ) : tab === 'sites' ? (
        <SitesView projectId={id} />
      ) : tab === 'policies' ? (
        <PoliciesView projectId={id} envs={envs || []} />
      ) : (
        <>
          {envs && envs.length > 0 && (
            <div className="vault-subnav">
              <Tabs
                tabs={envs.map((e) => ({ id: e.slug, label: e.name }))}
                active={envSlug}
                onChange={(slug) => setActiveEnv(slug)}
              />
              <button className="btn btn-sm btn-ghost" onClick={() => openDialog((c) => <EnvironmentModal projectId={id} onClose={c} />)}>
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

              <button className={`btn btn-sm ${revealAll ? 'on' : ''}`} onClick={() => setRevealAll(!revealAll)} title={revealAll ? t('Hide all values') : t('Reveal all values')}>
                {revealAll ? <EyeOff size={14} /> : <Eye size={14} />} {revealAll ? t('Hide All') : t('Reveal All')}
              </button>
            </div>

            <div className="vault-toolbar-right">
              <button className="btn btn-sm" onClick={() => openDialog((c) => <ExportModal projectId={id} envSlug={envSlug} onClose={c} />)}>
                <Download size={14} /> {t('Export')}
              </button>

              <button
                className={`btn btn-sm ${selectedSecretIds.size > 0 ? 'btn-primary' : ''}`}
                onClick={() =>
                  openDialog((c) => (
                    <ShareBundleModal
                      projectId={id}
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
                      projectId={id}
                      envSlug={envSlug}
                      existingSecrets={secretsData?.items || []}
                      onClose={c}
                    />
                  ))
                }
              >
                <Upload size={14} /> {t('Import .env')}
              </button>

              <button className="btn btn-primary btn-sm" onClick={() => openDialog((c) => <SecretModal projectId={id} envSlug={envSlug} existingSecrets={secretsData?.items || []} onClose={c} />)}>
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
                    <button className="btn btn-primary" onClick={() => openDialog((c) => <SecretModal projectId={id} envSlug={envSlug} existingSecrets={secretsData?.items || []} onClose={c} />)}>
                      <Plus size={14} /> {t('Add Secret')}
                    </button>
                    <button
                      className="btn btn-ghost"
                      onClick={() =>
                        openDialog((c) => (
                          <ImportModal
                            projectId={id}
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
                          projectId={id}
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
                    render: (s) => <SecretValueCell secret={s} projectId={id} envSlug={envSlug} revealAll={revealAll} onCopy={copyToClipboard} />,
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
                          openDialog((c) => <SecretVersionModal projectId={id} envSlug={envSlug} secret={s} onClose={c} />)
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
      )}
    </div>
  )
}

function SecretValueCell({
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
        style={{ color: 'var(--accent, #ea580c)' }}
      >
        {sharing ? <Spinner /> : <Flame size={12} />}
      </button>
    </div>
  )
}

export function ProjectModal({ initial, onClose }: { initial?: Project; onClose: () => void }) {
  const [name, setName] = useState(initial?.name ?? '')
  const [slug, setSlug] = useState(initial?.slug ?? '')
  const [description, setDescription] = useState(initial?.description ?? '')
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    try {
      if (initial) {
        await api.patch(`/projects/${enc(initial.id)}`, { name, description })
        toast.ok(t('Project updated'))
      } else {
        await api.post('/projects', { name, slug: slug || undefined, description })
        toast.ok(t('Project created with dev, staging, prod environments'))
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
    <Modal title={initial ? t('Edit Project') : t('New Project')} onClose={onClose}>
      <form onSubmit={submit}>
        <Field label={t('Name')}>
          <input required autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Backend API" />
        </Field>
        {!initial && (
          <Field label={t('Slug')} help={t('Unique URL identifier (lowercase letters, digits, hyphens). Leave blank to auto-slugify.')}>
            <input value={slug} onChange={(e) => setSlug(e.target.value)} placeholder="e.g. backend-api" />
          </Field>
        )}
        <Field label={t('Description')}>
          <textarea rows={3} value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Optional project description..." />
        </Field>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
          <button type="button" className="btn btn-ghost" onClick={onClose}>{t('Cancel')}</button>
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? <Spinner /> : initial ? t('Save') : t('Create Project')}
          </button>
        </div>
      </form>
    </Modal>
  )
}

function SecretModal({
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
        const patch: any = { comment }
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
              <Field label={t('Secret Key')} help={t('Environment variable name (e.g. DATABASE_URL, STRIPE_SECRET_KEY)')}>
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
              label={
                <div style={{ display: 'flex', justifyContent: 'space-between', width: '100%' }}>
                  <span>{t('Value / Template')} {loadingInitial && <Spinner />}</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span className="muted small mono">{value.length} {t('chars')}</span>
                    <button
                      type="button"
                      className="btn btn-ghost btn-sm"
                      style={{ padding: '0 4px', height: 'auto' }}
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
                  ...(showVal ? {} : ({ WebkitTextSecurity: 'disc' } as any)),
                }}
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder={initial ? (loadingInitial ? t('Loading decrypted value...') : t('Enter new value or template...')) : t('Secret value or composite template (e.g. postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}/${DB_NAME})')}
              />
            </Field>

            <div className="grid-2">
              <Field label={t('Path / Folder')} help={initial ? t('Path cannot be moved when editing') : t('Default root path /')}>
                <input value={path} disabled={!!initial} onChange={(e) => setPath(e.target.value)} placeholder="/" />
              </Field>
              <Field label={t('Comment')} help={t('Optional note')}>
                <input value={comment} onChange={(e) => setComment(e.target.value)} placeholder="e.g. Production RDS connection string" />
              </Field>
            </div>
          </div>

          {/* Right Column: Context, Intelligence & Interpolation Inspector */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {/* Live Resolved Preview Card */}
            <div style={{ padding: '12px 14px', background: 'var(--surface-2, var(--bg-subtle))', borderRadius: 8, border: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                <span style={{ fontSize: 12, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Sparkles size={14} style={{ color: 'var(--accent)' }} />
                  {t('Live Resolved Preview')}
                </span>
                {resolvedPreview && (
                  <button
                    type="button"
                    className="btn btn-ghost btn-sm"
                    style={{ padding: '1px 6px', height: 'auto', fontSize: 11 }}
                    onClick={() => {
                      copy(resolvedPreview).then((ok) => {
                        if (ok) toast.ok(t('Resolved preview copied to clipboard'))
                      })
                    }}
                    title={t('Copy resolved preview')}
                  >
                    <Copy size={11} style={{ marginRight: 3 }} /> {t('Copy')}
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
            <div style={{ padding: '12px 14px', background: 'var(--surface-2, var(--bg-subtle))', borderRadius: 8, border: '1px solid var(--border)' }}>
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
                      className="btn btn-ghost btn-sm"
                      style={{
                        padding: '3px 8px',
                        fontSize: 11,
                        height: 'auto',
                        border: '1px dashed var(--border)',
                        fontFamily: 'monospace',
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
            <div style={{ padding: '10px 14px', background: 'var(--bg-subtle)', borderRadius: 8, border: '1px solid var(--border)', fontSize: 11 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                <ShieldCheck size={14} style={{ color: '#10b981' }} />
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

function SecretVersionModal({
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
              className="btn btn-ghost btn-sm"
              style={{ fontSize: 11, padding: '2px 6px', height: 'auto' }}
              onClick={toggleRevealAll}
            >
              {revealAll ? <EyeOff size={12} style={{ marginRight: 4 }} /> : <Eye size={12} style={{ marginRight: 4 }} />}
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
                    background: isSelected ? 'var(--surface-2, var(--bg-subtle))' : 'var(--bg)',
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
                    <div style={{ fontSize: 12, marginBottom: 6, color: 'var(--fg)' }}>
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
                        className="icon-btn"
                        style={{ padding: 3 }}
                        title={isValRevealed ? t('Hide') : t('Reveal')}
                        onClick={() => toggleReveal(v.version)}
                      >
                        {isValRevealed ? <EyeOff size={12} /> : <Eye size={12} />}
                      </button>
                      <button
                        type="button"
                        className="icon-btn"
                        style={{ padding: 3 }}
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
              <div style={{ padding: '14px 16px', background: 'var(--surface-2, var(--bg-subtle))', borderRadius: 8, border: '1px solid var(--border)' }}>
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

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 12, marginBottom: 12 }}>
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
                        className="btn btn-ghost btn-sm"
                        style={{ padding: '1px 6px', height: 'auto', fontSize: 11 }}
                        onClick={() => toggleReveal(selectedVersion.version)}
                      >
                        {revealAll || revealed[selectedVersion.version] ? (
                          <><EyeOff size={11} style={{ marginRight: 3 }} /> {t('Mask')}</>
                        ) : (
                          <><Eye size={11} style={{ marginRight: 3 }} /> {t('Reveal')}</>
                        )}
                      </button>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        style={{ padding: '1px 6px', height: 'auto', fontSize: 11 }}
                        onClick={() => {
                          copy(selectedVersion.value).then((ok) => {
                            if (ok) toast.ok(t('v{0} value copied to clipboard', selectedVersion.version))
                          })
                        }}
                      >
                        <Copy size={11} style={{ marginRight: 3 }} /> {t('Copy')}
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
                      <RotateCcw size={13} style={{ marginRight: 6 }} />
                      {busy === selectedVersion.version ? <Spinner /> : t('Restore & Rollback to v{0}', selectedVersion.version)}
                    </button>
                    <span className="muted small" style={{ display: 'block', textAlign: 'center', marginTop: 4 }}>
                      {t('Creates a new version v{0} restoring this historic secret value.', (items[0]?.version || secret.version) + 1)}
                    </span>
                  </div>
                )}
              </div>

              <div style={{ padding: '10px 12px', background: 'var(--bg-subtle)', borderRadius: 8, border: '1px solid var(--border)', fontSize: 11 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                  <ShieldCheck size={14} style={{ color: '#10b981' }} />
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

function ExportModal({
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
              <Download size={13} style={{ marginRight: 6 }} /> {t('Download {0}', format === 'dotenv' ? '.env' : format.toUpperCase())}
            </button>
          </div>
        </div>
      }
    >
      <div className="modal-two-col">
        {/* Left Column: Format Picker & Export Options */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ padding: '12px 14px', background: 'var(--surface-2, var(--bg-subtle))', borderRadius: 8, border: '1px solid var(--border)' }}>
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

          <div style={{ padding: '12px 14px', background: 'var(--surface-2, var(--bg-subtle))', borderRadius: 8, border: '1px solid var(--border)' }}>
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
                {copied ? <Check size={13} style={{ marginRight: 6 }} /> : <Copy size={13} style={{ marginRight: 6 }} />}
                {copied ? t('Copied!') : t('Copy to Clipboard')}
              </button>
              <button
                type="button"
                className="btn btn-sm btn-subtle"
                style={{ flex: 1, justifyContent: 'center' }}
                onClick={download}
                disabled={loading || !content}
              >
                <Download size={13} style={{ marginRight: 6 }} />
                {t('Download File')}
              </button>
            </div>
          </div>

          {/* Interpolation Resolution Info Card */}
          <div style={{ padding: '10px 14px', background: 'var(--bg-subtle)', borderRadius: 8, border: '1px solid var(--border)', fontSize: 11 }}>
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

export function ShareBundleModal({
  projectId,
  envSlug,
  allSecrets,
  initialSelectedIds,
  onClose,
}: {
  projectId: string
  envSlug: string
  allSecrets: Secret[]
  initialSelectedIds?: Set<string>
  onClose: () => void
}) {
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => {
    if (initialSelectedIds && initialSelectedIds.size > 0) {
      return new Set(initialSelectedIds)
    }
    return new Set(allSecrets.map((s) => s.id))
  })
  const [search, setSearch] = useState('')
  const [bundleTitle, setBundleTitle] = useState(`${envSlug.toUpperCase()} Secrets Bundle`)
  const [interpolate, setInterpolate] = useState(true)
  const [ttlSeconds, setTtlSeconds] = useState(86400) // 1 day
  const [maxViews, setMaxViews] = useState(1) // 1 view
  const [passphrase, setPassphrase] = useState('')
  const [generating, setGenerating] = useState(false)
  const [createdUrl, setCreatedUrl] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const filteredSecrets = allSecrets.filter((s) =>
    s.key.toLowerCase().includes(search.toLowerCase())
  )

  const toggleSecret = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const selectAll = () => {
    setSelectedIds(new Set(allSecrets.map((s) => s.id)))
  }

  const deselectAll = () => {
    setSelectedIds(new Set())
  }

  const selectedCount = selectedIds.size

  const handleGenerate = async () => {
    if (selectedCount === 0) {
      toast.err(t('Please select at least one secret to share.'))
      return
    }

    setGenerating(true)
    try {
      const selectedSecrets = allSecrets.filter((s) => selectedIds.has(s.id))
      const bundleItems: { key: string; value: string; comment?: string }[] = []

      // Always fetch real decrypted values for masked secrets and abort on any error
      for (const s of selectedSecrets) {
        let val = s.value
        if (val === '••••••••') {
          const fetched = await api.get<Secret>(
            `/projects/${enc(projectId)}/environments/${enc(envSlug)}/secrets/${enc(s.id)}`
          )
          val = interpolate ? fetched.value : (fetched.raw_value ?? fetched.value)
        } else if (!interpolate && s.raw_value !== undefined) {
          val = s.raw_value
        }
        bundleItems.push({
          key: s.key,
          value: val,
          comment: s.comment || undefined,
        })
      }

      const bundlePayload: SecretBundlePayload = {
        __ducksecrets_bundle: true,
        version: 1,
        title: bundleTitle.trim() || `${envSlug.toUpperCase()} Secrets Bundle`,
        project: projectId,
        environment: envSlug,
        created_at: new Date().toISOString(),
        secrets: bundleItems,
      }

      const encData = await encryptShare(JSON.stringify(bundlePayload), passphrase)
      const res = await api.post<ShareCreated>('/shares', {
        ciphertext: encData.ciphertext,
        nonce: encData.nonce,
        ttl_seconds: ttlSeconds,
        max_views: maxViews,
        has_passphrase: encData.hasPassphrase,
        passphrase_salt: encData.passphraseSalt || '',
      })

      const fullUrl = `${window.location.origin}/#/share/${enc(res.id)}?k=${encData.keyUrlSafe}`
      setCreatedUrl(fullUrl)
      toast.ok(t('Bundle share link generated!'))
    } catch (err: any) {
      toast.err(err.message || t('Failed to generate bundle share link'))
    } finally {
      setGenerating(false)
    }
  }

  const handleCopyLink = () => {
    if (createdUrl) {
      copy(createdUrl).then((ok) => {
        if (ok) {
          setCopied(true)
          toast.ok(t('Share link copied to clipboard!'))
          setTimeout(() => setCopied(false), 2000)
        }
      })
    }
  }

  return (
    <Modal
      title={
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
          <Package size={16} />
          {t('Share Secret Bundle: {0}', envSlug)}
        </span>
      }
      wide="xl"
      allowFullscreen
      onClose={onClose}
      footer={
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
          <span className="muted small">
            {selectedCount} {t('of')} {allSecrets.length} {t('secrets selected')}
          </span>
          <div style={{ display: 'flex', gap: 8 }}>
            <button type="button" className="btn btn-ghost" onClick={onClose}>{t('Close')}</button>
            {createdUrl ? (
              <button type="button" className="btn btn-primary" onClick={handleCopyLink}>
                {copied ? <Check size={14} style={{ marginRight: 6 }} /> : <Copy size={14} style={{ marginRight: 6 }} />}
                {copied ? t('Copied!') : t('Copy Link')}
              </button>
            ) : (
              <button
                type="button"
                className="btn btn-primary"
                onClick={handleGenerate}
                disabled={generating || selectedCount === 0}
              >
                {generating ? <Spinner /> : <Flame size={14} style={{ marginRight: 6 }} />}
                {generating ? t('Encrypting Bundle...') : t('Generate Share Link')}
              </button>
            )}
          </div>
        </div>
      }
    >
      <div className="modal-two-col">
        {/* Left Column: Secret Picker & Security Configuration */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <Field label={t('Bundle Title')} help={t('Descriptive label shown to recipient')}>
            <input
              value={bundleTitle}
              onChange={(e) => setBundleTitle(e.target.value)}
              placeholder="e.g. Production RDS & Stripe Keys"
            />
          </Field>

          {/* Secrets Checklist */}
          <div style={{ border: '1px solid var(--border)', borderRadius: 8, padding: '10px 12px', background: 'var(--surface-2)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
              <span style={{ fontSize: 12, fontWeight: 600 }}>{t('Select Secrets to Include')}</span>
              <div style={{ display: 'flex', gap: 6 }}>
                <button type="button" className="btn btn-ghost btn-sm" style={{ padding: '1px 6px', height: 'auto', fontSize: 11 }} onClick={selectAll}>
                  {t('Select All')}
                </button>
                <button type="button" className="btn btn-ghost btn-sm" style={{ padding: '1px 6px', height: 'auto', fontSize: 11 }} onClick={deselectAll}>
                  {t('Deselect All')}
                </button>
              </div>
            </div>

            <div className="search" style={{ marginBottom: 8 }}>
              <Search size={13} />
              <input
                placeholder={t('Filter secrets…')}
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                style={{ fontSize: 12 }}
              />
              {search && <button className="icon-btn" onClick={() => setSearch('')}><X size={12} /></button>}
            </div>

            <div style={{ maxHeight: 180, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 4 }}>
              {filteredSecrets.length === 0 ? (
                <span className="muted small center" style={{ padding: '12px 0' }}>{t('No matching secrets')}</span>
              ) : (
                filteredSecrets.map((s) => {
                  const isChecked = selectedIds.has(s.id)
                  return (
                    <label
                      key={s.id}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 8,
                        padding: '5px 8px',
                        borderRadius: 6,
                        background: isChecked ? 'var(--surface)' : 'transparent',
                        cursor: 'pointer',
                        userSelect: 'none',
                        border: '1px solid',
                        borderColor: isChecked ? 'var(--border)' : 'transparent',
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => toggleSecret(s.id)}
                      />
                      <strong className="mono" style={{ fontSize: 12, flex: 1 }}>{s.key}</strong>
                      {s.raw_value && <span className="tag tag-accent mono" style={{ fontSize: 9, padding: '1px 4px' }}>REF</span>}
                      {s.comment && <span className="muted small" style={{ fontSize: 11, maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.comment}</span>}
                    </label>
                  )
                })
              )}
            </div>
          </div>

          {/* Interpolation Option */}
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, cursor: 'pointer', padding: '6px 8px', background: 'var(--surface-2)', borderRadius: 6, border: '1px solid var(--border)' }}>
            <input
              type="checkbox"
              checked={interpolate}
              onChange={(e) => setInterpolate(e.target.checked)}
            />
            <div>
              <strong>{t('Interpolate dynamic and referenced secrets')}</strong>
              <span className="muted small" style={{ display: 'block' }}>
                {t('Resolves ${VAR} placeholders into decrypted values before encrypting.')}
              </span>
            </div>
          </label>

          {/* Ephemeral Settings Grid */}
          <div className="grid-2">
            <Field label={t('Duration / TTL')} help={t('Link auto-expires after')}>
              <select value={ttlSeconds} onChange={(e) => setTtlSeconds(Number(e.target.value))}>
                <option value={3600}>{t('1 hour')}</option>
                <option value={28800}>{t('8 hours')}</option>
                <option value={86400}>{t('24 hours (1 day)')}</option>
                <option value={604800}>{t('7 days')}</option>
                <option value={2592000}>{t('30 days')}</option>
              </select>
            </Field>

            <Field label={t('Max Views')} help={t('Burn on read limit')}>
              <select value={maxViews} onChange={(e) => setMaxViews(Number(e.target.value))}>
                <option value={1}>{t('1 view (Burn on read)')}</option>
                <option value={2}>{t('2 views')}</option>
                <option value={5}>{t('5 views')}</option>
                <option value={10}>{t('10 views')}</option>
              </select>
            </Field>
          </div>

          <Field label={t('Optional Passphrase')} help={t('Extra layer of decryption security')}>
            <div style={{ position: 'relative' }}>
              <input
                type="password"
                placeholder={t('Extra passphrase to unlock (optional)')}
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                style={{ paddingLeft: 30 }}
              />
              <KeyRound size={14} style={{ position: 'absolute', left: 10, top: 10, color: 'var(--muted)' }} />
            </div>
          </Field>
        </div>

        {/* Right Column: Live Summary, Preview & Generated Link */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {createdUrl ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div
                style={{
                  padding: '14px',
                  borderRadius: 8,
                  backgroundColor: 'rgba(16, 185, 129, 0.1)',
                  color: '#10b981',
                  border: '1px solid rgba(16, 185, 129, 0.25)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                  fontWeight: 500,
                }}
              >
                <ShieldCheck size={22} />
                <span>{t('Secret Bundle encrypted with AES-256-GCM and ready!')}</span>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 600, marginBottom: 6 }}>
                  {t('One-Time Share Link')}
                </label>
                <div style={{ display: 'flex', gap: 6 }}>
                  <input
                    type="text"
                    readOnly
                    value={createdUrl}
                    className="mono"
                    style={{ fontSize: 11, padding: '8px 10px', background: 'var(--surface-2)', flex: 1 }}
                  />
                  <button type="button" className="btn btn-primary" onClick={handleCopyLink}>
                    {copied ? <Check size={14} /> : <Copy size={14} />}
                    <span style={{ marginLeft: 4 }}>{copied ? t('Copied!') : t('Copy')}</span>
                  </button>
                </div>
              </div>

              <div style={{ padding: '12px', background: 'var(--surface-2)', borderRadius: 8, border: '1px solid var(--border)', fontSize: 11, lineHeight: 1.5 }}>
                <strong style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--accent)', marginBottom: 4 }}>
                  <Flame size={14} />
                  {maxViews === 1 ? t('Burn on Read Enabled') : t('Limited Views ({0})', maxViews)}
                </strong>
                <p className="muted small" style={{ margin: 0 }}>
                  {t('The link contains the decryption key in the hash fragment (#k=). Once opened and burned, the bundle payload cannot be recovered.')}
                </p>
              </div>

              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => setCreatedUrl(null)}
                style={{ marginTop: 8 }}
              >
                {t('Configure Another Bundle')}
              </button>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {/* Summary Card */}
              <div style={{ padding: '12px 14px', background: 'var(--surface-2)', borderRadius: 8, border: '1px solid var(--border)' }}>
                <span style={{ fontSize: 12, fontWeight: 600, display: 'block', marginBottom: 8 }}>
                  {t('Bundle Summary')}
                </span>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span className="muted">{t('Selected Secrets')}:</span>
                    <strong className="mono">{selectedCount} {t('secrets')}</strong>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span className="muted">{t('Burn Policy')}:</span>
                    <strong style={{ color: 'var(--accent)' }}>
                      {maxViews === 1 ? t('Burn immediately on read') : t('{0} views allowed', maxViews)}
                    </strong>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span className="muted">{t('Passphrase')}:</span>
                    <strong>{passphrase ? t('Enabled') : t('None')}</strong>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span className="muted">{t('Interpolation')}:</span>
                    <strong>{interpolate ? t('Resolved (Ready to use)') : t('Raw templates')}</strong>
                  </div>
                </div>
              </div>

              {/* Selected Keys Preview List */}
              <div style={{ border: '1px solid var(--border)', borderRadius: 8, padding: '10px 12px', background: 'var(--surface-2)' }}>
                <span style={{ fontSize: 12, fontWeight: 600, display: 'block', marginBottom: 6 }}>
                  {t('Bundle Payload Preview ({0})', selectedCount)}
                </span>
                <div style={{ maxHeight: 200, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {allSecrets.filter((s) => selectedIds.has(s.id)).map((s) => (
                    <div
                      key={s.id}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        padding: '4px 8px',
                        background: 'var(--surface)',
                        borderRadius: 4,
                        fontSize: 11,
                        border: '1px solid var(--border)',
                      }}
                    >
                      <span className="mono" style={{ fontWeight: 600 }}>{s.key}</span>
                      <span className="mono muted">••••••••••••</span>
                    </div>
                  ))}
                  {selectedCount === 0 && (
                    <span className="muted small center" style={{ padding: '12px 0' }}>
                      {t('No secrets selected')}
                    </span>
                  )}
                </div>
              </div>

              {/* Zero Knowledge Trust Badge */}
              <div style={{ padding: '10px 12px', background: 'var(--surface-2)', borderRadius: 8, border: '1px solid var(--border)', fontSize: 11, display: 'flex', alignItems: 'center', gap: 8 }}>
                <ShieldCheck size={18} style={{ color: '#10b981', flexShrink: 0 }} />
                <span className="muted small">
                  {t('Encrypted in your browser before upload. The server never sees the decryption key.')}
                </span>
              </div>
            </div>
          )}
        </div>
      </div>
    </Modal>
  )
}

interface ParsedSecretItem {
  id: string
  key: string
  value: string
  comment?: string
  selected: boolean
}

export function parseEnvContent(raw: string): Omit<ParsedSecretItem, 'id' | 'selected'>[] {
  const trimmed = raw.trim()
  if (!trimmed) return []

  // Check if JSON object
  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    try {
      const obj = JSON.parse(trimmed)
      return Object.entries(obj).map(([k, v]) => ({
        key: k.trim(),
        value: typeof v === 'object' ? JSON.stringify(v) : String(v),
      }))
    } catch {}
  }

  // Parse lines (.env / dotenv)
  const lines = raw.split(/\r?\n/)
  const result: Omit<ParsedSecretItem, 'id' | 'selected'>[] = []
  let pendingComment = ''

  for (let line of lines) {
    line = line.trim()
    if (!line) {
      pendingComment = ''
      continue
    }
    if (line.startsWith('#')) {
      pendingComment = line.replace(/^#+\s*/, '')
      continue
    }
    // Strip "export " prefix
    if (line.startsWith('export ')) {
      line = line.slice(7).trim()
    }
    const eqIdx = line.indexOf('=')
    const colonIdx = line.indexOf(':')

    let key = ''
    let val = ''

    const useColon =
      colonIdx !== -1 &&
      (eqIdx === -1 || colonIdx < eqIdx) &&
      /^[a-zA-Z_][a-zA-Z0-9_.-]*$/.test(line.slice(0, colonIdx).trim())

    if (useColon) {
      key = line.slice(0, colonIdx).trim()
      val = line.slice(colonIdx + 1).trim()
    } else if (eqIdx !== -1) {
      key = line.slice(0, eqIdx).trim()
      val = line.slice(eqIdx + 1).trim()
    } else if (colonIdx !== -1) {
      key = line.slice(0, colonIdx).trim()
      val = line.slice(colonIdx + 1).trim()
    } else {
      continue
    }

    // Strip surrounding quotes
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      const quote = val[0]
      val = val.slice(1, -1)
      if (quote === '"') {
        val = val.replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\"/g, '"')
      }
    }

    if (key) {
      result.push({
        key,
        value: val,
        comment: pendingComment || undefined,
      })
      pendingComment = ''
    }
  }

  return result
}

function ImportModal({
  projectId,
  envSlug,
  existingSecrets,
  onClose,
}: {
  projectId: string
  envSlug: string
  existingSecrets: Secret[]
  onClose: () => void
}) {
  const [step, setStep] = useState<'paste' | 'select'>('paste')
  const [rawText, setRawText] = useState('')
  const [targetPath, setTargetPath] = useState('/')
  const [overwrite, setOverwrite] = useState(true)
  const [items, setItems] = useState<ParsedSecretItem[]>([])
  const [filterQuery, setFilterQuery] = useState('')
  const [showValues, setShowValues] = useState(false)
  const [busy, setBusy] = useState(false)

  const existingKeyMap = useMemo(() => {
    const map = new Map<string, Secret>()
    for (const s of existingSecrets) {
      map.set(s.key, s)
    }
    return map
  }, [existingSecrets])

  const handleParse = (e: React.FormEvent) => {
    e.preventDefault()
    const parsed = parseEnvContent(rawText)
    if (parsed.length === 0) {
      toast.err(t('No valid key-value pairs or secrets found in pasted content'))
      return
    }
    const newItems: ParsedSecretItem[] = parsed.map((p, idx) => ({
      id: `${p.key}_${idx}_${Date.now()}`,
      key: p.key,
      value: p.value,
      comment: p.comment,
      selected: true,
    }))
    setItems(newItems)
    setStep('select')
  }

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (ev) => {
      const text = ev.target?.result
      if (typeof text === 'string') {
        setRawText(text)
      }
    }
    reader.readAsText(file)
  }

  const toggleSelectAll = () => {
    const allSelected = items.every((i) => i.selected)
    setItems(items.map((i) => ({ ...i, selected: !allSelected })))
  }

  const toggleItem = (id: string) => {
    setItems(items.map((i) => (i.id === id ? { ...i, selected: !i.selected } : i)))
  }

  const removeItem = (id: string) => {
    setItems(items.filter((i) => i.id !== id))
  }

  const updateItemKey = (id: string, newKey: string) => {
    setItems(items.map((i) => (i.id === id ? { ...i, key: newKey } : i)))
  }

  const updateItemValue = (id: string, newVal: string) => {
    setItems(items.map((i) => (i.id === id ? { ...i, value: newVal } : i)))
  }

  const selectedCount = items.filter((i) => i.selected).length
  const newCount = items.filter((i) => i.selected && !existingKeyMap.has(i.key)).length
  const overwriteCount = items.filter((i) => i.selected && existingKeyMap.has(i.key)).length

  const filteredItems = useMemo(() => {
    const q = filterQuery.toLowerCase().trim()
    if (!q) return items
    return items.filter((i) => i.key.toLowerCase().includes(q) || i.value.toLowerCase().includes(q))
  }, [items, filterQuery])

  const submitImport = async () => {
    const selected = items.filter((i) => i.selected)
    if (selected.length === 0) {
      toast.err(t('Please select at least one secret to import'))
      return
    }
    setBusy(true)
    try {
      const res = await api.post<ImportSecretsResponse>(
        `/projects/${enc(projectId)}/environments/${enc(envSlug)}/secrets/import`,
        {
          path: targetPath,
          overwrite,
          secrets: selected.map((s): ImportSecretItem => ({
            key: s.key,
            value: s.value,
            comment: s.comment,
          })),
        }
      )
      invalidate('/projects')
      toast.ok(
        t('Successfully imported {0} secrets ({1} created, {2} updated)', res.total, res.created, res.updated)
      )
      onClose()
    } catch (err: any) {
      toast.err(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      title={step === 'paste' ? t('Import Secrets into {0}', envSlug) : t('Select Secrets to Import ({0} found)', items.length)}
      wide
      onClose={onClose}
    >
      {step === 'paste' ? (
        <form onSubmit={handleParse}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
            <span className="muted small">
              {t('Paste your .env, JSON, or YAML content, or choose a file from your computer:')}
            </span>
            <label className="btn btn-xs btn-ghost" style={{ cursor: 'pointer', margin: 0 }}>
              <Upload size={12} style={{ marginRight: 4 }} />
              {t('Choose File…')}
              <input type="file" style={{ display: 'none' }} accept=".env*,.txt,.json,.yaml,.yml" onChange={handleFileUpload} />
            </label>
          </div>

          <Field label={t('.env or Key-Value Content')}>
            <textarea
              required
              autoFocus
              className="mono"
              rows={12}
              style={{ fontSize: 13, width: '100%' }}
              placeholder={`# Paste your .env file here\nPORT=8080\nDATABASE_URL="postgres://user:password@localhost:5432/app"\nAPI_KEY=sk_live_123456789`}
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
            />
          </Field>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginTop: 12 }}>
            <Field label={t('Target Path / Folder')} help={t('Default root path /')}>
              <input value={targetPath} onChange={(e) => setTargetPath(e.target.value)} placeholder="/" />
            </Field>

            <div style={{ display: 'flex', alignItems: 'center', gap: 8, alignSelf: 'center', marginTop: 12 }}>
              <input
                type="checkbox"
                id="import-overwrite"
                checked={overwrite}
                onChange={(e) => setOverwrite(e.target.checked)}
              />
              <label htmlFor="import-overwrite" style={{ fontSize: 13, cursor: 'pointer', margin: 0 }}>
                {t('Overwrite existing secrets (creates new version)')}
              </label>
            </div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
            <button type="button" className="btn btn-ghost" onClick={onClose}>{t('Cancel')}</button>
            <button type="submit" className="btn btn-primary" disabled={!rawText.trim()}>
              {t('Parse Secrets & Select →')}
            </button>
          </div>
        </form>
      ) : (
        <div>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '10px 12px',
              background: 'var(--surface-2)',
              borderRadius: 6,
              marginBottom: 12,
              fontSize: 13,
            }}
          >
            <div>
              <strong>{t('{0} selected', selectedCount)}</strong>
              <span className="muted" style={{ marginLeft: 8 }}>
                ({newCount} {t('new')}, {overwriteCount} {t('will overwrite')})
              </span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <button type="button" className="btn btn-xs btn-ghost" onClick={toggleSelectAll}>
                {items.every((i) => i.selected) ? t('Deselect All') : t('Select All')}
              </button>
              <button type="button" className="btn btn-xs btn-ghost" onClick={() => setShowValues(!showValues)}>
                {showValues ? <EyeOff size={12} /> : <Eye size={12} />} {showValues ? t('Hide Values') : t('Show Values')}
              </button>
            </div>
          </div>

          <div style={{ marginBottom: 10 }}>
            <div className="search" style={{ width: '100%' }}>
              <Search size={14} />
              <input
                placeholder={t('Filter parsed secrets…')}
                value={filterQuery}
                onChange={(e) => setFilterQuery(e.target.value)}
              />
              {filterQuery && (
                <button type="button" className="icon-btn" onClick={() => setFilterQuery('')}>
                  <X size={13} />
                </button>
              )}
            </div>
          </div>

          <div
            style={{
              maxHeight: 380,
              overflowY: 'auto',
              border: '1px solid var(--border)',
              borderRadius: 6,
              background: 'var(--surface-1)',
            }}
          >
            <table className="table" style={{ margin: 0 }}>
              <thead>
                <tr>
                  <th style={{ width: 36, textAlign: 'center' }}>
                    <input
                      type="checkbox"
                      checked={items.length > 0 && items.every((i) => i.selected)}
                      onChange={toggleSelectAll}
                    />
                  </th>
                  <th style={{ width: 220 }}>{t('Key')}</th>
                  <th>{t('Value')}</th>
                  <th style={{ width: 120 }}>{t('Status')}</th>
                  <th style={{ width: 36 }} />
                </tr>
              </thead>
              <tbody>
                {filteredItems.map((item) => {
                  const existing = existingKeyMap.get(item.key)
                  return (
                    <tr key={item.id} style={{ opacity: item.selected ? 1 : 0.5 }}>
                      <td style={{ textAlign: 'center' }}>
                        <input
                          type="checkbox"
                          checked={item.selected}
                          onChange={() => toggleItem(item.id)}
                        />
                      </td>
                      <td>
                        <input
                          className="mono"
                          style={{ fontSize: 13, fontWeight: 600, padding: '2px 6px' }}
                          value={item.key}
                          onChange={(e) => updateItemKey(item.id, e.target.value.toUpperCase())}
                        />
                      </td>
                      <td>
                        <input
                          type={showValues ? 'text' : 'password'}
                          className="mono"
                          style={{ fontSize: 13, padding: '2px 6px', width: '100%' }}
                          value={item.value}
                          onChange={(e) => updateItemValue(item.id, e.target.value)}
                        />
                      </td>
                      <td>
                        {existing ? (
                          <Tag tone="warn" title={t('Already exists (v{0}). Importing will create v{1}.', existing.version, existing.version + 1)}>
                            {t('OVERWRITE')}
                          </Tag>
                        ) : (
                          <Tag tone="good">
                            {t('NEW')}
                          </Tag>
                        )}
                      </td>
                      <td style={{ textAlign: 'center' }}>
                        <button
                          type="button"
                          className="icon-btn"
                          style={{ color: '#ef4444' }}
                          title={t('Remove from import')}
                          onClick={() => removeItem(item.id)}
                        >
                          <Trash2 size={13} />
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 16 }}>
            <button type="button" className="btn btn-ghost" onClick={() => setStep('paste')}>
              {t('← Edit Raw Text')}
            </button>
            <div style={{ display: 'flex', gap: 8 }}>
              <button type="button" className="btn btn-ghost" onClick={onClose}>
                {t('Cancel')}
              </button>
              <button
                type="button"
                className="btn btn-primary"
                disabled={busy || selectedCount === 0}
                onClick={submitImport}
              >
                {busy ? <Spinner /> : t('Import {0} Secrets', selectedCount)}
              </button>
            </div>
          </div>
        </div>
      )}
    </Modal>
  )
}

function EnvironmentModal({ projectId, onClose }: { projectId: string; onClose: () => void }) {
  const [name, setName] = useState('')
  const [slug, setSlug] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    try {
      await api.post(`/projects/${enc(projectId)}/environments`, {
        name,
        slug: slug || undefined,
      })
      toast.ok(t('Environment created'))
      invalidate('/projects')
      onClose()
    } catch (err) {
      toast.err(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal title={t('Add Environment')} onClose={onClose}>
      <form onSubmit={submit}>
        <Field label={t('Name')}>
          <input required autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Preview or Testing" />
        </Field>
        <Field label={t('Slug')} help={t('Identifier for CLI and API (e.g. preview, test)')}>
          <input value={slug} onChange={(e) => setSlug(e.target.value)} placeholder="e.g. preview" />
        </Field>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
          <button type="button" className="btn btn-ghost" onClick={onClose}>{t('Cancel')}</button>
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? <Spinner /> : t('Create Environment')}
          </button>
        </div>
      </form>
    </Modal>
  )
}

async function removeProject(p: Project) {
  if (
    !(await confirm({
      title: t('Delete {0}?', p.name),
      body: t('This will permanently delete the project, all its environments, and all encrypted secrets.'),
      danger: true,
      confirm: t('Delete Project'),
    }))
  ) {
    return
  }
  api.del(`/projects/${enc(p.id)}`).then(() => {
    invalidate('/projects')
    go('projects')
    toast.ok(t('Project deleted'))
  }, toast.err)
}

async function removeSecret(projectId: string, envSlug: string, s: Secret) {
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

function TokensView({ projectId, envs }: { projectId: string; envs: Environment[] }) {
  const { data: tokens, error, loading } = useResource<ServiceToken[]>(`/projects/${enc(projectId)}/tokens`)
  const [q, setQ] = useState('')
  const [envFilter, setEnvFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'burned'>('all')

  const tokenActions = (tk: ServiceToken): MenuEntry[] => [
    { header: tk.name },
    { label: t('Revoke Token'), icon: <Trash2 size={14} />, danger: true, onClick: () => removeToken(projectId, tk) },
  ]

  const rows = useMemo(() => {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean)
    return (tokens || []).filter((tk) => {
      if (envFilter && tk.environment_slug !== '*' && tk.environment_slug !== envFilter) return false
      if (statusFilter === 'active' && tk.burned_at) return false
      if (statusFilter === 'burned' && !tk.burned_at) return false
      return words.every((w) => `${tk.name} ${tk.token_prefix} ${tk.environment_slug} ${tk.allowed_cidrs || ''}`.toLowerCase().includes(w))
    })
  }, [tokens, q, envFilter, statusFilter])

  return (
    <div>
      <div className="vault-toolbar">
        <div className="vault-toolbar-left">
          <div className="search">
            <Search size={14} />
            <input placeholder={t('Filter tokens…')} value={q} onChange={(e) => setQ(e.currentTarget.value)} />
            {q && <button className="icon-btn" onClick={() => setQ('')}><X size={13} /></button>}
          </div>

          <select
            className="vault-select"
            value={envFilter}
            onChange={(e) => setEnvFilter(e.target.value)}
            title={t('Filter by environment scope')}
          >
            <option value="">{t('All Scopes')}</option>
            <option value="*">{t('All Environments (*)')}</option>
            {envs.map((e) => (
              <option key={e.slug} value={e.slug}>{e.name} ({e.slug})</option>
            ))}
          </select>

          <select
            className="vault-select"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as any)}
            title={t('Filter by token status')}
          >
            <option value="all">{t('All Statuses')}</option>
            <option value="active">{t('Active')}</option>
            <option value="burned">{t('Burned (Single-use)')}</option>
          </select>
        </div>

        <div className="vault-toolbar-right">
          <button
            className="btn btn-primary btn-sm"
            onClick={() => openDialog((c) => <TokenModal projectId={projectId} envs={envs} onClose={c} />)}
          >
            <Plus size={14} /> {t('Generate Token')}
          </button>
        </div>
      </div>

      {error && <div className="alert alert-bad">{error.message}</div>}
      {loading && <Spinner />}

      {tokens && tokens.length === 0 ? (
        <Empty
          icon={<KeyRound size={32} />}
          title={t('No service tokens yet')}
          action={
            <button
              className="btn btn-primary"
              onClick={() => openDialog((c) => <TokenModal projectId={projectId} envs={envs} onClose={c} />)}
            >
              <Plus size={14} /> {t('Generate Token')}
            </button>
          }
        >
          {t('Generate scoped tokens (duck_st_*) to inject secrets into containers or CI without a user session.')}
        </Empty>
      ) : (
        <DataTable
          rows={rows}
          rowKey={(tk) => tk.id}
          rowMenu={tokenActions}
          defaultSort={{ key: 'created', dir: -1 }}
          columns={[
            {
              key: 'name',
              label: t('Name'),
              render: (tk) => (
                <div>
                  <strong>{tk.name}</strong>
                  <div className="muted small mono">{tk.token_prefix}</div>
                </div>
              ),
            },
            {
              key: 'scope',
              label: t('Scope'),
              render: (tk) => (
                <Tag tone="accent">
                  {tk.environment_slug === '*' ? t('All Environments') : tk.environment_slug}
                </Tag>
              ),
            },
            {
              key: 'permissions',
              label: t('Permissions'),
              render: (tk) => <span className="muted small mono">{tk.permissions}</span>,
            },
            {
              key: 'security',
              label: t('Security'),
              render: (tk) => (
                <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
                  {tk.single_use ? (
                    tk.burned_at ? (
                      <Tag tone="bad" title={t('Burned at {0}', dateTime(tk.burned_at))}>
                        <Flame size={10} style={{ marginRight: 3 }} /> {t('BURNED')}
                      </Tag>
                    ) : (
                      <Tag tone="warning" title={t('Will auto-destruct on first secret retrieval')}>
                        <Flame size={10} style={{ marginRight: 3 }} /> {t('SINGLE-USE')}
                      </Tag>
                    )
                  ) : null}
                  {tk.allowed_cidrs ? (
                    <span className="muted small mono" title={t('Allowed networks: {0}', tk.allowed_cidrs.replace(/[\n\r]+/g, ', '))} style={{ display: 'inline-flex', alignItems: 'center' }}>
                      <ShieldCheck size={12} style={{ marginRight: 3, color: 'var(--tone-good)' }} />
                      {(() => {
                        const clean = tk.allowed_cidrs.replace(/[\n\r]+/g, ', ')
                        return clean.length > 20 ? clean.slice(0, 18) + '…' : clean
                      })()}
                    </span>
                  ) : (
                    <span className="muted small">{t('Any network')}</span>
                  )}
                </div>
              ),
            },
            {
              key: 'created',
              label: t('Created'),
              sort: (tk) => tk.created_at,
              render: (tk) => (
                <span className="muted small" title={dateTime(tk.created_at)}>
                  {ago(tk.created_at)} {tk.created_by ? t('by {0}', tk.created_by) : ''}
                </span>
              ),
            },
            {
              key: 'last_used',
              label: t('Last Used'),
              render: (tk) => (
                <span className="muted small">
                  {tk.last_used_at ? ago(tk.last_used_at) : t('Never')}
                </span>
              ),
            },
          ]}
        />
      )}
    </div>
  )
}

function TokenModal({ projectId, envs, onClose }: { projectId: string; envs: Environment[]; onClose: () => void }) {
  const [name, setName] = useState('')
  const [envSlug, setEnvSlug] = useState('*')
  const [permissions, setPermissions] = useState('secrets.read')
  const [allowedCidrs, setAllowedCidrs] = useState('')
  const [singleUse, setSingleUse] = useState(false)
  const [expiresInDays, setExpiresInDays] = useState(0)
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    try {
      const res = await api.post<CreatedServiceToken>(`/projects/${enc(projectId)}/tokens`, {
        name,
        environment_slug: envSlug,
        permissions,
        allowed_cidrs: allowedCidrs.trim() || undefined,
        single_use: singleUse,
        expires_in_days: expiresInDays || undefined,
      })
      invalidate('/projects')
      onClose()
      openDialog((c) => <TokenSuccessModal token={res} onClose={c} />)
    } catch (err: any) {
      toast.err(err)
    } finally {
      setBusy(false)
    }
  }

  const appendCidr = (cidr: string) => {
    const trimmed = allowedCidrs.trim()
    if (!trimmed) {
      setAllowedCidrs(cidr)
      return
    }
    const parts = trimmed.split(/[\n,;\s]+/).map((s) => s.trim()).filter(Boolean)
    if (!parts.includes(cidr)) {
      setAllowedCidrs([...parts, cidr].join('\n'))
    }
  }

  const parsedCidrs = useMemo(() => {
    return allowedCidrs
      .split(/[\n,;\s]+/)
      .map((s) => s.trim())
      .filter(Boolean)
  }, [allowedCidrs])

  return (
    <Modal
      title={t('Generate Service Token')}
      wide="xl"
      allowFullscreen
      onClose={onClose}
      footer={
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, width: '100%' }}>
          <button type="button" className="btn btn-ghost" onClick={onClose}>{t('Cancel')}</button>
          <button type="submit" form="token-form" className="btn btn-primary" disabled={busy}>
            {busy ? <Spinner /> : t('Generate Token')}
          </button>
        </div>
      }
    >
      <form id="token-form" onSubmit={submit}>
        <div className="modal-two-col">
          {/* Left Column: Scope & Identity */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <Field label={t('Token Name')} help={t('Descriptive label (e.g. GitHub Actions, Docker Staging Agent)')}>
              <input required autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. CI / CD Runner" />
            </Field>

            <Field label={t('Environment Scope')} help={t('Restrict token to a specific project environment or grant wildcard access')}>
              <select value={envSlug} onChange={(e) => setEnvSlug(e.target.value)}>
                <option value="*">{t('All Environments (*)')}</option>
                {envs.map((env) => (
                  <option key={env.id} value={env.slug}>{env.name} ({env.slug})</option>
                ))}
              </select>
            </Field>

            <Field label={t('Permissions')}>
              <select value={permissions} onChange={(e) => setPermissions(e.target.value)}>
                <option value="secrets.read">{t('Read Only (secrets.read)')}</option>
                <option value="secrets.read secrets.write">{t('Read & Write (secrets.read, secrets.write)')}</option>
              </select>
            </Field>

            <Field label={t('Expiration')}>
              <select value={expiresInDays} onChange={(e) => setExpiresInDays(Number(e.target.value))}>
                <option value={0}>{t('Never expires')}</option>
                <option value={30}>{t('30 days')}</option>
                <option value={90}>{t('90 days')}</option>
                <option value={365}>{t('1 year')}</option>
              </select>
            </Field>
          </div>

          {/* Right Column: Hardening, CIDR & Usage Preview */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {/* Network Whitelist Card */}
            <div style={{ padding: '12px 14px', background: 'var(--surface-2, var(--bg-subtle))', borderRadius: 8, border: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{ fontSize: 12, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Network size={14} style={{ color: 'var(--accent)' }} />
                  {t('CIDR IP Whitelisting')}
                </span>
                <Tag tone={allowedCidrs.trim() ? 'good' : 'accent'} mono style={{ fontSize: 10 }}>
                  {allowedCidrs.trim() ? t('Restricted') : t('Any IP')}
                </Tag>
              </div>
              <p className="muted small" style={{ margin: '0 0 8px 0', fontSize: 11, lineHeight: 1.4 }}>
                {t('Reject requests if origin IP is not within these CIDR subnets. Separate by newlines, commas, or spaces.')}
              </p>
              <textarea
                rows={4}
                className="mono"
                style={{ fontSize: 12, lineHeight: 1.4, resize: 'vertical' }}
                value={allowedCidrs}
                onChange={(e) => setAllowedCidrs(e.target.value)}
                placeholder={`127.0.0.1/32\n172.17.0.0/16\n10.0.0.0/8`}
              />
              {parsedCidrs.length > 0 && (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 6, alignItems: 'center' }}>
                  <span className="muted small" style={{ fontSize: 10 }}>{t('{0} active subnet(s):', parsedCidrs.length)}</span>
                  {parsedCidrs.map((c) => (
                    <Tag key={c} tone="good" mono style={{ fontSize: 10 }}>
                      {c}
                    </Tag>
                  ))}
                </div>
              )}
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 8, alignItems: 'center' }}>
                <span className="muted small" style={{ fontSize: 10 }}>{t('Quick Presets:')}</span>
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  style={{ padding: '1px 6px', fontSize: 10, height: 'auto', border: '1px dashed var(--border)' }}
                  onClick={() => appendCidr('127.0.0.1/32')}
                >
                  + 127.0.0.1/32 (Host)
                </button>
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  style={{ padding: '1px 6px', fontSize: 10, height: 'auto', border: '1px dashed var(--border)' }}
                  onClick={() => appendCidr('172.17.0.0/16')}
                >
                  + 172.17.0.0/16 (Docker)
                </button>
                <button
                  type="button"
                  className="btn btn-ghost btn-sm"
                  style={{ padding: '1px 6px', fontSize: 10, height: 'auto', border: '1px dashed var(--border)' }}
                  onClick={() => appendCidr('10.0.0.0/8')}
                >
                  + 10.0.0.0/8 (VPC)
                </button>
              </div>
            </div>

            {/* Zero-Trust Single-Use Card */}
            <div style={{ padding: '12px 14px', background: 'var(--surface-2, var(--bg-subtle))', borderRadius: 8, border: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{ fontSize: 12, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Flame size={14} style={{ color: singleUse ? '#ea580c' : 'var(--muted)' }} />
                  {t('Single-Use Token')}
                </span>
                {singleUse && <Tag tone="bad" mono style={{ fontSize: 10 }}>{t('BURNS AFTER READ')}</Tag>}
              </div>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: 12, fontWeight: 500, margin: '6px 0 4px 0' }}>
                <input type="checkbox" checked={singleUse} onChange={(e) => setSingleUse(e.target.checked)} />
                <span>{t('Burn token permanently on first secrets read')}</span>
              </label>
              <p className="muted small" style={{ margin: 0, fontSize: 11, lineHeight: 1.4 }}>
                {t('Useful for containers: the token expires after its first read so it cannot be reused.')}
              </p>
            </div>

            {/* Usage Preview Snippet */}
            <div style={{ padding: '10px 14px', background: 'var(--bg-subtle)', borderRadius: 8, border: '1px solid var(--border)', fontSize: 11 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                <Code size={13} style={{ color: 'var(--accent)' }} />
                <strong>{t('CLI / CI Usage Pattern')}</strong>
              </div>
              <div className="mono" style={{ padding: '6px 8px', background: 'var(--bg)', borderRadius: 4, border: '1px solid var(--border)', fontSize: 11, color: 'var(--muted)' }}>
                export DUCKSECRETS_TOKEN=duck_st_...<br />
                ducksecrets run -- ./start.sh
              </div>
            </div>
          </div>
        </div>
      </form>
    </Modal>
  )
}

function TokenSuccessModal({ token, onClose }: { token: CreatedServiceToken; onClose: () => void }) {
  const [copied, setCopied] = useState(false)

  const copyToken = () => {
    copy(token.raw_token).then((ok) => {
      if (ok) {
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
        toast.ok(t('Token copied to clipboard'))
      }
    })
  }

  return (
    <Modal title={t('Service Token Created')} wide onClose={onClose}>
      <div className="alert alert-bad" style={{ marginBottom: 16 }}>
        <strong>{t('Copy your token now.')}</strong> {t('This is the only time it will ever be shown!')}
      </div>

      <Field label={t('Secret Token')}>
        <div style={{ display: 'flex', gap: 8 }}>
          <input readOnly className="mono" value={token.raw_token} style={{ flex: 1, fontSize: 13 }} />
          <button className="btn btn-sm btn-primary" onClick={copyToken}>
            {copied ? <Check size={14} /> : <Copy size={14} />} {copied ? t('Copied') : t('Copy')}
          </button>
        </div>
      </Field>

      <div style={{ marginTop: 16, padding: 12, background: 'var(--bg-subtle)', borderRadius: 6 }}>
        <p className="muted small" style={{ margin: '0 0 6px' }}><strong>{t('CLI & CI/CD Usage:')}</strong></p>
        <pre className="mono small" style={{ margin: 0, padding: 8, background: 'var(--bg)', borderRadius: 4 }}>
{`# Authenticate CLI
ducksecrets login --server=https://... --token=${token.raw_token}

# Or inject directly in CI/CD / Docker
export DUCKSECRETS_TOKEN="${token.raw_token}"
ducksecrets run -- npm start`}
        </pre>
      </div>

      <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 16 }}>
        <button className="btn btn-primary" onClick={onClose}>{t('Done')}</button>
      </div>
    </Modal>
  )
}

async function removeToken(projectId: string, tk: ServiceToken) {
  if (
    !(await confirm({
      title: t('Revoke {0}?', tk.name),
      body: t('Any CI pipeline or container using this token will immediately lose access.'),
      danger: true,
      confirm: t('Revoke Token'),
    }))
  ) {
    return
  }
  api.del(`/projects/${enc(projectId)}/tokens/${enc(tk.id)}`).then(() => {
    invalidate('/projects')
    toast.ok(t('Token revoked'))
  }, toast.err)
}

// ---------------------------------------------------------
// DYNAMIC SECRETS (POSTGRES, MYSQL, REDIS, PAM)
// ---------------------------------------------------------

function DynamicView({ projectId, envSlug, envs }: { projectId: string; envSlug: string; envs: Environment[] }) {
  const [selectedEnv, setSelectedEnv] = useState(envSlug)
  const currentEnv = envs.some((e) => e.slug === selectedEnv) ? selectedEnv : envs[0]?.slug || 'dev'
  const { data: providers, loading, error } = useResource<DynamicProvider[]>(
    `/projects/${enc(projectId)}/environments/${enc(currentEnv)}/dynamic`
  )
  const { data: sites } = useResource<Site[]>(`/projects/${enc(projectId)}/sites`)
  const [activeLeasesProvId, setActiveLeasesProvId] = useState<string | null>(null)
  const menu = useMenu()

  const providerActions = (p: DynamicProvider): MenuEntry[] => [
    { header: p.name },
    { label: t('Test Connection'), icon: <Activity size={14} />, onClick: () => testProvider(p.id) },
    { label: t('Issue Credentials…'), icon: <KeyRound size={14} />, onClick: () => openDialog((c) => <IssueLeaseModal projectId={projectId} envSlug={currentEnv} provider={p} onClose={c} />) },
    { label: t('Active Leases'), icon: <Clock size={14} />, onClick: () => setActiveLeasesProvId(activeLeasesProvId === p.id ? null : p.id) },
    'sep',
    { label: t('Delete Provider'), icon: <Trash2 size={14} />, danger: true, onClick: () => deleteProvider(p.id, p.name) },
  ]

  const testProvider = (provId: string) => {
    api
      .post<TestProviderResponse>(`/projects/${enc(projectId)}/environments/${enc(currentEnv)}/dynamic/${enc(provId)}/test`, {})
      .then((res) => {
        if (res.success) {
          toast.ok(res.message)
        } else {
          toast.err(res.message)
        }
      })
      .catch(toast.err)
  }

  const deleteProvider = async (provId: string, name: string) => {
    if (
      !(await confirm({
        title: t('Delete {0}?', name),
        body: t('Deleting this provider will also revoke all active leases.'),
        danger: true,
        confirm: t('Delete Provider'),
      }))
    ) {
      return
    }
    api.del(`/projects/${enc(projectId)}/environments/${enc(currentEnv)}/dynamic/${enc(provId)}`).then(() => {
      invalidate('/projects')
      toast.ok(t('Provider deleted'))
    }, toast.err)
  }

  const [q, setQ] = useState('')
  const [engineFilter, setEngineFilter] = useState('')

  const filteredProviders = useMemo(() => {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean)
    return (providers || []).filter((p) => {
      if (engineFilter && p.engine !== engineFilter) return false
      return words.every((w) => `${p.name} ${p.engine}`.toLowerCase().includes(w))
    })
  }, [providers, q, engineFilter])

  return (
    <div>
      <div className="vault-subnav">
        <Tabs
          tabs={envs.map((e) => ({ id: e.slug, label: e.name }))}
          active={currentEnv}
          onChange={(slug) => setSelectedEnv(slug)}
        />
        <span className="muted small">{t('{0} engines configured', (providers || []).length)}</span>
      </div>

      <div className="vault-toolbar">
        <div className="vault-toolbar-left">
          <div className="search">
            <Search size={14} />
            <input placeholder={t('Filter dynamic engines…')} value={q} onChange={(e) => setQ(e.currentTarget.value)} />
            {q && <button className="icon-btn" onClick={() => setQ('')}><X size={13} /></button>}
          </div>

          <select
            className="vault-select"
            value={engineFilter}
            onChange={(e) => setEngineFilter(e.target.value)}
            title={t('Filter by engine type')}
          >
            <option value="">{t('All Engines')}</option>
            <option value="postgres">PostgreSQL</option>
            <option value="mysql">MySQL / MariaDB</option>
            <option value="redis">Redis</option>
            <option value="pam">Linux PAM / SSH</option>
          </select>
        </div>

        <div className="vault-toolbar-right">
          <button
            className="btn btn-primary btn-sm"
            onClick={() => openDialog((c) => <DynamicProviderModal projectId={projectId} envSlug={currentEnv} onClose={c} />)}
          >
            <Plus size={14} /> {t('Add Dynamic Provider')}
          </button>
        </div>
      </div>

      {loading && <div className="center" style={{ padding: 24 }}><Spinner /></div>}
      {error && <div className="alert alert-bad">{error.message}</div>}

      {providers && providers.length === 0 ? (
        <Empty
          icon={<Database size={32} />}
          title={t('No dynamic secret engines in {0}', currentEnv)}
          action={
            <button className="btn btn-primary" onClick={() => openDialog((c) => <DynamicProviderModal projectId={projectId} envSlug={currentEnv} onClose={c} />)}>
              <Plus size={14} /> {t('Configure Dynamic Engine')}
            </button>
          }
        >
          <p>{t('Configure on-demand ephemeral credentials for PostgreSQL, MySQL, Redis, or PAM server access.')}</p>
        </Empty>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: 16 }}>
          {filteredProviders.map((p) => (
            <div key={p.id} className="card" onContextMenu={menu(() => providerActions(p))} style={{ padding: 16, borderRadius: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  {p.engine === 'pam' ? <Server size={18} color="#ea580c" /> : <Database size={18} color="#2563eb" />}
                  <strong>{p.name}</strong>
                </div>
                <div style={{ display: 'flex', gap: 6 }}>
                  {p.site_id && (
                    <Tag tone="accent">
                      <Network size={11} style={{ marginRight: 4 }} />
                      {sites?.find((s) => s.id === p.site_id)?.name || t('Site Gateway')}
                    </Tag>
                  )}
                  {p.enforced_port ? (
                    <Tag tone="bad">{t('Port :{0}', p.enforced_port)}</Tag>
                  ) : (
                    <Tag tone="good">{t('Ephemeral port')}</Tag>
                  )}
                  <Tag>{p.engine.toUpperCase()}</Tag>
                </div>
              </div>

              <div style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 16 }}>
                <div>{t('Default TTL: {0}s ({1}m)', p.default_ttl_seconds, Math.round(p.default_ttl_seconds / 60))}</div>
                <div>{t('Max TTL: {0}s ({1}h)', p.max_ttl_seconds, Math.round(p.max_ttl_seconds / 3600))}</div>
                {p.role_template && <div className="ellipsis" style={{ marginTop: 4 }}><code>{p.role_template}</code></div>}
              </div>

              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, borderTop: '1px solid var(--border)', paddingTop: 12 }}>
                <button
                  className="btn btn-sm btn-subtle"
                  onClick={() => testProvider(p.id)}
                  title={t('Verify connectivity')}
                >
                  <Activity size={13} /> {t('Test')}
                </button>
                <button
                  className="btn btn-sm btn-primary"
                  onClick={() => openDialog((c) => <IssueLeaseModal projectId={projectId} envSlug={currentEnv} provider={p} onClose={c} />)}
                >
                  <KeyRound size={13} /> {t('Issue Credentials')}
                </button>
                <button
                  className="btn btn-sm btn-ghost"
                  onClick={() => setActiveLeasesProvId(activeLeasesProvId === p.id ? null : p.id)}
                >
                  <Clock size={13} /> {t('Active Leases')}
                </button>
                <button
                  className="icon-btn"
                  style={{ marginLeft: 'auto', color: '#ef4444' }}
                  onClick={() => deleteProvider(p.id, p.name)}
                >
                  <Trash2 size={14} />
                </button>
              </div>

              {activeLeasesProvId === p.id && (
                <div style={{ marginTop: 12, borderTop: '1px dashed var(--border)', paddingTop: 8 }}>
                  <ActiveLeasesList projectId={projectId} envSlug={currentEnv} providerId={p.id} />
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function ActiveLeasesList({ projectId, envSlug, providerId }: { projectId: string; envSlug: string; providerId: string }) {
  const { data: leases, loading } = useResource<DynamicLease[]>(
    `/projects/${enc(projectId)}/environments/${enc(envSlug)}/dynamic/${enc(providerId)}/leases`
  )

  const revoke = (leaseId: string) => {
    api.del(`/projects/${enc(projectId)}/environments/${enc(envSlug)}/dynamic/${enc(providerId)}/leases/${enc(leaseId)}`).then(() => {
      invalidate('/projects')
      toast.ok(t('Lease revoked'))
    }, toast.err)
  }

  if (loading) return <Spinner />
  if (!leases || leases.length === 0) return <p className="muted small">{t('No active leases.')}</p>

  return (
    <div>
      <p className="muted small" style={{ fontWeight: 600, marginBottom: 6 }}>{t('Active Leases ({0}):', leases.length)}</p>
      {leases.map((l) => (
        <div key={l.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '4px 0', fontSize: 12 }}>
          <div>
            <code style={{ marginRight: 6 }}>{l.username}</code>
            <span className="muted">({l.issued_to})</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span className="muted">{t('Expires: {0}', new Date(l.expires_at).toLocaleTimeString())}</span>
            <button className="btn btn-sm btn-ghost" style={{ color: '#ef4444', padding: '2px 6px' }} onClick={() => revoke(l.id)}>
              {t('Revoke')}
            </button>
          </div>
        </div>
      ))}
    </div>
  )
}

function DynamicProviderModal({ projectId, envSlug, onClose }: { projectId: string; envSlug: string; onClose: () => void }) {
  const { data: sites } = useResource<Site[]>(`/projects/${enc(projectId)}/sites`)
  const [name, setName] = useState('')
  const [engine, setEngine] = useState('postgres')
  const [config, setConfig] = useState('{"connection_url": "postgres://user:password@localhost:5432/app"}')
  const [defaultTTL, setDefaultTTL] = useState(3600)
  const [maxTTL, setMaxTTL] = useState(86400)
  const [enforcedPort, setEnforcedPort] = useState(0)
  const [siteId, setSiteId] = useState('')
  const [roleTemplate, setRoleTemplate] = useState('')
  const [busy, setBusy] = useState(false)

  const handleEngineChange = (e: string) => {
    setEngine(e)
    if (e === 'postgres') {
      setConfig('{"connection_url": "postgres://user:password@localhost:5432/app"}')
      setRoleTemplate('GRANT USAGE ON SCHEMA public TO {{name}}; GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};')
    } else if (e === 'mysql') {
      setConfig('{"dsn": "root:secret@tcp(127.0.0.1:3306)/app"}')
      setRoleTemplate('GRANT SELECT ON *.* TO {{name}};')
    } else if (e === 'redis') {
      setConfig('{"address": "127.0.0.1:6379", "password": "", "acl_rules": "~* +@read"}')
      setRoleTemplate('~* +@read')
    } else if (e === 'pam') {
      setConfig('{"mode": "local", "default_shell": "/bin/bash", "groups": "developers"}')
      setRoleTemplate('')
    }
  }

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    api
      .post(`/projects/${enc(projectId)}/environments/${enc(envSlug)}/dynamic`, {
        name,
        engine,
        config,
        default_ttl_seconds: Number(defaultTTL),
        max_ttl_seconds: Number(maxTTL),
        role_template: roleTemplate,
        enforced_port: Number(enforcedPort) || 0,
        site_id: siteId || undefined,
      })
      .then(() => {
        invalidate('/projects')
        toast.ok(t('Dynamic provider created'))
        onClose()
      })
      .catch(toast.err)
      .finally(() => setBusy(false))
  }

  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null)
  const [testing, setTesting] = useState(false)

  const testConfig = () => {
    setTesting(true)
    setTestResult(null)
    api
      .post<{ success: boolean; message: string }>(`/projects/${enc(projectId)}/environments/${enc(envSlug)}/dynamic/test-config`, {
        engine,
        config,
      })
      .then((res) => {
        setTestResult(res)
        if (res.success) {
          toast.ok(res.message)
        } else {
          toast.err(res.message)
        }
      })
      .catch((err: any) => {
        setTestResult({ success: false, message: err.message || 'Connection failed' })
        toast.err(err)
      })
      .finally(() => setTesting(false))
  }

  const applyPreset = (template: string) => {
    setRoleTemplate(template)
    toast.ok(t('Preset applied to Role Template'))
  }

  return (
    <Modal
      title={t('Add Dynamic Secret Engine')}
      wide="xl"
      allowFullscreen
      onClose={onClose}
      footer={
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, width: '100%' }}>
          <button type="button" className="btn btn-ghost" onClick={onClose}>{t('Cancel')}</button>
          <button type="submit" form="dynamic-form" className="btn btn-primary" disabled={busy}>
            {busy ? <Spinner /> : t('Create Provider')}
          </button>
        </div>
      }
    >
      <form id="dynamic-form" onSubmit={submit}>
        <div className="modal-two-col">
          {/* Left Column: Target Engine & Connection Topology */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <Field label={t('Target Engine')}>
              <select value={engine} onChange={(e) => handleEngineChange(e.target.value)}>
                <option value="postgres">PostgreSQL</option>
                <option value="mysql">MySQL / MariaDB</option>
                <option value="redis">Redis (ACL)</option>
                <option value="pam">PAM / Linux Server Access</option>
              </select>
            </Field>

            <Field label={t('Provider Name')}>
              <input required placeholder="e.g. app-postgres-readonly" value={name} onChange={(e) => setName(e.target.value)} />
            </Field>

            <DynamicEngineConfigForm
              engine={engine}
              value={config}
              onChange={setConfig}
              onRoleTemplateChange={setRoleTemplate}
            />

            <div className="grid-2">
              <Field label={t('Default TTL (seconds)')}>
                <input type="number" min={60} value={defaultTTL} onChange={(e) => setDefaultTTL(Number(e.target.value))} />
              </Field>
              <Field label={t('Max TTL (seconds)')}>
                <input type="number" min={60} value={maxTTL} onChange={(e) => setMaxTTL(Number(e.target.value))} />
              </Field>
            </div>

            <div className="grid-2">
              <Field label={t('Enforced Local Port')} help={t('0 = dynamic ephemeral port')}>
                <input type="number" min={0} max={65535} placeholder="0 (ephemeral)" value={enforcedPort || ''} onChange={(e) => setEnforcedPort(Number(e.target.value))} />
              </Field>

              <Field label={t('Network Site Gateway')} help={t('Optional private VPC jump route')}>
                <select value={siteId} onChange={(e) => setSiteId(e.target.value)}>
                  <option value="">{t('Direct Connection')}</option>
                  {(sites || []).map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name} ({s.online ? t('ONLINE') : t('OFFLINE')})
                    </option>
                  ))}
                </select>
              </Field>
            </div>
          </div>

          {/* Right Column: Role Template & Object Permissions Inspector */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ padding: '12px 14px', background: 'var(--surface-2, var(--bg-subtle))', borderRadius: 8, border: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{ fontSize: 12, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Sparkles size={14} style={{ color: 'var(--accent)' }} />
                  {t('Role Template & Permissions SQL')}
                </span>
                <span className="mono muted small">{t('Placeholder: {{name}}')}</span>
              </div>
              <p className="muted small" style={{ margin: '0 0 8px 0', fontSize: 11, lineHeight: 1.4 }}>
                {t('SQL or ACL statements executed when provisioning each temporary user. Use {{name}} for the generated username.')}
              </p>

              <textarea
                rows={6}
                className="mono"
                style={{ fontSize: 12, lineHeight: 1.4, width: '100%', resize: 'vertical' }}
                value={roleTemplate}
                onChange={(e) => setRoleTemplate(e.target.value)}
                placeholder="GRANT USAGE ON SCHEMA public TO {{name}}; GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};"
              />

              {/* Engine Presets */}
              <div style={{ marginTop: 8 }}>
                <span className="muted small" style={{ fontSize: 11, display: 'block', marginBottom: 4 }}>
                  {t('Quick Permission Presets:')}
                </span>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {engine === 'postgres' && (
                    <>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        style={{ padding: '2px 6px', fontSize: 11, height: 'auto', border: '1px dashed var(--border)' }}
                        onClick={() => applyPreset('GRANT USAGE ON SCHEMA public TO {{name}}; GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};')}
                      >
                        + {t('Read-Only Public')}
                      </button>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        style={{ padding: '2px 6px', fontSize: 11, height: 'auto', border: '1px dashed var(--border)' }}
                        onClick={() => applyPreset('GRANT app_readonly TO {{name}};')}
                      >
                        + {t('Group Role (app_readonly)')}
                      </button>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        style={{ padding: '2px 6px', fontSize: 11, height: 'auto', border: '1px dashed var(--border)' }}
                        onClick={() => applyPreset('GRANT USAGE ON SCHEMA public TO {{name}}; GRANT SELECT, INSERT, UPDATE ON TABLE orders, customers TO {{name}};')}
                      >
                        + {t('Specific Tables')}
                      </button>
                    </>
                  )}
                  {engine === 'mysql' && (
                    <>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        style={{ padding: '2px 6px', fontSize: 11, height: 'auto', border: '1px dashed var(--border)' }}
                        onClick={() => applyPreset("GRANT SELECT ON *.* TO {{name}};")}
                      >
                        + {t('Read-Only (SELECT)')}
                      </button>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        style={{ padding: '2px 6px', fontSize: 11, height: 'auto', border: '1px dashed var(--border)' }}
                        onClick={() => applyPreset("GRANT 'app_reader' TO {{name}}; SET DEFAULT ROLE 'app_reader' TO {{name}};")}
                      >
                        + {t('Group Role (MySQL 8+)')}
                      </button>
                    </>
                  )}
                  {engine === 'redis' && (
                    <>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        style={{ padding: '2px 6px', fontSize: 11, height: 'auto', border: '1px dashed var(--border)' }}
                        onClick={() => applyPreset('~* +@read')}
                      >
                        + {t('Read-Only (~* +@read)')}
                      </button>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        style={{ padding: '2px 6px', fontSize: 11, height: 'auto', border: '1px dashed var(--border)' }}
                        onClick={() => applyPreset('~cache:* +@all -@dangerous')}
                      >
                        + {t('Restricted Cache Keys')}
                      </button>
                    </>
                  )}
                  {engine === 'pam' && (
                    <>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        style={{ padding: '2px 6px', fontSize: 11, height: 'auto', border: '1px dashed var(--border)' }}
                        onClick={() => applyPreset('')}
                      >
                        + {t('Default Shell Access')}
                      </button>
                    </>
                  )}
                </div>
              </div>
            </div>

            {/* Connection Test Bar */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 14px', background: 'var(--surface-2, var(--bg-subtle))', borderRadius: 8, border: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <Activity size={14} style={{ color: 'var(--accent)' }} />
                <span style={{ fontSize: 12, fontWeight: 600 }}>{t('Verify Topology Connectivity')}</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                {testResult && (
                  <Tag tone={testResult.success ? 'good' : 'bad'} mono>
                    {testResult.success ? t('ONLINE') : t('FAILED')}
                  </Tag>
                )}
                <button
                  type="button"
                  className="btn btn-sm btn-subtle"
                  onClick={testConfig}
                  disabled={testing}
                >
                  {testing ? <Spinner /> : <Activity size={12} />} {t('Test Now')}
                </button>
              </div>
            </div>

            {/* JIT Architecture Info Card */}
            <div style={{ padding: '10px 14px', background: 'var(--bg-subtle)', borderRadius: 8, border: '1px solid var(--border)', fontSize: 11 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                <Database size={14} style={{ color: '#2563eb' }} />
                <strong>{t('Temporary Credentials')}</strong>
              </div>
              <p className="muted small" style={{ margin: 0, lineHeight: 1.4 }}>
                {t('Credentials are created on demand and removed when their TTL expires. Failed grants roll back.')}
              </p>
            </div>
          </div>
        </div>
      </form>
    </Modal>
  )
}

function IssueLeaseModal({ projectId, envSlug, provider, onClose }: { projectId: string; envSlug: string; provider: DynamicProvider; onClose: () => void }) {
  const [ttl, setTTL] = useState(provider.default_ttl_seconds)
  const [busy, setBusy] = useState(false)

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    api
      .post<IssuedLease>(`/projects/${enc(projectId)}/environments/${enc(envSlug)}/dynamic/${enc(provider.id)}/lease`, {
        ttl_seconds: Number(ttl),
      })
      .then((res) => {
        invalidate('/projects')
        onClose()
        openDialog((c) => <LeaseSuccessModal lease={res} onClose={c} />)
      })
      .catch(toast.err)
      .finally(() => setBusy(false))
  }

  return (
    <Modal title={t('Issue Temporary Credentials — {0}', provider.name)} onClose={onClose}>
      <form onSubmit={submit}>
        <Field label={t('Lease Duration')}>
          <select value={ttl} onChange={(e) => setTTL(Number(e.target.value))}>
            <option value={900}>{t('15 minutes')}</option>
            <option value={1800}>{t('30 minutes')}</option>
            <option value={3600}>{t('1 hour')}</option>
            <option value={14400}>{t('4 hours')}</option>
            <option value={28800}>{t('8 hours')}</option>
            <option value={86400}>{t('24 hours')}</option>
          </select>
        </Field>
        <p className="muted small">
          {t('A unique temporary user will be provisioned on {0} and automatically revoked when expired.', provider.engine.toUpperCase())}
        </p>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
          <button type="button" className="btn btn-ghost" onClick={onClose}>{t('Cancel')}</button>
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? <Spinner /> : t('Generate Credentials')}
          </button>
        </div>
      </form>
    </Modal>
  )
}

function LeaseSuccessModal({ lease, onClose }: { lease: IssuedLease; onClose: () => void }) {
  const copyCred = (val: string, label: string) => {
    copy(val).then((ok) => {
      if (ok) toast.ok(t('{0} copied', label))
    })
  }

  return (
    <Modal title={t('Temporary Credentials Issued')} wide onClose={onClose}>
      <div className="alert alert-good" style={{ marginBottom: 16 }}>
        <strong>{t('Credentials active!')}</strong> {t('Expires at {0}', new Date(lease.expires_at).toLocaleString())}
      </div>

      <Field label={t('Temporary Username')}>
        <div style={{ display: 'flex', gap: 8 }}>
          <input readOnly className="mono" value={lease.username} style={{ flex: 1 }} />
          <button className="btn btn-sm btn-subtle" onClick={() => copyCred(lease.username, 'Username')}><Copy size={13} /></button>
        </div>
      </Field>

      <Field label={t('Temporary Password')}>
        <div style={{ display: 'flex', gap: 8 }}>
          <input readOnly className="mono" value={lease.password} style={{ flex: 1 }} />
          <button className="btn btn-sm btn-subtle" onClick={() => copyCred(lease.password, 'Password')}><Copy size={13} /></button>
        </div>
      </Field>

      {lease.connection_string && (
        <Field label={t('Direct Connection String')}>
          <div style={{ display: 'flex', gap: 8 }}>
            <input readOnly className="mono" value={lease.connection_string} style={{ flex: 1 }} />
            <button className="btn btn-sm btn-subtle" onClick={() => copyCred(lease.connection_string || '', 'Connection string')}><Copy size={13} /></button>
          </div>
        </Field>
      )}

      <Field label={t('Connect via Managed Tunnel (CLI)')} help={t('Opens a secure localhost proxy and revokes credentials on disconnect')}>
        <div style={{ display: 'flex', gap: 8 }}>
          <input readOnly className="mono" value={`ducksecrets connect --lease ${lease.lease_id}`} style={{ flex: 1 }} />
          <button className="btn btn-sm btn-subtle" onClick={() => copyCred(`ducksecrets connect --lease ${lease.lease_id}`, 'CLI Command')}><Copy size={13} /></button>
        </div>
      </Field>

      <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 16 }}>
        <button className="btn btn-primary" onClick={onClose}>{t('Done')}</button>
      </div>
    </Modal>
  )
}

// ---------------------------------------------------------
// AUTOMATED SECRET ROTATION
// ---------------------------------------------------------

function RotationView({ projectId, envSlug }: { projectId: string; envSlug: string }) {
  const { data: policies, loading, error } = useResource<RotationPolicy[]>(
    `/projects/${enc(projectId)}/environments/${enc(envSlug)}/rotation`
  )
  const menu = useMenu()

  const runRotation = (secretId: string, secretKey: string) => {
    toast.ok(t('Executing rotation and health verification probe…'))
    api
      .post<RotationRunResponse>(`/projects/${enc(projectId)}/environments/${enc(envSlug)}/secrets/${enc(secretId)}/rotation/run`, {})
      .then((res) => {
        invalidate('/projects')
        if (res.success) {
          toast.ok(t('{0}: {1}', secretKey, res.message))
        } else {
          toast.err(t('{0}: {1}', secretKey, res.message || t('Rotation failed')))
        }
      })
      .catch(toast.err)
  }

  const deletePolicy = async (secretId: string, secretKey: string) => {
    if (
      !(await confirm({
        title: t('Remove rotation policy for {0}?', secretKey),
        body: t('Automated rotation will stop for this secret.'),
        danger: true,
        confirm: t('Remove Policy'),
      }))
    ) {
      return
    }
    api.del(`/projects/${enc(projectId)}/environments/${enc(envSlug)}/secrets/${enc(secretId)}/rotation`).then(() => {
      invalidate('/projects')
      toast.ok(t('Rotation policy removed'))
    }, toast.err)
  }

  const policyActions = (pol: RotationPolicy): MenuEntry[] => [
    { header: pol.secret_key || t('Rotation Policy') },
    {
      label: t('Edit Policy'),
      icon: <Pencil size={14} />,
      onClick: () =>
        openDialog((c) => (
          <RotationPolicyModal
            projectId={projectId}
            envSlug={envSlug}
            secret={{ id: pol.secret_id, key: pol.secret_key || pol.secret_id, path: pol.secret_path || '/' } as any}
            existingPolicy={pol}
            onClose={c}
          />
        )),
    },
    { label: t('Run Rotation Now'), icon: <Play size={14} />, onClick: () => runRotation(pol.secret_id, pol.secret_key || '') },
    'sep',
    { label: t('Remove Policy'), icon: <Trash2 size={14} />, danger: true, onClick: () => deletePolicy(pol.secret_id, pol.secret_key || '') },
  ]

  const [q, setQ] = useState('')
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'error'>('all')

  const filteredPolicies = useMemo(() => {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean)
    return (policies || []).filter((pol) => {
      if (statusFilter === 'active' && pol.status === 'error') return false
      if (statusFilter === 'error' && pol.status !== 'error') return false
      return words.every((w) => `${pol.secret_key || ''} ${pol.secret_path || ''} ${pol.generator_type || ''} ${pol.status || ''}`.toLowerCase().includes(w))
    })
  }, [policies, q, statusFilter])

  if (loading) return <div className="center" style={{ padding: 24 }}><Spinner /></div>
  if (error) return <div className="alert alert-bad">{error.message}</div>

  return (
    <div>
      <div className="vault-toolbar">
        <div className="vault-toolbar-left">
          <div className="search">
            <Search size={14} />
            <input placeholder={t('Filter rotation policies…')} value={q} onChange={(e) => setQ(e.currentTarget.value)} />
            {q && <button className="icon-btn" onClick={() => setQ('')}><X size={13} /></button>}
          </div>

          <select
            className="vault-select"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as any)}
            title={t('Filter by health status')}
          >
            <option value="all">{t('All Statuses')}</option>
            <option value="active">{t('Healthy / Active')}</option>
            <option value="error">{t('Error / Attention')}</option>
          </select>
        </div>

        <div className="vault-toolbar-right">
          <Tag tone="accent">
            <RefreshCw size={12} style={{ marginRight: 4 }} />
            {policies?.length || 0} {t('Active Policies')}
          </Tag>
        </div>
      </div>

      {!policies || policies.length === 0 ? (
        <Empty
          icon={<RefreshCw size={32} />}
          title={t('No rotation policies active')}
        >
          <p>{t('Configure auto-rotation directly from any secret in the Secrets tab by clicking Auto-Rotation…')}</p>
        </Empty>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: 16 }}>
          {filteredPolicies.map((pol) => (
            <div key={pol.id} className="card" onContextMenu={menu(() => policyActions(pol))} style={{ padding: 16, borderRadius: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                <div>
                  <strong style={{ fontSize: 15 }}>{pol.secret_key || t('Secret')}</strong>
                  {pol.secret_path && <span className="muted small" style={{ marginLeft: 6 }}>{pol.secret_path}</span>}
                </div>
                <Tag tone={pol.status === 'error' ? 'bad' : 'good'}>
                  {pol.status.toUpperCase()}
                </Tag>
              </div>

              <div style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 12 }}>
                <div>{t('Interval: every {0} days', Math.round(pol.interval_seconds / 86400))}</div>
                <div>{t('Generator: {0}', pol.generator_type)}</div>
                <div>{t('Health Probe: {0}', pol.verifier_type)}</div>
                <div style={{ marginTop: 4 }}>
                  <Clock size={12} style={{ display: 'inline', marginRight: 4, verticalAlign: 'text-bottom' }} />
                  {t('Next rotation: {0}', new Date(pol.next_rotation_at).toLocaleDateString())}
                </div>
              </div>

              {pol.last_error && (
                <div className="alert alert-bad" style={{ fontSize: 12, padding: 8, marginBottom: 12 }}>
                  <AlertCircle size={13} style={{ display: 'inline', marginRight: 4, verticalAlign: 'text-bottom' }} />
                  {pol.last_error}
                </div>
              )}

              <div style={{ display: 'flex', gap: 8, borderTop: '1px solid var(--border)', paddingTop: 10 }}>
                <button
                  className="btn btn-sm btn-primary"
                  onClick={() => runRotation(pol.secret_id, pol.secret_key || pol.secret_id)}
                >
                  <Play size={13} /> {t('Rotate Now')}
                </button>
                <button
                  className="btn btn-sm btn-ghost"
                  onClick={() =>
                    openDialog((c) => (
                      <RotationPolicyModal
                        projectId={projectId}
                        envSlug={envSlug}
                        secret={{ id: pol.secret_id, key: pol.secret_key || pol.secret_id, path: pol.secret_path || '/' } as any}
                        existingPolicy={pol}
                        onClose={c}
                      />
                    ))
                  }
                >
                  <Pencil size={13} /> {t('Edit')}
                </button>
                <button
                  className="icon-btn"
                  style={{ marginLeft: 'auto', color: '#ef4444' }}
                  onClick={() => deletePolicy(pol.secret_id, pol.secret_key || pol.secret_id)}
                  title={t('Remove Policy')}
                >
                  <Trash2 size={14} />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function RotationPolicyModal({
  projectId,
  envSlug,
  secret,
  existingPolicy,
  onClose,
}: {
  projectId: string
  envSlug: string
  secret: Secret
  existingPolicy?: RotationPolicy
  onClose: () => void
}) {
  const [intervalDays, setIntervalDays] = useState(
    existingPolicy ? Math.max(1, Math.round(existingPolicy.interval_seconds / 86400)) : 30
  )
  const [generatorType, setGeneratorType] = useState(existingPolicy?.generator_type || 'password')
  const [passwordLength, setPasswordLength] = useState(() => {
    if (existingPolicy?.generator_config) {
      try {
        const c = JSON.parse(existingPolicy.generator_config)
        if (c.length) return Number(c.length)
      } catch {}
    }
    return 32
  })
  const [valueTemplate, setValueTemplate] = useState(() => {
    if (existingPolicy?.generator_config) {
      try {
        const c = JSON.parse(existingPolicy.generator_config)
        if (c.template) return String(c.template)
      } catch {}
    }
    return ''
  })
  const [verifierType, setVerifierType] = useState(existingPolicy?.verifier_type || 'none')
  const [verifierConfig, setVerifierConfig] = useState(existingPolicy?.verifier_config || '')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (existingPolicy) return
    api
      .get<RotationPolicy>(`/projects/${enc(projectId)}/environments/${enc(envSlug)}/secrets/${enc(secret.id)}/rotation`)
      .then((pol) => {
        if (!pol) return
        setIntervalDays(Math.max(1, Math.round(pol.interval_seconds / 86400)))
        setGeneratorType(pol.generator_type)
        setVerifierType(pol.verifier_type)
        setVerifierConfig(pol.verifier_config || '')
        if (pol.generator_config) {
          try {
            const c = JSON.parse(pol.generator_config)
            if (c.length) setPasswordLength(Number(c.length))
            if (c.template) setValueTemplate(String(c.template))
          } catch {}
        }
      })
      .catch(() => {})
  }, [projectId, envSlug, secret.id, existingPolicy])

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    const genConfigObj: any = {}
    if (generatorType === 'password') {
      genConfigObj.length = Number(passwordLength) || 32
    }
    if (valueTemplate.trim()) {
      genConfigObj.template = valueTemplate.trim()
    }
    const genConfig = JSON.stringify(genConfigObj)
    api
      .post(`/projects/${enc(projectId)}/environments/${enc(envSlug)}/secrets/${enc(secret.id)}/rotation`, {
        interval_seconds: intervalDays * 86400,
        generator_type: generatorType,
        generator_config: genConfig,
        verifier_type: verifierType,
        verifier_config: verifierConfig || '{}',
      })
      .then(() => {
        invalidate('/projects')
        toast.ok(t('Rotation policy saved for {0}', secret.key))
        onClose()
      })
      .catch(toast.err)
      .finally(() => setBusy(false))
  }

  return (
    <Modal
      title={t('Configure Auto-Rotation — {0}', secret.key)}
      wide="xl"
      allowFullscreen
      onClose={onClose}
      footer={
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, width: '100%' }}>
          <button type="button" className="btn btn-ghost" onClick={onClose}>{t('Cancel')}</button>
          <button type="submit" form="rotation-form" className="btn btn-primary" disabled={busy}>
            {busy ? <Spinner /> : t('Save Policy')}
          </button>
        </div>
      }
    >
      <form id="rotation-form" onSubmit={submit}>
        <div className="modal-two-col">
          {/* Left Column: Generation Strategy & Scheduling */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <Field label={t('Rotation Frequency')} help={t('How often DuckSecrets generates a new credential')}>
              <select value={intervalDays} onChange={(e) => setIntervalDays(Number(e.target.value))}>
                <option value={1}>{t('Every 24 hours (1 day)')}</option>
                <option value={7}>{t('Every 7 days (Weekly)')}</option>
                <option value={30}>{t('Every 30 days (Monthly)')}</option>
                <option value={90}>{t('Every 90 days (Quarterly)')}</option>
                <option value={365}>{t('Every 365 days (Yearly)')}</option>
              </select>
            </Field>

            <Field label={t('Secret Generator Type')}>
              <select value={generatorType} onChange={(e) => setGeneratorType(e.target.value)}>
                <option value="password">{t('Random Strong Password (alphanumeric + symbols)')}</option>
                <option value="hex">{t('Hex Token (256-bit / 64 chars)')}</option>
                <option value="base64">{t('Base64 Token (256-bit)')}</option>
                <option value="jwt_secret">{t('JWT Signing Key (512-bit HMAC secret)')}</option>
                <option value="uuid">{t('UUIDv4')}</option>
                <option value="rsa">{t('RSA 2048-bit Private Key (PEM)')}</option>
              </select>
            </Field>

            {generatorType === 'password' && (
              <Field label={t('Password Length ({0} characters)', passwordLength)}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <input
                    type="range"
                    min={8}
                    max={128}
                    value={passwordLength}
                    onChange={(e) => setPasswordLength(Number(e.target.value))}
                    style={{ flex: 1 }}
                  />
                  <span className="mono" style={{ width: 40, textAlign: 'right', fontWeight: 600 }}>
                    {passwordLength}
                  </span>
                </div>
              </Field>
            )}

            <Field
              label={t('Value Template / Connection String (Optional)')}
              help={t('Use {{secret}} as placeholder for the generated password. Ideal for compound secrets like DATABASE_URL.')}
            >
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <input
                  className="mono"
                  placeholder="postgres://user:{{secret}}@host:port/dbname"
                  value={valueTemplate}
                  onChange={(e) => setValueTemplate(e.target.value)}
                />
                {secret.value && secret.value !== '••••••••' && (
                  <div style={{ display: 'flex', gap: 6 }}>
                    <button
                      type="button"
                      className="btn btn-xs btn-ghost"
                      onClick={() => {
                        const val = secret.raw_value || secret.value
                        try {
                          const u = new URL(val)
                          if (u.password) {
                            const templated = val.replace(`:${u.password}@`, ':{{secret}}@')
                            setValueTemplate(templated)
                            return
                          }
                        } catch {}
                        setValueTemplate(val.replace(/:[^:@]+@/, ':{{secret}}@'))
                      }}
                    >
                      <Sparkles size={12} style={{ marginRight: 4 }} />
                      {t('Convert current secret value to template')}
                    </button>
                  </div>
                )}
              </div>
            </Field>
          </div>

          {/* Right Column: Health Probe & Zero-Downtime Rollback Guard */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ padding: '12px 14px', background: 'var(--surface-2, var(--bg-subtle))', borderRadius: 8, border: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{ fontSize: 12, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Activity size={14} style={{ color: 'var(--accent)' }} />
                  {t('Health Verification Probe')}
                </span>
                <Tag tone={verifierType !== 'none' ? 'good' : 'accent'} mono style={{ fontSize: 10 }}>
                  {verifierType.toUpperCase()}
                </Tag>
              </div>
              <p className="muted small" style={{ margin: '0 0 8px 0', fontSize: 11, lineHeight: 1.4 }}>
                {t('A probe connects to the service immediately after rotation. If it fails, DuckSecrets auto-rollbacks to the previous version.')}
              </p>

              <Field label={t('Probe Type')}>
                <select value={verifierType} onChange={(e) => setVerifierType(e.target.value)}>
                  <option value="none">{t('None (Commit rotation immediately)')}</option>
                  <option value="http_probe">{t('HTTP Endpoint Probe (GET/POST test)')}</option>
                  <option value="tcp_probe">{t('TCP Port Probe')}</option>
                  <option value="script">{t('Custom Verification Command')}</option>
                </select>
              </Field>

              {verifierType === 'http_probe' && (
                <div style={{ marginTop: 8 }}>
                  <HttpProbeConfigForm value={verifierConfig} onChange={setVerifierConfig} />
                </div>
              )}

              {verifierType === 'tcp_probe' && (
                <div style={{ marginTop: 8 }}>
                  <TcpProbeConfigForm value={verifierConfig} onChange={setVerifierConfig} />
                </div>
              )}

              {verifierType === 'script' && (
                <div style={{ marginTop: 8 }}>
                  <ScriptProbeConfigForm value={verifierConfig} onChange={setVerifierConfig} />
                </div>
              )}
            </div>

            {/* Zero-Downtime Rollback Guarantee Card */}
            <div style={{ padding: '10px 14px', background: 'var(--bg-subtle)', borderRadius: 8, border: '1px solid var(--border)', fontSize: 11 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                <ShieldCheck size={14} style={{ color: '#10b981' }} />
                <strong>{t('Automatic Rollback')}</strong>
              </div>
              <p className="muted small" style={{ margin: 0, lineHeight: 1.4 }}>
                {t('If the health check fails, DuckSecrets restores the previous secret and logs the failure.')}
              </p>
            </div>
          </div>
        </div>
      </form>
    </Modal>
  )
}

function SitesView({ projectId }: { projectId: string }) {
  const { data: sites, error, loading } = useResource<Site[]>(`/projects/${enc(projectId)}/sites`)

  const removeSite = async (site: Site) => {
    if (
      !(await confirm({
        title: t('Delete site connector "{0}"?', site.name),
        body: t('This will disconnect any active reverse tunnels and remove the site registration.'),
        danger: true,
        confirm: t('Delete Site'),
      }))
    ) {
      return
    }
    api.del(`/projects/${enc(projectId)}/sites/${enc(site.id)}`).then(() => {
      invalidate('/projects')
      toast.ok(t('Site deleted'))
    }, toast.err)
  }

  const siteActions = (site: Site): MenuEntry[] => [
    { header: site.name },
    { label: t('Delete Site'), icon: <Trash2 size={14} />, danger: true, onClick: () => removeSite(site) },
  ]

  const [q, setQ] = useState('')
  const [statusFilter, setStatusFilter] = useState<'all' | 'online' | 'offline'>('all')

  const rows = useMemo(() => {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean)
    return (sites || []).filter((s) => {
      if (statusFilter === 'online' && !s.online) return false
      if (statusFilter === 'offline' && s.online) return false
      return words.every((w) => `${s.name} ${s.description || ''} ${s.token_prefix || ''}`.toLowerCase().includes(w))
    })
  }, [sites, q, statusFilter])

  return (
    <div>
      <div className="vault-toolbar">
        <div className="vault-toolbar-left">
          <div className="search">
            <Search size={14} />
            <input placeholder={t('Filter sites…')} value={q} onChange={(e) => setQ(e.currentTarget.value)} />
            {q && <button className="icon-btn" onClick={() => setQ('')}><X size={13} /></button>}
          </div>

          <select
            className="vault-select"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as any)}
            title={t('Filter by connection status')}
          >
            <option value="all">{t('All Sites')}</option>
            <option value="online">{t('Online')}</option>
            <option value="offline">{t('Offline')}</option>
          </select>
        </div>

        <div className="vault-toolbar-right">
          <button
            className="btn btn-primary btn-sm"
            onClick={() => openDialog((c) => <SiteModal projectId={projectId} onClose={c} />)}
          >
            <Plus size={14} /> {t('New Site Connector')}
          </button>
        </div>
      </div>

      {error && <div className="alert alert-bad">{error.message}</div>}
      {loading && <Spinner />}

      {sites && sites.length === 0 ? (
        <Empty
          icon={<Network size={32} />}
          title={t('No network sites registered')}
          action={
            <button
              className="btn btn-primary"
              onClick={() => openDialog((c) => <SiteModal projectId={projectId} onClose={c} />)}
            >
              <Plus size={14} /> {t('New Site Connector')}
            </button>
          }
        >
          {t('Deploy an agent (ducksecrets site run) inside private networks. It opens an outbound tunnel to ducksecretsd with no inbound ports required.')}
        </Empty>
      ) : (
        <DataTable
          rows={rows}
          rowKey={(s) => s.id}
          rowMenu={siteActions}
          defaultSort={{ key: 'created', dir: -1 }}
          columns={[
            {
              key: 'name',
              label: t('Site Name'),
              render: (s) => (
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <strong>{s.name}</strong>
                    {s.online ? (
                      <Tag tone="good">{t('ONLINE')}</Tag>
                    ) : (
                      <Tag>{t('OFFLINE')}</Tag>
                    )}
                  </div>
                  {s.description && <div className="muted small">{s.description}</div>}
                  <div className="muted small mono">{s.token_prefix}</div>
                </div>
              ),
            },
            {
              key: 'last_seen',
              label: t('Last Seen'),
              render: (s) => (
                <span className="muted small">
                  {s.last_seen_at ? ago(s.last_seen_at) : t('Never connected')}
                </span>
              ),
            },
            {
              key: 'created',
              label: t('Created'),
              sort: (s) => s.created_at,
              render: (s) => (
                <span className="muted small" title={dateTime(s.created_at)}>
                  {ago(s.created_at)}
                </span>
              ),
            },
          ]}
        />
      )}
    </div>
  )
}

function SiteModal({ projectId, onClose }: { projectId: string; onClose: () => void }) {
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    try {
      const res = await api.post<CreatedSite>(`/projects/${enc(projectId)}/sites`, {
        name,
        description: description || undefined,
      })
      invalidate('/projects')
      onClose()
      openDialog((c) => <SiteSuccessModal site={res} onClose={c} />)
    } catch (err: any) {
      toast.err(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal title={t('Register Network Site Connector')} onClose={onClose}>
      <form onSubmit={submit}>
        <Field label={t('Site Name')} help={t('e.g. aws-us-east-1-vpc, onprem-datacenter, customer-dc')}>
          <input required autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. prod-vpc-private" />
        </Field>
        <Field label={t('Description (Optional)')}>
          <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="e.g. AWS VPC US-East Private Subnet" />
        </Field>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
          <button type="button" className="btn btn-ghost" onClick={onClose}>{t('Cancel')}</button>
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? <Spinner /> : t('Create Site')}
          </button>
        </div>
      </form>
    </Modal>
  )
}

function SiteSuccessModal({ site, onClose }: { site: CreatedSite; onClose: () => void }) {
  const [copiedToken, setCopiedToken] = useState(false)
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null)
  const [mode, setMode] = useState<'oneliner' | 'download' | 'cli'>('oneliner')

  const serverUrl = window.location.origin
  const onelinerCmd = `curl -fsSL ${serverUrl}/install.sh | DUCKSECRETS_SITE_ID=${site.id} DUCKSECRETS_SITE_TOKEN=${site.token} sh`
  const downloadCmd = `curl -fsSL ${serverUrl}/download/ducksecrets -o ducksecrets && chmod +x ducksecrets && ./ducksecrets site run --server ${serverUrl} --site-id ${site.id} --token ${site.token}`
  const cliCmd = `ducksecrets site run --server ${serverUrl} --site-id ${site.id} --token ${site.token}`

  const copyToken = () => {
    copy(site.token).then((ok) => {
      if (ok) {
        setCopiedToken(true)
        setTimeout(() => setCopiedToken(false), 2000)
        toast.ok(t('Token copied to clipboard'))
      }
    })
  }

  const handleCopyCmd = (cmd: string, key: string) => {
    copy(cmd).then((ok) => {
      if (ok) {
        setCopiedCmd(key)
        setTimeout(() => setCopiedCmd(null), 2000)
        toast.ok(t('Command copied to clipboard'))
      }
    })
  }

  return (
    <Modal title={t('Site Connector Created — {0}', site.name)} wide onClose={onClose}>
      <div className="alert alert-bad" style={{ marginBottom: 16 }}>
        <strong>{t('Copy your site token now.')}</strong> {t('This is the only time it will ever be shown!')}
      </div>

      <Field label={t('Site Connector Token')}>
        <div style={{ display: 'flex', gap: 8 }}>
          <input readOnly className="mono" value={site.token} style={{ flex: 1, fontSize: 13 }} />
          <button className="btn btn-sm btn-primary" onClick={copyToken}>
            {copiedToken ? <Check size={14} /> : <Copy size={14} />} {copiedToken ? t('Copied') : t('Copy')}
          </button>
        </div>
      </Field>

      <div style={{ marginTop: 16 }}>
        <Tabs
          tabs={[
            { id: 'oneliner', label: t('1-Line Install & Run (curl)') },
            { id: 'download', label: t('Download Binary & Run') },
            { id: 'cli', label: t('Existing CLI') },
          ]}
          active={mode}
          onChange={(m) => setMode(m as any)}
        />
      </div>

      <div style={{ marginTop: 12, padding: 12, background: 'var(--bg-subtle)', borderRadius: 6 }}>
        {mode === 'oneliner' && (
          <>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
              <strong className="small">{t('Automated install & connect via curl (Recommended):')}</strong>
              <button className="btn btn-sm" onClick={() => handleCopyCmd(onelinerCmd, 'oneliner')}>
                {copiedCmd === 'oneliner' ? <Check size={13} /> : <Copy size={13} />} {copiedCmd === 'oneliner' ? t('Copied') : t('Copy Command')}
              </button>
            </div>
            <pre className="mono small" style={{ margin: 0, padding: 8, background: 'var(--bg)', borderRadius: 4, overflowX: 'auto', whiteSpace: 'pre-wrap' }}>
{onelinerCmd}
            </pre>
            <p className="muted small" style={{ margin: '8px 0 0' }}>
              {t('Downloads ducksecrets CLI from this server to /usr/local/bin (or ~/.local/bin), sets permissions, and immediately connects.')}
            </p>
          </>
        )}

        {mode === 'download' && (
          <>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
              <strong className="small">{t('Download standalone binary and run locally:')}</strong>
              <button className="btn btn-sm" onClick={() => handleCopyCmd(downloadCmd, 'download')}>
                {copiedCmd === 'download' ? <Check size={13} /> : <Copy size={13} />} {copiedCmd === 'download' ? t('Copied') : t('Copy Command')}
              </button>
            </div>
            <pre className="mono small" style={{ margin: 0, padding: 8, background: 'var(--bg)', borderRadius: 4, overflowX: 'auto', whiteSpace: 'pre-wrap' }}>
{downloadCmd}
            </pre>
            <p className="muted small" style={{ margin: '8px 0 0' }}>
              {t('Downloads the ducksecrets executable from this server into the current directory and starts the tunnel to {0}.', serverUrl)}
            </p>
          </>
        )}

        {mode === 'cli' && (
          <>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
              <strong className="small">{t('If ducksecrets CLI is already installed on the host:')}</strong>
              <button className="btn btn-sm" onClick={() => handleCopyCmd(cliCmd, 'cli')}>
                {copiedCmd === 'cli' ? <Check size={13} /> : <Copy size={13} />} {copiedCmd === 'cli' ? t('Copied') : t('Copy Command')}
              </button>
            </div>
            <pre className="mono small" style={{ margin: 0, padding: 8, background: 'var(--bg)', borderRadius: 4, overflowX: 'auto', whiteSpace: 'pre-wrap' }}>
{cliCmd}
            </pre>
          </>
        )}
      </div>

      <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 16 }}>
        <button className="btn btn-primary" onClick={onClose}>{t('Done')}</button>
      </div>
    </Modal>
  )
}

const TTLS = [
  { label: t('Permanent'), s: 0 },
  { label: t('1 hour'), s: 3600 },
  { label: t('8 hours'), s: 8 * 3600 },
  { label: t('1 day'), s: 86400 },
  { label: t('7 days'), s: 7 * 86400 },
  { label: t('30 days'), s: 30 * 86400 },
]

function policyExpiryState(p: ProjectPolicy) {
  if (!p.expires_at) return 'permanent'
  const left = Date.parse(p.expires_at) - Date.now()
  return left <= 0 ? 'expired' : left < 86400e3 ? 'expiring' : 'active'
}

function PolicyExpiry({ p }: { p: ProjectPolicy }) {
  const st = policyExpiryState(p)
  if (st === 'permanent') return <span className="muted">{t('Permanent')}</span>
  return (
    <span
      className={`row gap small ${st === 'expired' ? 'tone-bad' : st === 'expiring' ? 'tone-warn' : ''}`}
      style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}
      title={p.expires_at ? dateTime(p.expires_at) : undefined}
    >
      <Clock size={12} /> {st === 'expired' ? t('expired {0}', ago(p.expires_at!)) : t('expires {0}', ago(p.expires_at!))}
    </span>
  )
}

function PolicyPerms({ p }: { p: ProjectPolicy }) {
  return (
    <span style={{ display: 'inline-flex', gap: 4 }}>
      {p.can_read && <Tag tone="ok">{t('Read')}</Tag>}
      {p.can_write && <Tag tone="accent">{t('Write')}</Tag>}
      {p.can_admin && <Tag tone="bad">{t('Admin')}</Tag>}
    </span>
  )
}

async function removePolicy(projectId: string, p: ProjectPolicy) {
  if (
    !(await confirm({
      title: t('Revoke this access policy?'),
      body: t('The subject will immediately lose granted permissions on this project and environment.'),
      danger: true,
      confirm: t('Revoke Policy'),
    }))
  ) {
    return
  }
  api
    .del(`/projects/${enc(projectId)}/policies/${enc(p.id)}`)
    .then(() => {
      invalidate(`/projects/${enc(projectId)}/policies`)
      toast.ok(t('Policy revoked'))
    }, toast.err)
}

function PoliciesView({ projectId, envs }: { projectId: string; envs: Environment[] }) {
  const canListUsers = allowed('users.manage')
  const { data: policies, error, loading } = useResource<ProjectPolicy[]>(`/projects/${enc(projectId)}/policies`)
  const { data: usersData } = useResource<Page<User>>(canListUsers ? '/users?per_page=100' : null)
  const { data: roles } = useResource<Role[]>('/roles')
  const [q, setQ] = useState('')

  const userMap = useMemo(() => {
    const map = new Map<string, User>()
    for (const u of usersData?.items || []) {
      map.set(u.id, u)
    }
    return map
  }, [usersData])

  const roleMap = useMemo(() => {
    const map = new Map<string, Role>()
    for (const r of roles || []) {
      map.set(r.name, r)
    }
    return map
  }, [roles])

  const subjectLabel = (p: ProjectPolicy) => {
    if (p.subject_type === 'user') {
      const u = userMap.get(p.subject_id)
      return {
        icon: <UserIcon size={14} />,
        name: u ? (u.display_name ? `${u.display_name} (${u.username})` : u.username) : p.subject_id,
        sub: p.subject_type,
      }
    }
    const r = roleMap.get(p.subject_id)
    return {
      icon: <UsersRound size={14} />,
      name: r ? r.name : p.subject_id,
      sub: p.subject_type,
    }
  }

  const [subjectFilter, setSubjectFilter] = useState<'all' | 'user' | 'role'>('all')
  const [envFilter, setEnvFilter] = useState('')

  const rows = useMemo(() => {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean)
    return (policies || []).filter((p) => {
      if (subjectFilter !== 'all' && p.subject_type !== subjectFilter) return false
      if (envFilter && p.environment_slug !== '*' && p.environment_slug !== envFilter) return false
      const s = subjectLabel(p)
      return words.every((w) => `${s.name} ${p.environment_slug} ${p.description || ''}`.toLowerCase().includes(w))
    })
  }, [policies, q, userMap, roleMap, subjectFilter, envFilter])

  const policyActions = (p: ProjectPolicy): MenuEntry[] => [
    { header: `${p.subject_type}:${p.subject_id} (${p.environment_slug})` },
    {
      label: t('Edit…'),
      icon: <Pencil size={14} />,
      onClick: () => openDialog((c) => <PolicyModal projectId={projectId} envs={envs} initial={p} onClose={c} />),
    },
    'sep',
    {
      label: t('Revoke Policy'),
      icon: <Trash2 size={14} />,
      danger: true,
      onClick: () => removePolicy(projectId, p),
    },
  ]

  return (
    <div>
      <div className="vault-toolbar">
        <div className="vault-toolbar-left">
          <div className="search">
            <Search size={14} />
            <input placeholder={t('Filter policies…')} value={q} onChange={(e) => setQ(e.currentTarget.value)} />
            {q && (
              <button className="icon-btn" onClick={() => setQ('')}>
                <X size={13} />
              </button>
            )}
          </div>

          <select
            className="vault-select"
            value={subjectFilter}
            onChange={(e) => setSubjectFilter(e.target.value as any)}
            title={t('Filter by subject type')}
          >
            <option value="all">{t('All Subjects')}</option>
            <option value="user">{t('Users')}</option>
            <option value="role">{t('Roles')}</option>
          </select>

          <select
            className="vault-select"
            value={envFilter}
            onChange={(e) => setEnvFilter(e.target.value)}
            title={t('Filter by environment scope')}
          >
            <option value="">{t('All Scopes')}</option>
            <option value="*">{t('All Environments (*)')}</option>
            {envs.map((e) => (
              <option key={e.slug} value={e.slug}>{e.name} ({e.slug})</option>
            ))}
          </select>
        </div>

        <div className="vault-toolbar-right">
          <button
            className="btn btn-primary btn-sm"
            onClick={() => openDialog((c) => <PolicyModal projectId={projectId} envs={envs} onClose={c} />)}
          >
            <Plus size={14} /> {t('Grant Access')}
          </button>
        </div>
      </div>

      {error && <div className="alert alert-bad">{error.message}</div>}
      {loading && <Spinner />}

      {policies && policies.length === 0 ? (
        <Empty
          icon={<ShieldCheck size={32} />}
          title={t('No project policies configured')}
          action={
            <button
              className="btn btn-primary"
              onClick={() => openDialog((c) => <PolicyModal projectId={projectId} envs={envs} onClose={c} />)}
            >
              <Plus size={14} /> {t('Grant Access')}
            </button>
          }
        >
          {t('By default with 0 policies, users with global permissions can view this project. Once you grant specific access, access is strictly governed by project policies.')}
        </Empty>
      ) : (
        <DataTable
          rows={rows}
          rowKey={(p) => p.id}
          rowMenu={policyActions}
          defaultSort={{ key: 'created', dir: -1 }}
          columns={[
            {
              key: 'subject',
              label: t('Subject'),
              render: (p) => {
                const s = subjectLabel(p)
                return (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    {s.icon}
                    <div>
                      <strong>{s.name}</strong>
                      <div className="muted small mono">{s.sub}</div>
                    </div>
                  </div>
                )
              },
            },
            {
              key: 'env',
              label: t('Environment'),
              render: (p) => (
                <Tag tone={p.environment_slug === '*' ? 'accent' : 'ok'} mono>
                  {p.environment_slug === '*' ? t('All Environments (*)') : p.environment_slug}
                </Tag>
              ),
            },
            {
              key: 'perms',
              label: t('Permissions'),
              render: (p) => <PolicyPerms p={p} />,
            },
            {
              key: 'expiry',
              label: t('Duration / Expiry'),
              render: (p) => <PolicyExpiry p={p} />,
            },
            {
              key: 'description',
              label: t('Reason / Notes'),
              render: (p) => <span className="muted small">{p.description || '—'}</span>,
            },
            {
              key: 'created',
              label: t('Created'),
              render: (p) => (
                <span className="muted small" title={dateTime(p.created_at)}>
                  {ago(p.created_at)}
                </span>
              ),
            },
          ]}
        />
      )}
    </div>
  )
}

function PolicyModal({
  projectId,
  envs,
  initial,
  onClose,
}: {
  projectId: string
  envs: Environment[]
  initial?: ProjectPolicy
  onClose: () => void
}) {
  const canListUsers = allowed('users.manage')
  const { data: usersData } = useResource<Page<User>>(canListUsers ? '/users?per_page=100' : null)
  const { data: roles } = useResource<Role[]>('/roles')

  const [subjectType, setSubjectType] = useState<'user' | 'role'>(initial ? initial.subject_type : 'user')
  const [subjectId, setSubjectId] = useState<string>(initial ? initial.subject_id : '')
  const [envSlug, setEnvSlug] = useState<string>(initial ? initial.environment_slug : '*')
  const [canRead, setCanRead] = useState<boolean>(initial ? initial.can_read : true)
  const [canWrite, setCanWrite] = useState<boolean>(initial ? initial.can_write : false)
  const [canAdmin, setCanAdmin] = useState<boolean>(initial ? initial.can_admin : false)
  const [ttl, setTTL] = useState<number>(0)
  const [description, setDescription] = useState<string>(initial ? initial.description : '')
  const [busy, setBusy] = useState(false)

  const selectedUserName = usersData?.items?.find((u) => u.id === subjectId)?.display_name || usersData?.items?.find((u) => u.id === subjectId)?.username
  const selectedRoleName = roles?.find((r) => r.name === subjectId)?.name

  const save = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!subjectId) {
      toast.err(t('Please select a subject'))
      return
    }
    setBusy(true)
    try {
      if (initial) {
        await api.put(`/projects/${enc(projectId)}/policies/${enc(initial.id)}`, {
          environment_slug: envSlug,
          can_read: canRead,
          can_write: canWrite,
          can_admin: canAdmin,
          description: description.trim(),
        })
        toast.ok(t('Policy updated'))
      } else {
        await api.post(`/projects/${enc(projectId)}/policies`, {
          subject_type: subjectType,
          subject_id: subjectId,
          environment_slug: envSlug,
          can_read: canRead,
          can_write: canWrite,
          can_admin: canAdmin,
          ttl_seconds: ttl > 0 ? ttl : undefined,
          description: description.trim(),
        })
        toast.ok(t('Access granted'))
      }
      invalidate(`/projects/${enc(projectId)}/policies`)
      onClose()
    } catch (err) {
      toast.err(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      title={initial ? t('Edit Access Policy') : t('Grant Project Access')}
      icon={<ShieldCheck size={18} style={{ color: 'var(--accent)' }} />}
      wide="xl"
      allowFullscreen
      onClose={onClose}
      footer={
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, width: '100%' }}>
          <button type="button" className="btn btn-ghost" onClick={onClose}>
            {t('Cancel')}
          </button>
          <button
            type="submit"
            form="policy-form"
            className="btn btn-primary"
            disabled={busy || !subjectId || (!canRead && !canWrite && !canAdmin)}
          >
            {busy ? <Spinner /> : initial ? t('Update Policy') : t('Grant Access')}
          </button>
        </div>
      }
    >
      <form id="policy-form" onSubmit={save}>
        <div className="modal-two-col">
          {/* Left Column: Subject, Scope & Privileges */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {!initial ? (
              <Field label={t('Subject Type')} help={t('Assign access to an individual user or a group role')}>
                <div style={{ display: 'flex', gap: 6 }}>
                  <button
                    type="button"
                    className={subjectType === 'user' ? 'btn btn-sm btn-primary' : 'btn btn-sm btn-ghost'}
                    style={{ flex: 1, justifyContent: 'center' }}
                    onClick={() => {
                      setSubjectType('user')
                      setSubjectId('')
                    }}
                  >
                    <UserIcon size={14} style={{ marginRight: 6 }} /> {t('User')}
                  </button>
                  <button
                    type="button"
                    className={subjectType === 'role' ? 'btn btn-sm btn-primary' : 'btn btn-sm btn-ghost'}
                    style={{ flex: 1, justifyContent: 'center' }}
                    onClick={() => {
                      setSubjectType('role')
                      setSubjectId('')
                    }}
                  >
                    <UsersRound size={14} style={{ marginRight: 6 }} /> {t('Role Group')}
                  </button>
                </div>
              </Field>
            ) : null}

            <Field label={subjectType === 'user' ? (canListUsers ? t('Select User') : t('User ID')) : t('Select Role')}>
              {initial ? (
                <input readOnly value={`${initial.subject_type}: ${initial.subject_id}`} className="mono" />
              ) : subjectType === 'user' ? (
                canListUsers ? (
                  <select value={subjectId} onChange={(e) => setSubjectId(e.currentTarget.value)} required>
                    <option value="">{t('Choose a user…')}</option>
                    {(usersData?.items || []).map((u) => (
                      <option key={u.id} value={u.id}>
                        {u.display_name ? `${u.display_name} (@${u.username})` : `@${u.username}`}
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    className="mono"
                    value={subjectId}
                    onChange={(e) => setSubjectId(e.currentTarget.value)}
                    placeholder={t('Enter user ID…')}
                    required
                  />
                )
              ) : (
                <select value={subjectId} onChange={(e) => setSubjectId(e.currentTarget.value)} required>
                  <option value="">{t('Choose a role…')}</option>
                  {(roles || []).map((r) => (
                    <option key={r.name} value={r.name}>
                      {r.name} {r.description ? `— ${r.description}` : ''}
                    </option>
                  ))}
                </select>
              )}
            </Field>

            <Field label={t('Environment Scope')} help={t('Restrict access to a specific environment or apply across all environments')}>
              <select value={envSlug} onChange={(e) => setEnvSlug(e.currentTarget.value)}>
                <option value="*">{t('All Environments (*)')}</option>
                {envs.map((env) => (
                  <option key={env.slug} value={env.slug}>
                    {env.name} ({env.slug})
                  </option>
                ))}
              </select>
            </Field>

            {/* Granular Permissions Cards */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <span style={{ fontSize: 12, fontWeight: 600 }}>{t('Assigned Permissions')}</span>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <label style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '8px 12px', background: canRead ? 'var(--surface-2, var(--bg-subtle))' : 'transparent', border: '1px solid var(--border)', borderRadius: 6, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={canRead}
                    onChange={(e) => setCanRead(e.currentTarget.checked)}
                    style={{ marginTop: 2 }}
                  />
                  <div>
                    <strong style={{ fontSize: 13, display: 'block' }}>{t('Can Read (secrets.read)')}</strong>
                    <span className="muted small">{t('Decrypt and view secret values, export environment variables')}</span>
                  </div>
                </label>

                <label style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '8px 12px', background: canWrite ? 'var(--surface-2, var(--bg-subtle))' : 'transparent', border: '1px solid var(--border)', borderRadius: 6, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={canWrite}
                    onChange={(e) => setCanWrite(e.currentTarget.checked)}
                    style={{ marginTop: 2 }}
                  />
                  <div>
                    <strong style={{ fontSize: 13, display: 'block' }}>{t('Can Write (secrets.write)')}</strong>
                    <span className="muted small">{t('Create, edit, import, and delete secrets in this project')}</span>
                  </div>
                </label>

                <label style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '8px 12px', background: canAdmin ? 'var(--surface-2, var(--bg-subtle))' : 'transparent', border: '1px solid var(--border)', borderRadius: 6, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={canAdmin}
                    onChange={(e) => setCanAdmin(e.currentTarget.checked)}
                    style={{ marginTop: 2 }}
                  />
                  <div>
                    <strong style={{ fontSize: 13, display: 'block' }}>{t('Can Admin (projects.admin)')}</strong>
                    <span className="muted small">{t('Manage project policies, tokens, dynamic engines, and network sites')}</span>
                  </div>
                </label>
              </div>
            </div>

            <Field label={t('Reason / Notes')} help={t('Audit note explaining why access was requested')}>
              <input
                placeholder={t('e.g. ticket SEC-402, on-call deployment, QA testing')}
                value={description}
                onChange={(e) => setDescription(e.currentTarget.value)}
              />
            </Field>
          </div>

          {/* Right Column: JIT Expiry & Access Matrix Inspector */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {/* JIT Ephemeral Duration Card */}
            {!initial && (
              <div style={{ padding: '12px 14px', background: 'var(--surface-2, var(--bg-subtle))', borderRadius: 8, border: '1px solid var(--border)' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                  <span style={{ fontSize: 12, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
                    <Clock size={14} style={{ color: ttl > 0 ? '#ea580c' : 'var(--accent)' }} />
                    {t('Duration (Just-In-Time Expiry)')}
                  </span>
                  <Tag tone={ttl > 0 ? 'good' : 'accent'} mono style={{ fontSize: 10 }}>
                    {ttl > 0 ? t('JIT EPHEMERAL') : t('PERMANENT')}
                  </Tag>
                </div>
                <p className="muted small" style={{ margin: '0 0 10px 0', fontSize: 11, lineHeight: 1.4 }}>
                  {t('Access is revoked automatically when the expiration time is reached.')}
                </p>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {TTLS.map((item) => (
                    <button
                      key={item.s}
                      type="button"
                      className={ttl === item.s ? 'btn btn-sm btn-primary' : 'btn btn-sm btn-ghost'}
                      style={{ fontSize: 11, padding: '3px 8px', height: 'auto', border: '1px dashed var(--border)' }}
                      onClick={() => setTTL(item.s)}
                    >
                      {item.label}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Access Summary Card */}
            <div style={{ padding: '12px 14px', background: 'var(--surface-2, var(--bg-subtle))', borderRadius: 8, border: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
                <Activity size={14} style={{ color: 'var(--accent)' }} />
                <span style={{ fontSize: 12, fontWeight: 600 }}>{t('Effective Policy Matrix')}</span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid var(--border)' }}>
                  <span className="muted">{t('Subject')}</span>
                  <strong>
                    {subjectId ? (
                      subjectType === 'user' ? (selectedUserName ? `@${selectedUserName}` : subjectId) : `Role: ${selectedRoleName || subjectId}`
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </strong>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid var(--border)' }}>
                  <span className="muted">{t('Environment')}</span>
                  <Tag mono style={{ fontSize: 10 }}>{envSlug === '*' ? t('All (*)') : envSlug}</Tag>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: '1px solid var(--border)' }}>
                  <span className="muted">{t('Access Level')}</span>
                  <div style={{ display: 'flex', gap: 4 }}>
                    {canAdmin ? (
                      <Tag tone="bad" mono style={{ fontSize: 10 }}>{t('ADMIN')}</Tag>
                    ) : canWrite ? (
                      <Tag tone="accent" mono style={{ fontSize: 10 }}>{t('READ-WRITE')}</Tag>
                    ) : canRead ? (
                      <Tag tone="good" mono style={{ fontSize: 10 }}>{t('READ-ONLY')}</Tag>
                    ) : (
                      <Tag tone="muted" mono style={{ fontSize: 10 }}>{t('NONE')}</Tag>
                    )}
                  </div>
                </div>

                {!initial && (
                  <div style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0' }}>
                    <span className="muted">{t('Lifecycle')}</span>
                    <span className="muted mono" style={{ fontSize: 11 }}>
                      {ttl > 0 ? t('Expires in {0}', TTLS.find((x) => x.s === ttl)?.label || `${ttl}s`) : t('Permanent Grant')}
                    </span>
                  </div>
                )}
              </div>
            </div>

            {/* Zero-Trust Audit Notice */}
            <div style={{ padding: '10px 14px', background: 'var(--bg-subtle)', borderRadius: 8, border: '1px solid var(--border)', fontSize: 11 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                <ShieldCheck size={14} style={{ color: '#10b981' }} />
                <strong>{t('Audit Trail')}</strong>
              </div>
              <p className="muted small" style={{ margin: 0, lineHeight: 1.4 }}>
                {t('Access changes are recorded in the project audit log with user, IP address, and note.')}
              </p>
            </div>
          </div>
        </div>
      </form>
    </Modal>
  )
}
