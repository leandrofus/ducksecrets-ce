import { useMemo, useState } from 'react'
import {
  KeyRound,
  ShieldCheck,
  Globe,
  UserCheck,
  Plus,
  Search,
  X,
  RefreshCw,
  Eye,
  Pencil,
  Trash2,
  Layers,
  Copy,
  ArrowUpRight,
} from 'lucide-react'
import { t } from '../../i18n'
import { api, enc, type Credential, type CredentialList } from '../../lib/api'
import { ago, copy, dateTime } from '../../lib/format'
import { allowed } from '../../lib/access'
import { go } from '../../lib/router'
import { invalidate, useResource } from '../../lib/store'
import type { MenuEntry } from '../../ui/ContextMenu'
import { DataTable, Empty, Tabs, Tag } from '../../ui/common'
import { confirm, openDialog, toast } from '../../ui/overlays'
import {
  CredentialModal,
  credentialKindLabel,
  credentialKindTone,
} from './CredentialModal'
import { CredentialInspectorModal } from './CredentialInspectorModal'
import { SyncCredentialModal } from './SyncCredentialModal'

export async function removeCredential(c: Credential, onDone?: () => void) {
  const ok = await confirm({
    title: t('Delete credential {0}?', c.name),
    body: t('This will permanently delete this encrypted credential from the vault.'),
    danger: true,
    confirm: t('Delete Credential'),
  })
  if (!ok) return
  try {
    await api.del(`/credentials/${enc(c.id)}`)
    invalidate('/credentials')
    if (c.project_id) invalidate(`/projects/${enc(c.project_id)}/credentials`)
    toast.ok(t('Credential deleted'))
    onDone?.()
  } catch (err) {
    toast.err(err)
  }
}

export function copyPrimaryCredentialMaterial(c: Credential) {
  api
    .get<Credential>(`/credentials/${enc(c.id)}`)
    .then((res) => {
      const p = res.payload || {}
      const primary =
        p.private_key ||
        p.client_secret ||
        p.api_key ||
        p.password ||
        p.certificate ||
        p.public_key ||
        ''
      if (!primary) {
        toast.err(t('No secret material found in this credential'))
        return
      }
      copy(primary).then((ok) => {
        if (ok) toast.ok(t('Primary secret of {0} copied to clipboard', c.name))
      })
    })
    .catch(toast.err)
}

export function CredentialsListView({
  projectId,
  envSlug,
}: {
  projectId?: string
  envSlug?: string
}) {
  const endpoint = projectId
    ? `/projects/${enc(projectId)}/credentials`
    : '/credentials'
  const { data, error, loading } = useResource<CredentialList>(endpoint)
  const [kindFilter, setKindFilter] = useState<'all' | 'ssh_key' | 'tls_cert' | 'oauth_api' | 'login'>('all')
  const [q, setQ] = useState('')

  const canEdit = allowed('credentials.write')
  const items = data?.items || []

  const rows = useMemo(() => {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean)
    return items.filter((c) => {
      if (kindFilter !== 'all' && c.kind !== kindFilter) return false
      if (projectId && envSlug && c.environment_slug && c.environment_slug !== envSlug) {
        // Show both wildcard ('') and matching env credentials
      }
      return words.every((w) =>
        `${c.name} ${c.kind} ${c.summary} ${c.description} ${c.project_name || ''} ${c.environment_slug || ''}`
          .toLowerCase()
          .includes(w),
      )
    })
  }, [items, kindFilter, q, projectId, envSlug])

  const counts = useMemo(() => {
    const map = { all: items.length, ssh_key: 0, tls_cert: 0, oauth_api: 0, login: 0 }
    for (const c of items) {
      if (c.kind in map) map[c.kind as keyof typeof map]++
    }
    return map
  }, [items])

  const rowMenu = (c: Credential): MenuEntry[] => [
    { header: c.name },
    {
      label: t('Inspect & Reveal…'),
      icon: <Eye size={14} />,
      onClick: () => openDialog((close) => <CredentialInspectorModal credential={c} onClose={close} />),
    },
    {
      label: t('Copy Primary Secret'),
      icon: <Copy size={14} />,
      onClick: () => copyPrimaryCredentialMaterial(c),
    },
    {
      label: t('Sync to Environment (.env)…'),
      icon: <Layers size={14} />,
      onClick: () =>
        openDialog((close) => (
          <SyncCredentialModal
            credential={c}
            defaultProjectId={projectId || c.project_id || undefined}
            defaultEnvSlug={envSlug || c.environment_slug || undefined}
            onClose={close}
          />
        )),
    },
    ...(canEdit
      ? ([
          {
            label: t('Edit…'),
            icon: <Pencil size={14} />,
            onClick: () => openDialog((close) => <CredentialModal initial={c} onClose={close} />),
          },
          'sep',
          {
            label: t('Delete'),
            icon: <Trash2 size={14} />,
            danger: true,
            onClick: () => removeCredential(c),
          },
        ] as MenuEntry[])
      : []),
  ]

  const kindIcon = (kind: string) => {
    switch (kind) {
      case 'ssh_key':
        return <KeyRound size={15} style={{ color: 'var(--accent)' }} />
      case 'tls_cert':
        return <ShieldCheck size={15} style={{ color: 'var(--ok)' }} />
      case 'oauth_api':
        return <Globe size={15} style={{ color: 'var(--accent)' }} />
      default:
        return <UserCheck size={15} className="muted" />
    }
  }

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap', marginBottom: 14 }}>
        <Tabs
          tabs={[
            { id: 'all', label: t('All Credentials'), count: counts.all },
            { id: 'ssh_key', label: t('SSH Keys'), count: counts.ssh_key },
            { id: 'tls_cert', label: t('TLS Certificates'), count: counts.tls_cert },
            { id: 'oauth_api', label: t('API & OAuth'), count: counts.oauth_api },
            { id: 'login', label: t('Logins'), count: counts.login },
          ]}
          active={kindFilter}
          onChange={(next) => setKindFilter(next as any)}
        />

        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div className="search-input">
            <Search size={14} />
            <input
              placeholder={t('Filter credentials…')}
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
            {q && (
              <button className="icon-btn" onClick={() => setQ('')}>
                <X size={13} />
              </button>
            )}
          </div>
          <button
            className="icon-btn"
            title={t('Refresh')}
            onClick={() => invalidate(endpoint)}
          >
            <RefreshCw size={15} />
          </button>
          {canEdit && (
            <button
              className="btn btn-sm btn-primary"
              onClick={() =>
                openDialog((close) => (
                  <CredentialModal
                    defaultProjectId={projectId}
                    defaultEnvSlug={envSlug}
                    onClose={close}
                  />
                ))
              }
            >
              <Plus size={14} /> {t('Add Credential')}
            </button>
          )}
        </div>
      </div>

      {error && <div className="alert alert-bad" style={{ marginBottom: 14 }}>{error.message}</div>}

      {!loading && rows.length === 0 ? (
        <Empty
          icon={<KeyRound size={30} />}
          title={t('No structured credentials stored yet')}
          action={
            canEdit ? (
              <button
                className="btn btn-sm btn-primary"
                onClick={() =>
                  openDialog((close) => (
                    <CredentialModal
                      defaultProjectId={projectId}
                      defaultEnvSlug={envSlug}
                      onClose={close}
                    />
                  ))
                }
              >
                <Plus size={14} /> {t('Add Credential')}
              </button>
            ) : undefined
          }
        >
          {t(
            'Store SSH keypairs (with built-in Ed25519/RSA generator), X.509 TLS certificates, OAuth 2.0 / API keys, and logins — and optionally link or sync them to any Project & Environment.',
          )}
        </Empty>
      ) : (
        <DataTable
          rows={rows}
          rowKey={(c) => c.id}
          rowMenu={rowMenu}
          onOpen={(c) => openDialog((close) => <CredentialInspectorModal credential={c} onClose={close} />)}
          columns={[
            {
              key: 'name',
              label: t('Credential'),
              sort: (c) => c.name.toLowerCase(),
              render: (c) => (
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  {kindIcon(c.kind)}
                  <div>
                    <strong>{c.name}</strong>
                    {c.description && <div className="muted small ellipsis">{c.description}</div>}
                  </div>
                </div>
              ),
            },
            {
              key: 'kind',
              label: t('Type'),
              width: 140,
              sort: (c) => c.kind,
              render: (c) => <Tag tone={credentialKindTone(c.kind)}>{credentialKindLabel(c.kind)}</Tag>,
            },
            {
              key: 'summary',
              label: t('Identity / Fingerprint / Details'),
              render: (c) => <span className="mono small muted">{c.summary || '—'}</span>,
            },
            ...(!projectId
              ? [
                  {
                    key: 'scope',
                    label: t('Project / Scope'),
                    render: (c: Credential) =>
                      c.project_id ? (
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <button
                            type="button"
                            className="btn btn-xs btn-ghost"
                            onClick={(e) => {
                              e.stopPropagation()
                              go('projects', c.project_id!, 'credentials')
                            }}
                          >
                            {c.project_name || c.project_slug || t('Project')}
                            <ArrowUpRight size={11} />
                          </button>
                          <Tag mono tone="muted">
                            {c.environment_slug || '*'}
                          </Tag>
                        </div>
                      ) : (
                        <Tag tone="muted">{t('Global')}</Tag>
                      ),
                  },
                ]
              : [
                  {
                    key: 'env',
                    label: t('Environment'),
                    width: 130,
                    render: (c: Credential) => (
                      <Tag mono tone={c.environment_slug ? 'accent' : 'muted'}>
                        {c.environment_slug || t('All (*)')}
                      </Tag>
                    ),
                  },
                ]),
            {
              key: 'expires',
              label: t('Expires'),
              width: 130,
              sort: (c) => c.expires_at || '',
              render: (c) => {
                if (!c.expires_at) return <span className="muted small">{t('Never')}</span>
                const expMs = new Date(c.expires_at).getTime()
                const expired = expMs <= Date.now()
                return (
                  <Tag tone={expired ? 'bad' : 'ok'} title={dateTime(c.expires_at)}>
                    {expired ? t('Expired') : ago(c.expires_at)}
                  </Tag>
                )
              },
            },
            {
              key: 'actions',
              label: '',
              width: 150,
              render: (c) => (
                <div style={{ display: 'flex', gap: 4, justifyContent: 'flex-end' }}>
                  <button
                    type="button"
                    className="btn btn-xs btn-ghost"
                    title={t('Copy Primary Secret')}
                    onClick={(e) => {
                      e.stopPropagation()
                      copyPrimaryCredentialMaterial(c)
                    }}
                  >
                    <Copy size={12} /> {t('Copy')}
                  </button>
                  <button
                    type="button"
                    className="btn btn-xs btn-ghost"
                    title={t('Sync fields into Environment Secrets')}
                    onClick={(e) => {
                      e.stopPropagation()
                      openDialog((close) => (
                        <SyncCredentialModal
                          credential={c}
                          defaultProjectId={projectId || c.project_id || undefined}
                          defaultEnvSlug={envSlug || c.environment_slug || undefined}
                          onClose={close}
                        />
                      ))
                    }}
                  >
                    <Layers size={12} /> {t('Sync .env')}
                  </button>
                </div>
              ),
            },
          ]}
        />
      )}
    </div>
  )
}
