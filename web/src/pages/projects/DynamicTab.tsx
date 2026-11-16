import { useMemo, useState } from 'react'
import {
  Plus,
  Search,
  X,
  Trash2,
  Copy,
  KeyRound,
  Database,
  Server,
  Clock,
  Activity,
  Network,
} from 'lucide-react'
import { t } from '../../i18n'
import {
  api,
  enc,
  type Environment,
  type DynamicProvider,
  type DynamicLease,
  type IssuedLease,
  type TestProviderResponse,
  type Site,
} from '../../lib/api'
import { invalidate, useResource } from '../../lib/store'
import { go } from '../../lib/router'
import { copy } from '../../lib/format'
import { useMenu, type MenuEntry } from '../../ui/ContextMenu'
import { Empty, Spinner, Tabs, Tag } from '../../ui/common'
import { Modal, confirm, openDialog, toast } from '../../ui/overlays'
import { Field } from '../../ui/Field'
import { DynamicProviderModal } from './DynamicProviderModal'

export function DynamicView({ projectId, envSlug, envs }: { projectId: string; envSlug: string; envs: Environment[] }) {
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
  const [duckjumpUrl, setDuckjumpUrl] = useState(() => {
    try {
      return localStorage.getItem('ducksecrets.duckjump_url') || ''
    } catch {
      return ''
    }
  })
  const [editingJumpUrl, setEditingJumpUrl] = useState(false)
  const [jumpDraft, setJumpDraft] = useState(duckjumpUrl)

  const saveDuckjumpUrl = () => {
    const clean = jumpDraft.trim().replace(/\/+$/, '')
    setDuckjumpUrl(clean)
    try {
      if (clean) localStorage.setItem('ducksecrets.duckjump_url', clean)
      else localStorage.removeItem('ducksecrets.duckjump_url')
    } catch {}
    setEditingJumpUrl(false)
  }

  const dbProviders = useMemo(
    () => (providers || []).filter((p) => p.engine !== 'pam'),
    [providers]
  )

  const filteredProviders = useMemo(() => {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean)
    return dbProviders.filter((p) => {
      if (engineFilter && p.engine !== engineFilter) return false
      return words.every((w) => `${p.name} ${p.engine}`.toLowerCase().includes(w))
    })
  }, [dbProviders, q, engineFilter])

  return (
    <div>
      <div className="vault-subnav">
        <Tabs
          tabs={envs.map((e) => ({ id: e.slug, label: e.name }))}
          active={currentEnv}
          onChange={(slug) => setSelectedEnv(slug)}
        />
        <span className="muted small">{t('{0} engines configured', dbProviders.length)}</span>
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

      {providers && dbProviders.length === 0 ? (
        <Empty
          icon={<Database size={32} />}
          title={t('No dynamic secret engines in {0}', currentEnv)}
          action={
            <button className="btn btn-primary" onClick={() => openDialog((c) => <DynamicProviderModal projectId={projectId} envSlug={currentEnv} onClose={c} />)}>
              <Plus size={14} /> {t('Configure Dynamic Engine')}
            </button>
          }
        >
          <p>{t('Configure on-demand ephemeral credentials for PostgreSQL, MySQL, or Redis.')}</p>
        </Empty>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: 16 }}>
          {filteredProviders.map((p) => (
            <div key={p.id} className="card" onContextMenu={menu(() => providerActions(p))} style={{ padding: 16, borderRadius: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Database size={18} style={{ color: 'var(--accent)' }} />
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
                  className="icon-btn tone-bad"
                  style={{ marginLeft: 'auto' }}
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

      {/* DuckJump (Duck Suite) Integration Card */}
      <div
        className="card"
        style={{
          marginTop: 20,
          padding: 16,
          borderRadius: 8,
          display: 'flex',
          flexDirection: 'column',
          gap: 10,
          background: 'var(--surface-2)',
          cursor: 'default',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Server size={18} style={{ color: 'var(--accent)' }} />
            <div>
              <strong>{t('SSH Bastion & Host Access → DuckJump (Duck Suite)')}</strong>
              <p className="muted small" style={{ margin: '2px 0 0' }}>
                {t('Ephemeral Linux SSH sessions, audited shells, and local port forwarding to dev/prod servers are handled natively by DuckJump. Use scoped DuckSecrets Service Tokens to sync keys or vault secrets with your DuckJump instance.')}
              </p>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <button
              type="button"
              className="btn btn-sm btn-subtle"
              onClick={() => go('projects', projectId, 'tokens')}
            >
              <KeyRound size={13} /> {t('Issue Service Token')}
            </button>
            {duckjumpUrl && /^https?:\/\//i.test(duckjumpUrl) && (
              <a
                className="btn btn-sm btn-primary"
                href={duckjumpUrl}
                target="_blank"
                rel="noopener noreferrer"
              >
                {t('Open DuckJump')}
              </a>
            )}
            <button
              type="button"
              className="btn btn-sm btn-ghost"
              onClick={() => {
                setJumpDraft(duckjumpUrl)
                setEditingJumpUrl((v) => !v)
              }}
            >
              {duckjumpUrl ? t('Edit URL') : t('Link DuckJump URL')}
            </button>
          </div>
        </div>

        {editingJumpUrl && (
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', marginTop: 4 }}>
            <input
              type="url"
              placeholder="https://duckjump.example.com"
              value={jumpDraft}
              onChange={(e) => setJumpDraft(e.target.value)}
              style={{ flex: 1, minWidth: 240 }}
            />
            <button type="button" className="btn btn-sm btn-primary" onClick={saveDuckjumpUrl}>
              {t('Save')}
            </button>
            <button type="button" className="btn btn-sm btn-ghost" onClick={() => setEditingJumpUrl(false)}>
              {t('Cancel')}
            </button>
          </div>
        )}
      </div>
    </div>
  )
}

export function ActiveLeasesList({
  projectId,
  envSlug,
  providerId,
}: {
  projectId: string
  envSlug: string
  providerId: string
}) {
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
            <button className="btn btn-xs btn-ghost tone-bad" onClick={() => revoke(l.id)}>
              {t('Revoke')}
            </button>
          </div>
        </div>
      ))}
    </div>
  )
}

export function IssueLeaseModal({
  projectId,
  envSlug,
  provider,
  onClose,
}: {
  projectId: string
  envSlug: string
  provider: DynamicProvider
  onClose: () => void
}) {
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

export function LeaseSuccessModal({
  lease,
  onClose,
}: {
  lease: IssuedLease
  onClose: () => void
}) {
  const copyCred = (val: string, label: string) => {
    copy(val).then((ok) => {
      if (ok) toast.ok(t('{0} copied', label))
    })
  }
  const cliConnectCmd = `ducksecrets connect --lease ${lease.lease_id}`

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

      <Field
        label={t('Connect via Managed Tunnel (CLI)')}
        help={t('Opens a secure localhost proxy and revokes credentials on disconnect')}
      >
        <div style={{ display: 'flex', gap: 8 }}>
          <input readOnly className="mono" value={cliConnectCmd} style={{ flex: 1 }} />
          <button className="btn btn-sm btn-subtle" onClick={() => copyCred(cliConnectCmd, 'CLI Command')}><Copy size={13} /></button>
        </div>
      </Field>

      <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 16 }}>
        <button className="btn btn-primary" onClick={onClose}>{t('Done')}</button>
      </div>
    </Modal>
  )
}
