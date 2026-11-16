import { useMemo, useState } from 'react'
import {
  Plus,
  Search,
  X,
  Trash2,
  Pencil,
  Clock,
  Activity,
  ShieldCheck,
  User as UserIcon,
  UsersRound,
} from 'lucide-react'
import { t } from '../../i18n'
import {
  api,
  enc,
  type Page,
  type ProjectPolicy,
  type Environment,
  type User,
  type Role,
} from '../../lib/api'
import { allowed } from '../../lib/access'
import { invalidate, useResource } from '../../lib/store'
import { ago, dateTime } from '../../lib/format'
import type { MenuEntry } from '../../ui/ContextMenu'
import { DataTable, Empty, Spinner, Tag } from '../../ui/common'
import { Modal, confirm, openDialog, toast } from '../../ui/overlays'
import { Field } from '../../ui/Field'

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

export function PolicyExpiry({ p }: { p: ProjectPolicy }) {
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

export function PolicyPerms({ p }: { p: ProjectPolicy }) {
  return (
    <span style={{ display: 'inline-flex', gap: 4, flexWrap: 'wrap' }}>
      {p.can_read && <Tag tone="ok">{t('Read Secrets')}</Tag>}
      {p.can_write && <Tag tone="accent">{t('Write Secrets')}</Tag>}
      {p.can_view_creds && <Tag tone="ok">{t('View Creds')}</Tag>}
      {p.can_edit_creds && <Tag tone="accent">{t('Edit Creds')}</Tag>}
      {p.can_admin && <Tag tone="bad">{t('Admin')}</Tag>}
    </span>
  )
}

export async function removePolicy(projectId: string, p: ProjectPolicy) {
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

export function PoliciesView({ projectId, envs }: { projectId: string; envs: Environment[] }) {
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
            onChange={(e) => setSubjectFilter(e.target.value as 'all' | 'user' | 'role')}
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

export function PolicyModal({
  projectId,
  envs,
  initial,
  defaultEnvSlug,
  onClose,
}: {
  projectId: string
  envs: Environment[]
  initial?: ProjectPolicy
  defaultEnvSlug?: string
  onClose: () => void
}) {
  const canListUsers = allowed('users.manage')
  const { data: usersData } = useResource<Page<User>>(canListUsers ? '/users?per_page=100' : null)
  const { data: roles } = useResource<Role[]>('/roles')

  const [subjectType, setSubjectType] = useState<'user' | 'role'>(initial ? initial.subject_type : 'user')
  const [subjectId, setSubjectId] = useState<string>(initial ? initial.subject_id : '')
  const [envSlug, setEnvSlug] = useState<string>(initial ? initial.environment_slug : defaultEnvSlug || '*')
  const [canRead, setCanRead] = useState<boolean>(initial ? initial.can_read : true)
  const [canWrite, setCanWrite] = useState<boolean>(initial ? initial.can_write : false)
  const [canViewCreds, setCanViewCreds] = useState<boolean>(initial ? Boolean(initial.can_view_creds) : true)
  const [canEditCreds, setCanEditCreds] = useState<boolean>(initial ? Boolean(initial.can_edit_creds) : false)
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
          can_view_creds: canViewCreds,
          can_edit_creds: canEditCreds,
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
          can_view_creds: canViewCreds,
          can_edit_creds: canEditCreds,
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
            disabled={busy || !subjectId || (!canRead && !canWrite && !canViewCreds && !canEditCreds && !canAdmin)}
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
                    <UserIcon size={14} /> {t('User')}
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
                    <UsersRound size={14} /> {t('Role Group')}
                  </button>
                </div>
              </Field>
            ) : null}

            <Field required={!initial} label={subjectType === 'user' ? (canListUsers ? t('Select User') : t('User ID')) : t('Select Role')}>
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

            <Field optional label={t('Environment Scope')} help={t('Restrict access to a specific environment or apply across all environments')}>
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
                <label style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '8px 12px', background: canRead ? 'var(--surface-2)' : 'transparent', border: '1px solid var(--border)', borderRadius: 6, cursor: 'pointer' }}>
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

                <label style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '8px 12px', background: canWrite ? 'var(--surface-2)' : 'transparent', border: '1px solid var(--border)', borderRadius: 6, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={canWrite}
                    onChange={(e) => setCanWrite(e.currentTarget.checked)}
                    style={{ marginTop: 2 }}
                  />
                  <div>
                    <strong style={{ fontSize: 13, display: 'block' }}>{t('Can Write Secrets (secrets.write)')}</strong>
                    <span className="muted small">{t('Create, edit, import, and delete secrets in this project')}</span>
                  </div>
                </label>

                <label style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '8px 12px', background: canViewCreds ? 'var(--surface-2)' : 'transparent', border: '1px solid var(--border)', borderRadius: 6, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={canViewCreds}
                    onChange={(e) => setCanViewCreds(e.currentTarget.checked)}
                    style={{ marginTop: 2 }}
                  />
                  <div>
                    <strong style={{ fontSize: 13, display: 'block' }}>{t('Can View Credentials (credentials.read)')}</strong>
                    <span className="muted small">{t('Inspect, decrypt, export, and connect using SSH keys, DB logins, TLS certs, and API tokens')}</span>
                  </div>
                </label>

                <label style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '8px 12px', background: canEditCreds ? 'var(--surface-2)' : 'transparent', border: '1px solid var(--border)', borderRadius: 6, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={canEditCreds}
                    onChange={(e) => setCanEditCreds(e.currentTarget.checked)}
                    style={{ marginTop: 2 }}
                  />
                  <div>
                    <strong style={{ fontSize: 13, display: 'block' }}>{t('Can Edit Credentials (credentials.write)')}</strong>
                    <span className="muted small">{t('Create, rotate, update, and delete structured credentials in this project')}</span>
                  </div>
                </label>

                <label style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '8px 12px', background: canAdmin ? 'var(--surface-2)' : 'transparent', border: '1px solid var(--border)', borderRadius: 6, cursor: 'pointer' }}>
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

            <Field optional label={t('Reason / Notes')} help={t('Audit note explaining why access was requested')}>
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
              <div className="surface-box">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                  <span style={{ fontSize: 12, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
                    <Clock size={14} style={{ color: ttl > 0 ? 'var(--warn)' : 'var(--accent)' }} />
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
                      className={ttl === item.s ? 'btn btn-xs btn-primary' : 'btn btn-xs btn-ghost'}
                      style={{ border: '1px dashed var(--border)' }}
                      onClick={() => setTTL(item.s)}
                    >
                      {item.label}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Access Summary Card */}
            <div className="surface-box">
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
            <div className="surface-box" style={{ fontSize: 11 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                <ShieldCheck size={14} className="tone-ok" />
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
