import { useMemo, useState } from 'react'
import { Plus, Search, X, Trash2, KeyRound, Flame, ShieldCheck, Network, Code, Check, Copy } from 'lucide-react'
import { t } from '../../i18n'
import { api, enc, type Environment, type ServiceToken, type CreatedServiceToken } from '../../lib/api'
import { invalidate, useResource } from '../../lib/store'
import { ago, dateTime, copy } from '../../lib/format'
import type { MenuEntry } from '../../ui/ContextMenu'
import { DataTable, Empty, Spinner, Tag } from '../../ui/common'
import { Modal, confirm, openDialog, toast } from '../../ui/overlays'
import { Field } from '../../ui/Field'

export function TokensView({ projectId, envs }: { projectId: string; envs: Environment[] }) {
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
            onChange={(e) => setStatusFilter(e.target.value as 'all' | 'active' | 'burned')}
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
                        <Flame size={10} /> {t('BURNED')}
                      </Tag>
                    ) : (
                      <Tag tone="warning" title={t('Will auto-destruct on first secret retrieval')}>
                        <Flame size={10} /> {t('SINGLE-USE')}
                      </Tag>
                    )
                  ) : null}
                  {tk.allowed_cidrs ? (
                    <span className="muted small mono" title={t('Allowed networks: {0}', tk.allowed_cidrs.replace(/[\n\r]+/g, ', '))} style={{ display: 'inline-flex', alignItems: 'center' }}>
                      <ShieldCheck size={12} className="tone-ok" style={{ marginRight: 3 }} />
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

export function TokenModal({ projectId, envs, onClose }: { projectId: string; envs: Environment[]; onClose: () => void }) {
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
            <Field required label={t('Token Name')} help={t('Descriptive label (e.g. GitHub Actions, Docker Staging Agent)')}>
              <input required autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. CI / CD Runner" />
            </Field>

            <Field optional label={t('Environment Scope')} help={t('Restrict token to a specific project environment or grant wildcard access')}>
              <select value={envSlug} onChange={(e) => setEnvSlug(e.target.value)}>
                <option value="*">{t('All Environments (*)')}</option>
                {envs.map((env) => (
                  <option key={env.id} value={env.slug}>{env.name} ({env.slug})</option>
                ))}
              </select>
            </Field>

            <Field required label={t('Permissions')}>
              <select value={permissions} onChange={(e) => setPermissions(e.target.value)}>
                <option value="secrets.read">{t('Read Secrets Only (secrets.read)')}</option>
                <option value="secrets.read secrets.write">{t('Read & Write Secrets (secrets.read, secrets.write)')}</option>
                <option value="credentials.read">{t('View Credentials Only (credentials.read)')}</option>
                <option value="credentials.read credentials.write">{t('View & Edit Credentials (credentials.read, credentials.write)')}</option>
                <option value="secrets.read credentials.read">{t('Read Secrets & View Credentials (secrets.read, credentials.read)')}</option>
                <option value="secrets.read secrets.write credentials.read credentials.write">{t('Full Secrets & Credentials Read/Write')}</option>
              </select>
            </Field>

            <Field optional label={t('Expiration')}>
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
            <div className="surface-box">
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
                  className="btn btn-ghost btn-xs"
                  style={{ border: '1px dashed var(--border)' }}
                  onClick={() => appendCidr('127.0.0.1/32')}
                >
                  + 127.0.0.1/32 (Host)
                </button>
                <button
                  type="button"
                  className="btn btn-ghost btn-xs"
                  style={{ border: '1px dashed var(--border)' }}
                  onClick={() => appendCidr('172.17.0.0/16')}
                >
                  + 172.17.0.0/16 (Docker)
                </button>
                <button
                  type="button"
                  className="btn btn-ghost btn-xs"
                  style={{ border: '1px dashed var(--border)' }}
                  onClick={() => appendCidr('10.0.0.0/8')}
                >
                  + 10.0.0.0/8 (VPC)
                </button>
              </div>
            </div>

            {/* Zero-Trust Single-Use Card */}
            <div className="surface-box">
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{ fontSize: 12, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Flame size={14} style={{ color: singleUse ? 'var(--warn)' : 'var(--muted)' }} />
                  {t('Single-Use Token')}
                </span>
                {singleUse && <Tag tone="bad" mono style={{ fontSize: 10 }}>{t('BURNS AFTER READ')}</Tag>}
              </div>
              <label className="check" style={{ margin: '6px 0 4px 0', fontWeight: 500 }}>
                <input type="checkbox" checked={singleUse} onChange={(e) => setSingleUse(e.target.checked)} />
                <span>{t('Burn token permanently on first secrets read')}</span>
              </label>
              <p className="muted small" style={{ margin: 0, fontSize: 11, lineHeight: 1.4 }}>
                {t('Useful for containers: the token expires after its first read so it cannot be reused.')}
              </p>
            </div>

            {/* Usage Preview Snippet */}
            <div className="surface-box" style={{ fontSize: 11 }}>
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

export function TokenSuccessModal({ token, onClose }: { token: CreatedServiceToken; onClose: () => void }) {
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

      <div className="surface-box" style={{ marginTop: 16 }}>
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

export async function removeToken(projectId: string, tk: ServiceToken) {
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
