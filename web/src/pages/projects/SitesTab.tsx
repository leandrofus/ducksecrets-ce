import { useMemo, useState, useEffect } from 'react'
import { Plus, Search, X, Trash2, Network, Check, Copy } from 'lucide-react'
import { t } from '../../i18n'
import { api, enc, type Site, type CreatedSite } from '../../lib/api'
import { getMe } from '../../lib/session'
import { invalidate, useResource } from '../../lib/store'
import { ago, dateTime, copy } from '../../lib/format'
import type { MenuEntry } from '../../ui/ContextMenu'
import { DataTable, Empty, Spinner, Tabs, Tag } from '../../ui/common'
import { Modal, confirm, openDialog, toast } from '../../ui/overlays'
import { Field } from '../../ui/Field'

export function SitesView({ projectId }: { projectId: string }) {
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
            onChange={(e) => setStatusFilter(e.target.value as 'all' | 'online' | 'offline')}
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

export function SiteModal({ projectId, onClose }: { projectId: string; onClose: () => void }) {
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
        <Field required label={t('Site Name')} help={t('e.g. aws-us-east-1-vpc, onprem-datacenter, customer-dc')}>
          <input required autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. prod-vpc-private" />
        </Field>
        <Field optional label={t('Description')}>
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

export function SiteSuccessModal({ site, onClose }: { site: CreatedSite; onClose: () => void }) {
  const [copiedToken, setCopiedToken] = useState(false)
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null)
  const [mode, setMode] = useState<'oneliner' | 'download' | 'cli'>('oneliner')
  const me = getMe()
  const [selfSigned, setSelfSigned] = useState(Boolean(me?.self_signed))
  const [tlsFingerprint, setTlsFingerprint] = useState(me?.tls_fingerprint || '')

  const serverUrl = window.location.origin
  const isHttps = serverUrl.startsWith('https://')

  useEffect(() => {
    if (!isHttps || me?.self_signed !== undefined) return
    let alive = true
    api.get<{ self_signed?: boolean; fingerprint_sha256?: string }>('/system/tls')
      .then((res) => {
        if (!alive) return
        if (res.self_signed) setSelfSigned(true)
        if (res.fingerprint_sha256) setTlsFingerprint(res.fingerprint_sha256)
      })
      .catch(() => {})
    return () => { alive = false }
  }, [isHttps, me?.self_signed])

  const curlFlags = selfSigned ? '-fksSL' : '-fsSL'
  const cliTlsFlag = selfSigned
    ? (tlsFingerprint ? ` --tls-fingerprint ${tlsFingerprint}` : ' --insecure')
    : ''
  const onelinerCmd = `curl ${curlFlags} ${serverUrl}/install.sh | sudo DUCKSECRETS_SITE_ID=${site.id} DUCKSECRETS_SITE_TOKEN=${site.token} sh`
  const downloadCmd = `curl ${curlFlags} ${serverUrl}/download/ducksecrets -o ducksecrets && chmod +x ducksecrets && ./ducksecrets site run --server ${serverUrl} --site-id ${site.id} --token ${site.token}${cliTlsFlag}`
  const cliCmd = `ducksecrets site run --server ${serverUrl} --site-id ${site.id} --token ${site.token}${cliTlsFlag}`

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
          onChange={(m) => setMode(m as 'oneliner' | 'download' | 'cli')}
        />
      </div>

      <div className="surface-box" style={{ marginTop: 12 }}>
        {isHttps && (
          <label className="check small muted" style={{ marginBottom: 10 }}>
            <input type="checkbox" checked={selfSigned} onChange={(e) => setSelfSigned(e.target.checked)} />
            <span>{t('Self-signed HTTPS certificate (passes -k on initial curl bootstrap; installer pins server cert automatically)')}</span>
          </label>
        )}
        {mode === 'oneliner' && (
          <>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
              <strong className="small">{t('Automated install & systemd service setup via curl (Recommended):')}</strong>
              <button className="btn btn-sm" onClick={() => handleCopyCmd(onelinerCmd, 'oneliner')}>
                {copiedCmd === 'oneliner' ? <Check size={13} /> : <Copy size={13} />} {copiedCmd === 'oneliner' ? t('Copied') : t('Copy Command')}
              </button>
            </div>
            <pre className="mono small" style={{ margin: 0, padding: 8, background: 'var(--bg)', borderRadius: 4, overflowX: 'auto', whiteSpace: 'pre-wrap' }}>
{onelinerCmd}
            </pre>
            <p className="muted small" style={{ margin: '8px 0 0' }}>
              {t('Downloads ducksecrets CLI, pins the server TLS certificate when self-signed, and registers a background systemd service (ducksecrets-site-*.service).')}
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
