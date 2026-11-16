import { t } from '../i18n'
import { useMemo, useState } from 'react'
import { ArrowUpRight, Network, RefreshCw, Search, Server, X } from 'lucide-react'
import type { LicenseStatus } from '../lib/api'
import { can } from '../lib/session'
import { useFleetInventory } from '../lib/fleet'
import { ago, dateTime } from '../lib/format'
import { go } from '../lib/router'
import { useResource } from '../lib/store'
import { DataTable, Empty, Pill, Spinner, Tag } from '../ui/common'

export function NetworkSites() {
  const isAdmin = can('system.manage')
  const fleet = useFleetInventory({ sites: true })
  const { data: license } = useResource<LicenseStatus>('/system/license')
  const [q, setQ] = useState('')

  const rows = useMemo(() => {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean)
    return fleet.sites.filter((s) =>
      words.every((w) => `${s.name} ${s.description} ${s.project_name} ${s.project_slug} ${s.token_prefix}`.toLowerCase().includes(w)),
    )
  }, [fleet.sites, q])

  const onlineCount = fleet.sites.filter((s) => s.online).length
  const maxSitesText = license ? (license.max_sites < 0 ? t('Unlimited') : String(license.max_sites)) : '—'
  const quotaReached = Boolean(license && license.max_sites >= 0 && license.used_sites >= license.max_sites)

  return (
    <div className="page">
      <div className="page-head">
        <div className="page-title">
          <Network size={20} />
          <h1>{t('Network Sites')}</h1>
          <span className="count">{fleet.sites.length}</span>
          {onlineCount > 0 && <Tag tone="ok">{t('{0} online', onlineCount)}</Tag>}
          {fleet.loading && <Spinner />}
        </div>
        <div className="page-actions">
          {license && (
            <Tag tone={quotaReached ? 'bad' : 'muted'}>
              <Server size={12} style={{ marginRight: 4 }} />
              {t('Quota: {0} / {1}', license.used_sites, maxSitesText)}
            </Tag>
          )}
          <div className="search-input">
            <Search size={14} />
            <input placeholder={t('Filter sites…')} value={q} onChange={(e) => setQ(e.target.value)} />
            {q && (
              <button className="icon-btn" onClick={() => setQ('')}>
                <X size={13} />
              </button>
            )}
          </div>
          <button className="icon-btn" title={t('Refresh')} onClick={fleet.refresh}>
            <RefreshCw size={15} />
          </button>
        </div>
      </div>

      <div className="page-body">
        {fleet.error && <div className="alert alert-bad" style={{ marginBottom: 14 }}>{fleet.error.message}</div>}

        {quotaReached && isAdmin && (
          <div className="alert" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, marginBottom: 14 }}>
            <span>
              {t('You have reached the Network Sites quota ({0}) for your current edition.', maxSitesText)}
            </span>
            <button className="btn btn-sm btn-primary" onClick={() => go('license')}>
              {t('Manage License')}
            </button>
          </div>
        )}

        {!fleet.loading && fleet.sites.length === 0 ? (
          <Empty
            icon={<Network size={30} />}
            title={t('No network sites configured')}
            action={
              fleet.projects[0] ? (
                <button className="btn btn-sm btn-primary" onClick={() => go('projects', fleet.projects[0].id, 'sites')}>
                  {t('Configure in a Project')}
                </button>
              ) : (
                <button className="btn btn-sm btn-primary" onClick={() => go('projects')}>
                  {t('Go to Projects')}
                </button>
              )
            }
          >
            {t('Deploy outbound reverse tunnel connectors in private networks so DuckSecrets can reach internal databases without opening inbound firewall ports.')}
          </Empty>
        ) : (
          <DataTable
            rows={rows}
            rowKey={(s) => s.id}
            onOpen={(s) => go('projects', s.project_id, 'sites')}
            columns={[
              {
                key: 'status',
                label: t('Status'),
                width: 110,
                sort: (s) => (s.online ? 1 : 0),
                render: (s) => <Pill state={s.online ? 'running' : 'stopped'} label={s.online ? t('Online') : t('Offline')} />,
              },
              {
                key: 'name',
                label: t('Site'),
                sort: (s) => s.name.toLowerCase(),
                render: (s) => (
                  <div>
                    <strong>{s.name}</strong>
                    {s.description && <div className="muted small ellipsis">{s.description}</div>}
                  </div>
                ),
              },
              {
                key: 'project',
                label: t('Project'),
                sort: (s) => s.project_name.toLowerCase(),
                render: (s) => (
                  <div>
                    <span>{s.project_name}</span>
                    <div className="muted small mono">{s.project_slug}</div>
                  </div>
                ),
              },
              {
                key: 'prefix',
                label: t('Token Prefix'),
                render: (s) => <code className="small">{s.token_prefix}…</code>,
              },
              {
                key: 'seen',
                label: t('Last Seen'),
                sort: (s) => s.last_seen_at || '',
                render: (s) =>
                  s.last_seen_at ? (
                    <span className="muted small" title={dateTime(s.last_seen_at)}>{ago(s.last_seen_at)}</span>
                  ) : (
                    <span className="muted small">{t('Never connected')}</span>
                  ),
              },
              {
                key: 'open',
                label: '',
                width: 90,
                render: (s) => (
                  <button
                    type="button"
                    className="btn btn-xs btn-ghost"
                    onClick={(e) => {
                      e.stopPropagation()
                      go('projects', s.project_id, 'sites')
                    }}
                  >
                    {t('Open')} <ArrowUpRight size={12} />
                  </button>
                ),
              },
            ]}
          />
        )}
      </div>
    </div>
  )
}
