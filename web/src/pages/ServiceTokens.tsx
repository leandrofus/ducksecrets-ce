import { t } from '../i18n'
import { useMemo, useState } from 'react'
import { ArrowUpRight, RefreshCw, Search, Ticket, Trash2, X } from 'lucide-react'
import { api, enc } from '../lib/api'
import { isTokenActive, useFleetInventory } from '../lib/fleet'
import type { FleetToken } from '../lib/fleet'
import { ago, dateTime } from '../lib/format'
import { go } from '../lib/router'
import { DataTable, Empty, Spinner, Tag } from '../ui/common'
import { confirm, toast } from '../ui/overlays'

export function ServiceTokens() {
  const fleet = useFleetInventory({ tokens: true })
  const [q, setQ] = useState('')
  const [busyId, setBusyId] = useState<string | null>(null)

  const rows = useMemo(() => {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean)
    return fleet.tokens.filter((tk) =>
      words.every((w) =>
        `${tk.name} ${tk.token_prefix} ${tk.environment_slug} ${tk.path} ${tk.allowed_cidrs} ${tk.project_name} ${tk.permissions}`
          .toLowerCase()
          .includes(w),
      ),
    )
  }, [fleet.tokens, q])

  const revokeToken = async (tk: FleetToken) => {
    const ok = await confirm({
      title: t('Revoke service token {0}?', tk.name),
      body: t('CI/CD jobs or containers using {0}… will immediately lose access.', tk.token_prefix),
      danger: true,
      confirm: t('Revoke'),
    })
    if (!ok) return
    setBusyId(tk.id)
    try {
      await api.del(`/projects/${enc(tk.project_id)}/tokens/${enc(tk.id)}`)
      toast.ok(t('Service token revoked'))
      fleet.refresh()
    } catch (err: any) {
      toast.err(err)
    } finally {
      setBusyId(null)
    }
  }

  const activeCount = fleet.tokens.filter(isTokenActive).length

  return (
    <div className="page">
      <div className="page-head">
        <div className="page-title">
          <Ticket size={20} />
          <h1>{t('Service Tokens')}</h1>
          <span className="count">{fleet.tokens.length}</span>
          <Tag tone="ok">{t('{0} active', activeCount)}</Tag>
          {fleet.loading && <Spinner />}
        </div>
        <div className="page-actions">
          <div className="search-input">
            <Search size={14} />
            <input placeholder={t('Filter tokens…')} value={q} onChange={(e) => setQ(e.target.value)} />
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

        {!fleet.loading && fleet.tokens.length === 0 ? (
          <Empty
            icon={<Ticket size={30} />}
            title={t('No service tokens issued')}
            action={
              fleet.projects[0] ? (
                <button className="btn btn-sm btn-primary" onClick={() => go('projects', fleet.projects[0].id, 'tokens')}>
                  {t('Create in a Project')}
                </button>
              ) : (
                <button className="btn btn-sm btn-primary" onClick={() => go('projects')}>
                  {t('Go to Projects')}
                </button>
              )
            }
          >
            {t('Provision scoped machine tokens (duck_st_*) inside projects with environment, path, and CIDR restrictions for CI/CD and containers.')}
          </Empty>
        ) : (
          <DataTable
            rows={rows}
            rowKey={(tk) => tk.id}
            onOpen={(tk) => go('projects', tk.project_id, 'tokens')}
            columns={[
              {
                key: 'status',
                label: t('Status'),
                width: 110,
                render: (tk) =>
                  tk.burned_at ? (
                    <Tag tone="muted">{t('Burned')}</Tag>
                  ) : isTokenActive(tk) ? (
                    <Tag tone="ok">{tk.single_use ? t('Single-Use') : t('Active')}</Tag>
                  ) : (
                    <Tag tone="bad">{t('Expired')}</Tag>
                  ),
              },
              {
                key: 'name',
                label: t('Token'),
                sort: (tk) => tk.name.toLowerCase(),
                render: (tk) => (
                  <div>
                    <strong>{tk.name}</strong>
                    <div className="muted small mono">{tk.token_prefix}…</div>
                  </div>
                ),
              },
              {
                key: 'scope',
                label: t('Project / Scope'),
                render: (tk) => (
                  <div>
                    <span>{tk.project_name}</span>
                    <div className="muted small mono">
                      {tk.environment_slug || '*'} · {tk.path || '/'}
                    </div>
                  </div>
                ),
              },
              {
                key: 'cidrs',
                label: t('Allowed CIDRs'),
                render: (tk) => <code className="small">{tk.allowed_cidrs || t('Any')}</code>,
              },
              {
                key: 'last_used',
                label: t('Last Used'),
                sort: (tk) => tk.last_used_at || '',
                render: (tk) =>
                  tk.last_used_at ? (
                    <span className="muted small" title={dateTime(tk.last_used_at)}>{ago(tk.last_used_at)}</span>
                  ) : (
                    <span className="muted small">{t('Never')}</span>
                  ),
              },
              {
                key: 'expires',
                label: t('Expires'),
                sort: (tk) => tk.expires_at || '',
                render: (tk) =>
                  tk.expires_at ? (
                    <span className="muted small" title={dateTime(tk.expires_at)}>{ago(tk.expires_at)}</span>
                  ) : (
                    <span className="muted small">{t('Never')}</span>
                  ),
              },
              {
                key: 'actions',
                label: '',
                width: 130,
                render: (tk) => (
                  <div style={{ display: 'flex', gap: 4, justifyContent: 'flex-end' }}>
                    <button
                      type="button"
                      className="btn btn-xs btn-ghost"
                      disabled={busyId === tk.id}
                      onClick={(e) => {
                        e.stopPropagation()
                        revokeToken(tk)
                      }}
                    >
                      <Trash2 size={12} /> {t('Revoke')}
                    </button>
                    <button
                      type="button"
                      className="btn btn-xs btn-ghost"
                      onClick={(e) => {
                        e.stopPropagation()
                        go('projects', tk.project_id, 'tokens')
                      }}
                    >
                      <ArrowUpRight size={12} />
                    </button>
                  </div>
                ),
              },
            ]}
          />
        )}
      </div>
    </div>
  )
}
