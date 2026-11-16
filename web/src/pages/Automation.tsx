import { t } from '../i18n'
import { useMemo, useState } from 'react'
import { ArrowUpRight, Database, Play, RefreshCw, Search, Trash2, X } from 'lucide-react'
import { api, enc } from '../lib/api'
import type { RotationRunResponse } from '../lib/api'
import { isLeaseActive, useFleetInventory } from '../lib/fleet'
import type { FleetLease, FleetRotation } from '../lib/fleet'
import { ago, dateTime } from '../lib/format'
import { go } from '../lib/router'
import { DataTable, Empty, Spinner, Tabs, Tag } from '../ui/common'
import { confirm, toast } from '../ui/overlays'

function formatTTL(seconds: number): string {
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h`
  return `${Math.round(seconds / 86400)}d`
}

export function Automation() {
  const fleet = useFleetInventory({ providers: true, leases: true, rotations: true })
  const [tab, setTab] = useState<'leases' | 'providers' | 'rotation'>('leases')
  const [q, setQ] = useState('')
  const [busyId, setBusyId] = useState<string | null>(null)

  const words = useMemo(() => q.toLowerCase().split(/\s+/).filter(Boolean), [q])

  const leases = useMemo(
    () =>
      fleet.leases.filter((l) =>
        words.every((w) =>
          `${l.username} ${l.provider_name} ${l.engine} ${l.issued_to} ${l.project_name} ${l.environment_slug}`.toLowerCase().includes(w),
        ),
      ),
    [fleet.leases, words],
  )

  const providers = useMemo(
    () =>
      fleet.providers.filter((p) =>
        words.every((w) => `${p.name} ${p.engine} ${p.project_name} ${p.environment_slug}`.toLowerCase().includes(w)),
      ),
    [fleet.providers, words],
  )

  const rotations = useMemo(
    () =>
      fleet.rotations.filter((r) =>
        words.every((w) =>
          `${r.secret_key || ''} ${r.secret_path || ''} ${r.generator_type} ${r.status} ${r.project_name} ${r.environment_slug}`
            .toLowerCase()
            .includes(w),
        ),
      ),
    [fleet.rotations, words],
  )

  const revokeLease = async (lease: FleetLease) => {
    const ok = await confirm({
      title: t('Revoke dynamic lease?'),
      body: t('Drops temporary credential {0} from {1} immediately.', lease.username, lease.provider_name),
      danger: true,
      confirm: t('Revoke'),
    })
    if (!ok) return
    setBusyId(lease.id)
    try {
      await api.del(
        `/projects/${enc(lease.project_id)}/environments/${enc(lease.environment_slug)}/dynamic/${enc(lease.provider_id)}/leases/${enc(lease.id)}`,
      )
      toast.ok(t('Lease revoked'))
      fleet.refresh()
    } catch (err: any) {
      toast.err(err)
    } finally {
      setBusyId(null)
    }
  }

  const runRotation = async (rot: FleetRotation) => {
    setBusyId(rot.id)
    try {
      const res = await api.post<RotationRunResponse>(
        `/projects/${enc(rot.project_id)}/environments/${enc(rot.environment_slug)}/secrets/${enc(rot.secret_id)}/rotation/run`,
        {},
      )
      if (res.success) {
        toast.ok(res.message || t('Secret rotated cleanly'))
      } else {
        toast.err(res.message || t('Rotation completed'))
      }
      fleet.refresh()
    } catch (err: any) {
      toast.err(err)
    } finally {
      setBusyId(null)
    }
  }

  const activeLeasesCount = fleet.leases.filter(isLeaseActive).length

  return (
    <div className="page">
      <div className="page-head">
        <div className="page-title">
          <RefreshCw size={20} />
          <h1>{t('Dynamic & Rotation')}</h1>
          {fleet.loading && <Spinner />}
        </div>
        <div className="page-actions">
          <div className="search-input">
            <Search size={14} />
            <input placeholder={t('Filter…')} value={q} onChange={(e) => setQ(e.target.value)} />
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

      <div style={{ borderBottom: '1px solid var(--border)', marginBottom: 16 }}>
        <Tabs
          tabs={[
            { id: 'leases', label: t('Dynamic Leases'), count: activeLeasesCount },
            { id: 'providers', label: t('Dynamic Providers'), count: fleet.providers.length },
            { id: 'rotation', label: t('Rotation Policies'), count: fleet.rotations.length },
          ]}
          active={tab}
          onChange={(next) => setTab(next as any)}
        />
      </div>

      <div className="page-body">
        {fleet.error && <div className="alert alert-bad" style={{ marginBottom: 14 }}>{fleet.error.message}</div>}

        {tab === 'leases' && (
          leases.length === 0 && !fleet.loading ? (
            <Empty
              icon={<Database size={30} />}
              title={t('No dynamic leases issued')}
              action={
                fleet.projects[0] ? (
                  <button className="btn btn-sm btn-primary" onClick={() => go('projects', fleet.projects[0].id, 'dynamic')}>
                    {t('Open Dynamic Secrets')}
                  </button>
                ) : undefined
              }
            >
              {t('Ephemeral credentials issued by PostgreSQL, MySQL, Redis, or PAM providers appear here with live expiration and revocation.')}
            </Empty>
          ) : (
            <DataTable
              rows={leases}
              rowKey={(l) => l.id}
              onOpen={(l) => go('projects', l.project_id, 'dynamic')}
              columns={[
                {
                  key: 'state',
                  label: t('Status'),
                  width: 110,
                  render: (l) =>
                    l.revoked_at ? (
                      <Tag tone="muted">{t('Revoked')}</Tag>
                    ) : isLeaseActive(l) ? (
                      <Tag tone="ok">{t('Active')}</Tag>
                    ) : (
                      <Tag tone="muted">{t('Expired')}</Tag>
                    ),
                },
                {
                  key: 'user',
                  label: t('Username'),
                  render: (l) => (
                    <div>
                      <code className="small">{l.username}</code>
                      <div className="muted small">{l.issued_to}</div>
                    </div>
                  ),
                },
                {
                  key: 'provider',
                  label: t('Provider'),
                  render: (l) => (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <strong>{l.provider_name}</strong>
                      <Tag mono>{l.engine}</Tag>
                    </div>
                  ),
                },
                {
                  key: 'project',
                  label: t('Project / Env'),
                  render: (l) => (
                    <div>
                      <span>{l.project_name}</span>
                      <div className="muted small mono">{l.environment_slug}</div>
                    </div>
                  ),
                },
                {
                  key: 'expires',
                  label: t('Expires'),
                  sort: (l) => l.expires_at,
                  render: (l) => <span className="muted small" title={dateTime(l.expires_at)}>{dateTime(l.expires_at)}</span>,
                },
                {
                  key: 'actions',
                  label: '',
                  width: 110,
                  render: (l) =>
                    isLeaseActive(l) ? (
                      <button
                        type="button"
                        className="btn btn-xs btn-ghost"
                        disabled={busyId === l.id}
                        onClick={(e) => {
                          e.stopPropagation()
                          revokeLease(l)
                        }}
                      >
                        <Trash2 size={12} /> {t('Revoke')}
                      </button>
                    ) : (
                      <button
                        type="button"
                        className="btn btn-xs btn-ghost"
                        onClick={(e) => {
                          e.stopPropagation()
                          go('projects', l.project_id, 'dynamic')
                        }}
                      >
                        {t('Open')} <ArrowUpRight size={12} />
                      </button>
                    ),
                },
              ]}
            />
          )
        )}

        {tab === 'providers' && (
          providers.length === 0 && !fleet.loading ? (
            <Empty
              icon={<Database size={30} />}
              title={t('No dynamic secret providers configured')}
              action={
                fleet.projects[0] ? (
                  <button className="btn btn-sm btn-primary" onClick={() => go('projects', fleet.projects[0].id, 'dynamic')}>
                    {t('Configure in a Project')}
                  </button>
                ) : undefined
              }
            >
              {t('Configure PostgreSQL, MySQL, Redis, or PAM providers inside a project to mint short-lived credentials on demand.')}
            </Empty>
          ) : (
            <DataTable
              rows={providers}
              rowKey={(p) => p.id}
              onOpen={(p) => go('projects', p.project_id, 'dynamic')}
              columns={[
                {
                  key: 'name',
                  label: t('Provider'),
                  sort: (p) => p.name.toLowerCase(),
                  render: (p) => (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <strong>{p.name}</strong>
                      <Tag mono>{p.engine}</Tag>
                    </div>
                  ),
                },
                {
                  key: 'project',
                  label: t('Project / Env'),
                  render: (p) => (
                    <div>
                      <span>{p.project_name}</span>
                      <div className="muted small mono">{p.environment_slug}</div>
                    </div>
                  ),
                },
                {
                  key: 'ttl',
                  label: t('Default / Max TTL'),
                  render: (p) => <span className="mono small">{formatTTL(p.default_ttl_seconds)} / {formatTTL(p.max_ttl_seconds)}</span>,
                },
                {
                  key: 'route',
                  label: t('Connectivity'),
                  render: (p) => (p.site_id ? <Tag tone="accent">{t('Reverse Tunnel')}</Tag> : <Tag tone="muted">{t('Direct')}</Tag>),
                },
                {
                  key: 'open',
                  label: '',
                  width: 90,
                  render: (p) => (
                    <button
                      type="button"
                      className="btn btn-xs btn-ghost"
                      onClick={(e) => {
                        e.stopPropagation()
                        go('projects', p.project_id, 'dynamic')
                      }}
                    >
                      {t('Open')} <ArrowUpRight size={12} />
                    </button>
                  ),
                },
              ]}
            />
          )
        )}

        {tab === 'rotation' && (
          rotations.length === 0 && !fleet.loading ? (
            <Empty
              icon={<RefreshCw size={30} />}
              title={t('No auto-rotation policies configured')}
              action={
                fleet.projects[0] ? (
                  <button className="btn btn-sm btn-primary" onClick={() => go('projects', fleet.projects[0].id, 'rotation')}>
                    {t('Open Auto-Rotation')}
                  </button>
                ) : undefined
              }
            >
              {t('Schedule automated rotation intervals and verification probes directly on secrets inside any project.')}
            </Empty>
          ) : (
            <DataTable
              rows={rotations}
              rowKey={(r) => r.id}
              onOpen={(r) => go('projects', r.project_id, 'rotation')}
              columns={[
                {
                  key: 'secret',
                  label: t('Secret'),
                  render: (r) => (
                    <div>
                      <strong className="mono">{r.secret_key || r.secret_id.slice(0, 8)}</strong>
                      {r.secret_path && <div className="muted small mono">{r.secret_path}</div>}
                    </div>
                  ),
                },
                {
                  key: 'project',
                  label: t('Project / Env'),
                  render: (r) => (
                    <div>
                      <span>{r.project_name}</span>
                      <div className="muted small mono">{r.environment_slug}</div>
                    </div>
                  ),
                },
                {
                  key: 'status',
                  label: t('Status'),
                  render: (r) =>
                    r.last_error || r.status === 'error' ? (
                      <Tag tone="bad" title={r.last_error}>{r.status || t('Error')}</Tag>
                    ) : (
                      <Tag tone="ok">{r.status || t('Active')}</Tag>
                    ),
                },
                {
                  key: 'interval',
                  label: t('Every'),
                  render: (r) => <span className="mono small">{formatTTL(r.interval_seconds)} · {r.generator_type}</span>,
                },
                {
                  key: 'next',
                  label: t('Next Rotation'),
                  sort: (r) => r.next_rotation_at,
                  render: (r) => <span className="muted small" title={dateTime(r.next_rotation_at)}>{dateTime(r.next_rotation_at)}</span>,
                },
                {
                  key: 'last',
                  label: t('Last Run'),
                  render: (r) =>
                    r.last_rotated_at ? (
                      <span className="muted small" title={dateTime(r.last_rotated_at)}>{ago(r.last_rotated_at)}</span>
                    ) : (
                      <span className="muted small">—</span>
                    ),
                },
                {
                  key: 'run',
                  label: '',
                  width: 110,
                  render: (r) => (
                    <button
                      type="button"
                      className="btn btn-xs btn-ghost"
                      disabled={busyId === r.id}
                      onClick={(e) => {
                        e.stopPropagation()
                        runRotation(r)
                      }}
                    >
                      <Play size={12} /> {t('Run Now')}
                    </button>
                  ),
                },
              ]}
            />
          )
        )}
      </div>
    </div>
  )
}
