import { t } from '../i18n'
import {
  Activity,
  Database,
  DownloadCloud,
  Flame,
  FolderKey,
  KeyRound,
  LayoutDashboard,
  Network,
  Plus,
  RefreshCw,
  ScrollText,
  Shield,
  Terminal,
  Ticket,
} from 'lucide-react'
import type { AuditEvent, LicenseStatus, Page, TLSStatus, UpdateStatus } from '../lib/api'
import { can } from '../lib/session'
import { isLeaseActive, isTokenActive, useFleetInventory } from '../lib/fleet'
import { ago, dateTime } from '../lib/format'
import { go } from '../lib/router'
import { useResource } from '../lib/store'
import { Empty, Spinner, Tag } from '../ui/common'
import { openDialog } from '../ui/overlays'
import { ProjectModal } from './Projects'

export function Overview() {
  const isAdmin = can('system.manage')
  const canAudit = can('audit.read')
  const canWriteProjects = can('projects.write')

  const fleet = useFleetInventory({
    sites: true,
    tokens: true,
    providers: true,
    leases: true,
    rotations: true,
    secretsCount: true,
  })
  const { data: license } = useResource<LicenseStatus>('/system/license')
  const { data: tls } = useResource<TLSStatus>(isAdmin ? '/system/tls' : '')
  const { data: updateInfo } = useResource<UpdateStatus>(isAdmin ? '/system/update' : '')
  const { data: auditPage } = useResource<Page<AuditEvent>>(canAudit ? '/audit?page=1&per_page=6' : '')

  const onlineSites = fleet.sites.filter((s) => s.online).length
  const activeLeases = fleet.leases.filter(isLeaseActive).length
  const activeTokens = fleet.tokens.filter(isTokenActive).length
  const failingRotations = fleet.rotations.filter((r) => r.last_error || r.status === 'error').length
  const maxSitesText = license ? (license.max_sites < 0 ? t('Unlimited') : String(license.max_sites)) : '—'

  return (
    <div className="page">
      <div className="page-head">
        <div className="page-title">
          <LayoutDashboard size={20} />
          <h1>{t('Overview')}</h1>
          {fleet.loading && <Spinner />}
        </div>
        <div className="page-actions">
          <button className="btn btn-sm btn-ghost" onClick={() => go('cli')}>
            <Terminal size={14} /> {t('CLI & Setup')}
          </button>
          <button className="btn btn-sm btn-ghost" onClick={() => go('shares')}>
            <Flame size={14} /> {t('Share Secret')}
          </button>
          {canWriteProjects && (
            <button className="btn btn-sm btn-primary" onClick={() => openDialog((c) => <ProjectModal onClose={c} />)}>
              <Plus size={14} /> {t('New Project')}
            </button>
          )}
          <button className="icon-btn" title={t('Refresh')} onClick={fleet.refresh}>
            <RefreshCw size={15} />
          </button>
        </div>
      </div>

      <div className="page-body">
        {fleet.error && <div className="alert alert-bad" style={{ marginBottom: 14 }}>{fleet.error.message}</div>}

        <div className="kpis">
          <button className="kpi" onClick={() => go('projects')}>
            <span className="kpi-icon"><FolderKey size={16} /></span>
            <span className="kpi-label">{t('Projects')}</span>
            <span className="kpi-value">{fleet.projects.length}</span>
            <span className="kpi-sub">{t('{0} environments', fleet.envCount)}</span>
          </button>

          <button className="kpi" onClick={() => go('projects')}>
            <span className="kpi-icon"><KeyRound size={16} /></span>
            <span className="kpi-label">{t('Secrets')}</span>
            <span className="kpi-value">{fleet.secretCount}</span>
            <span className="kpi-sub">{t('Across accessible envs')}</span>
          </button>

          <button className="kpi" onClick={() => go('automation')}>
            <span className="kpi-icon"><Database size={16} /></span>
            <span className="kpi-label">{t('Dynamic Leases')}</span>
            <span className="kpi-value">
              {activeLeases} <small>/ {fleet.providers.length}</small>
            </span>
            <span className="kpi-sub">{t('{0} active · {1} providers', activeLeases, fleet.providers.length)}</span>
          </button>

          <button className={`kpi${failingRotations > 0 ? ' kpi-bad' : fleet.rotations.length > 0 ? ' kpi-ok' : ''}`} onClick={() => go('automation')}>
            <span className="kpi-icon"><RefreshCw size={16} /></span>
            <span className="kpi-label">{t('Auto-Rotation')}</span>
            <span className="kpi-value">{fleet.rotations.length}</span>
            <span className="kpi-sub">
              {failingRotations > 0 ? t('{0} failing', failingRotations) : t('All policies healthy')}
            </span>
          </button>

          <button className={`kpi${onlineSites > 0 ? ' kpi-ok' : ''}`} onClick={() => go('sites')}>
            <span className="kpi-icon"><Network size={16} /></span>
            <span className="kpi-label">{t('Network Sites')}</span>
            <span className="kpi-value">
              {onlineSites} <small>/ {fleet.sites.length}</small>
            </span>
            <span className="kpi-sub">
              {license ? t('Quota: {0} / {1}', license.used_sites, maxSitesText) : t('Reverse tunnel gateways')}
            </span>
          </button>

          <button className="kpi" onClick={() => go('tokens')}>
            <span className="kpi-icon"><Ticket size={16} /></span>
            <span className="kpi-label">{t('Service Tokens')}</span>
            <span className="kpi-value">{activeTokens}</span>
            <span className="kpi-sub">{t('{0} total provisioned', fleet.tokens.length)}</span>
          </button>
        </div>

        <div className="grid-2" style={{ alignItems: 'start', gap: 16 }}>
          <div style={{ border: '1px solid var(--border)', borderRadius: 10, padding: 16, background: 'var(--surface)' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
              <h3 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
                <FolderKey size={16} /> {t('Projects')}
              </h3>
              <button className="btn btn-sm btn-ghost" onClick={() => go('projects')}>
                {t('View all')}
              </button>
            </div>

            {fleet.projects.length === 0 ? (
              <Empty
                icon={<FolderKey size={26} />}
                title={t('No projects yet')}
                action={
                  canWriteProjects ? (
                    <button className="btn btn-sm btn-primary" onClick={() => openDialog((c) => <ProjectModal onClose={c} />)}>
                      <Plus size={14} /> {t('Create Project')}
                    </button>
                  ) : undefined
                }
              >
                {t('Create a project to organize secrets, dynamic providers, rotation policies, and tunnels.')}
              </Empty>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {fleet.projects.slice(0, 6).map((p) => {
                  const pSites = fleet.sites.filter((s) => s.project_id === p.id)
                  const pOnline = pSites.filter((s) => s.online).length
                  const pTokens = fleet.tokens.filter((tk) => tk.project_id === p.id && isTokenActive(tk)).length
                  return (
                    <div
                      key={p.id}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        gap: 10,
                        padding: '10px 12px',
                        border: '1px solid var(--border)',
                        borderRadius: 8,
                        background: 'var(--surface-2)',
                      }}
                    >
                      <button
                        type="button"
                        onClick={() => go('projects', p.id)}
                        style={{ border: 0, background: 'transparent', padding: 0, textAlign: 'left', cursor: 'pointer', flex: 1, minWidth: 0 }}
                      >
                        <strong style={{ display: 'block' }}>{p.name}</strong>
                        <span className="muted small mono">{p.slug}</span>
                      </button>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                        {pSites.length > 0 && (
                          <button type="button" className="btn btn-xs btn-ghost" onClick={() => go('projects', p.id, 'sites')}>
                            <Network size={12} /> {pOnline}/{pSites.length}
                          </button>
                        )}
                        {pTokens > 0 && (
                          <button type="button" className="btn btn-xs btn-ghost" onClick={() => go('projects', p.id, 'tokens')}>
                            <Ticket size={12} /> {pTokens}
                          </button>
                        )}
                        <button type="button" className="btn btn-xs" onClick={() => go('projects', p.id)}>
                          {t('Open')}
                        </button>
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div style={{ border: '1px solid var(--border)', borderRadius: 10, padding: 16, background: 'var(--surface)' }}>
              <h3 style={{ margin: '0 0 12px', display: 'flex', alignItems: 'center', gap: 8 }}>
                <Activity size={16} /> {t('Instance Status')}
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                  <span className="muted small" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <KeyRound size={14} /> {t('Edition')}
                  </span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <Tag tone={license?.edition === 'business' ? 'accent' : license?.edition === 'pro' ? 'ok' : 'muted'}>
                      {(license?.edition || 'community').toUpperCase()}
                    </Tag>
                    {isAdmin && (
                      <button className="btn btn-xs btn-ghost" onClick={() => go('license')}>
                        {t('Manage')}
                      </button>
                    )}
                  </div>
                </div>

                {isAdmin && (
                  <>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                      <span className="muted small" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <Shield size={14} /> {t('Transport Security')}
                      </span>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <Tag tone={tls?.tls_active ? 'ok' : 'muted'}>
                          {tls?.tls_active ? `HTTPS (${tls.mode})` : 'HTTP'}
                        </Tag>
                        <button className="btn btn-xs btn-ghost" onClick={() => go('tls')}>
                          {t('Configure')}
                        </button>
                      </div>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                      <span className="muted small" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <DownloadCloud size={14} /> {t('Version')}
                      </span>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <code className="small">{updateInfo?.current_version || '—'}</code>
                        {updateInfo?.update_available && (
                          <button className="btn btn-xs btn-primary" onClick={() => go('updates')}>
                            {updateInfo.latest_version}
                          </button>
                        )}
                      </div>
                    </div>
                  </>
                )}
              </div>
            </div>

            {canAudit && (
              <div style={{ border: '1px solid var(--border)', borderRadius: 10, padding: 16, background: 'var(--surface)' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                  <h3 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
                    <ScrollText size={16} /> {t('Recent Audit Activity')}
                  </h3>
                  <button className="btn btn-sm btn-ghost" onClick={() => go('audit')}>
                    {t('Audit log')}
                  </button>
                </div>
                {(auditPage?.items || []).length === 0 ? (
                  <p className="muted small" style={{ margin: 0 }}>{t('No audit events recorded yet.')}</p>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {(auditPage?.items || []).map((ev) => (
                      <div
                        key={ev.seq}
                        style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, fontSize: 12.5 }}
                      >
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
                          <Tag mono>{ev.action}</Tag>
                          <span className="muted ellipsis">{ev.actor_username || 'system'}</span>
                        </div>
                        <span className="muted small" title={dateTime(ev.created_at)}>
                          {ago(ev.created_at)}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
