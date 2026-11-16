import { useMemo, useState } from 'react'
import { FolderKey, Plus, Search, X, Trash2, Pencil } from 'lucide-react'
import { t } from '../../i18n'
import type { Project, ProjectList } from '../../lib/api'
import { useResource } from '../../lib/store'
import { go } from '../../lib/router'
import { ago, dateTime } from '../../lib/format'
import type { MenuEntry } from '../../ui/ContextMenu'
import { DataTable, Empty, Spinner } from '../../ui/common'
import { openDialog } from '../../ui/overlays'
import { ProjectModal, removeProject } from './ProjectModals'

export function ProjectListView() {
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
