import { useState, useEffect } from 'react'
import { FolderKey, ChevronRight, Settings2 } from 'lucide-react'
import { t } from '../i18n'
import { enc, type Project, type Environment, type SecretList } from '../lib/api'
import { useResource } from '../lib/store'
import { go } from '../lib/router'
import { Spinner, Tabs, Tag } from '../ui/common'
import { openDialog } from '../ui/overlays'
import { ProjectListView } from './projects/ProjectListView'
import { ProjectModal } from './projects/ProjectModals'
import { SecretsTab } from './projects/SecretsTab'
import { TokensView } from './projects/TokensTab'
import { DynamicView } from './projects/DynamicTab'
import { RotationView } from './projects/RotationTab'
import { SitesView } from './projects/SitesTab'
import { PoliciesView } from './projects/PoliciesTab'
import { CredentialsListView } from './credentials/CredentialsListView'

export { ProjectModal } from './projects/ProjectModals'
export { ShareBundleModal } from './projects/ShareBundleModal'
export { parseEnvContent } from '../lib/env'

type ProjectTab = 'secrets' | 'credentials' | 'tokens' | 'dynamic' | 'rotation' | 'sites' | 'policies'

const PROJECT_TABS: readonly ProjectTab[] = ['secrets', 'credentials', 'tokens', 'dynamic', 'rotation', 'sites', 'policies']

function resolveProjectTab(raw?: string): ProjectTab {
  return PROJECT_TABS.includes(raw as ProjectTab) ? (raw as ProjectTab) : 'secrets'
}

export function Projects({ id, initialTab }: { id?: string; initialTab?: string }) {
  if (id) {
    return <ProjectDetail id={id} initialTab={initialTab} />
  }
  return <ProjectListView />
}

function ProjectDetail({ id, initialTab }: { id: string; initialTab?: string }) {
  const { data: project, error: pErr } = useResource<Project>(`/projects/${enc(id)}`)
  const { data: envs } = useResource<Environment[]>(`/projects/${enc(id)}/environments`)

  const [tab, setTab] = useState<ProjectTab>(() => resolveProjectTab(initialTab))
  useEffect(() => {
    setTab(resolveProjectTab(initialTab))
  }, [id, initialTab])
  const [activeEnv, setActiveEnv] = useState<string>('dev')
  const [revealAll, setRevealAll] = useState(false)

  const envSlug = envs && envs.length > 0 ? (envs.some((e) => e.slug === activeEnv) ? activeEnv : envs[0].slug) : 'dev'

  const { data: secretsData, error: sErr, loading: sLoading } = useResource<SecretList>(
    `/projects/${enc(id)}/environments/${enc(envSlug)}/secrets${revealAll ? '?reveal=1' : ''}`
  )

  if (pErr) {
    return (
      <div className="page">
        <div className="alert alert-bad">{pErr.message}</div>
        <button className="btn btn-sm" onClick={() => go('projects')}>← {t('Back to projects')}</button>
      </div>
    )
  }

  return (
    <div className="page">
      <div className="page-head" style={{ marginBottom: 12 }}>
        <div>
          <div className="vault-breadcrumb">
            <a href="#projects" onClick={(e) => { e.preventDefault(); go('projects'); }}>
              <FolderKey size={13} />
              <span>{t('Projects')}</span>
            </a>
            <ChevronRight size={13} className="breadcrumb-sep" />
            <span className="breadcrumb-cur">{project?.name || t('Project Vault')}</span>
          </div>
          <div className="page-title">
            <FolderKey size={22} style={{ color: 'var(--accent)' }} />
            <h1>{project?.name || t('Project Vault')}</h1>
            {project?.slug && <Tag mono tone="accent">{project.slug}</Tag>}
            {sLoading && <Spinner />}
          </div>
          {project?.description && <p className="muted small" style={{ marginTop: 4 }}>{project.description}</p>}
        </div>

        <div className="page-actions">
          <button
            className="btn btn-sm btn-ghost"
            onClick={() => openDialog((c) => <ProjectModal initial={project} onClose={c} />)}
            title={t('Edit Project Settings')}
          >
            <Settings2 size={14} /> {t('Project Settings')}
          </button>
        </div>
      </div>

      <div style={{ borderBottom: '1px solid var(--border)', marginBottom: 16 }}>
        <Tabs
          tabs={[
            { id: 'secrets', label: t('Secrets') },
            { id: 'credentials', label: t('Credentials') },
            { id: 'tokens', label: t('Service Tokens') },
            { id: 'dynamic', label: t('Dynamic Secrets') },
            { id: 'rotation', label: t('Auto-Rotation') },
            { id: 'sites', label: t('Network Sites') },
            { id: 'policies', label: t('Access & Policies') },
          ]}
          active={tab}
          onChange={(next) => {
            const resolved = resolveProjectTab(next)
            setTab(resolved)
            go('projects', id, resolved === 'secrets' ? undefined : resolved)
          }}
        />
      </div>

      {tab === 'credentials' ? (
        <div className="page-body">
          <CredentialsListView projectId={id} envSlug={envSlug} />
        </div>
      ) : tab === 'tokens' ? (
        <TokensView projectId={id} envs={envs || []} />
      ) : tab === 'dynamic' ? (
        <DynamicView projectId={id} envSlug={envSlug} envs={envs || []} />
      ) : tab === 'rotation' ? (
        <RotationView projectId={id} envSlug={envSlug} />
      ) : tab === 'sites' ? (
        <SitesView projectId={id} />
      ) : tab === 'policies' ? (
        <PoliciesView projectId={id} envs={envs || []} />
      ) : (
        <SecretsTab
          projectId={id}
          envSlug={envSlug}
          envs={envs || []}
          onSelectEnv={setActiveEnv}
          revealAll={revealAll}
          onToggleRevealAll={() => setRevealAll((v) => !v)}
          secretsData={secretsData ?? undefined}
          sErr={sErr}
        />
      )}
    </div>
  )
}
