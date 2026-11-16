import { useState } from 'react'
import { Layers } from 'lucide-react'
import { t } from '../../i18n'
import {
  api,
  enc,
  type Credential,
  type Environment,
  type ProjectList,
  type SyncCredentialEnvResponse,
} from '../../lib/api'
import { invalidate, useResource } from '../../lib/store'
import { Field } from '../../ui/Field'
import { Spinner, Tag } from '../../ui/common'
import { Modal, toast } from '../../ui/overlays'

function sanitizePrefix(raw: string): string {
  return (
    raw
      .toUpperCase()
      .trim()
      .replace(/[^A-Z0-9_]+/g, '_')
      .replace(/^_+|_+$/g, '') || 'CRED'
  )
}

function previewKeysForKind(kind: string, prefix: string): string[] {
  const p = sanitizePrefix(prefix)
  switch (kind) {
    case 'ssh_key':
      return [`${p}_PRIVATE_KEY`, `${p}_PUBLIC_KEY`, `${p}_HOST`, `${p}_USER`, `${p}_FINGERPRINT`]
    case 'tls_cert':
      return [`${p}_CERT`, `${p}_PRIVATE_KEY`, `${p}_CA_CHAIN`]
    case 'oauth_api':
      return [`${p}_CLIENT_ID`, `${p}_CLIENT_SECRET`, `${p}_API_KEY`, `${p}_TOKEN_URL`, `${p}_ENDPOINT_URL`]
    case 'login':
      return [`${p}_USERNAME`, `${p}_PASSWORD`, `${p}_HOST`, `${p}_PORT`, `${p}_DATABASE`, `${p}_URL`]
    default:
      return [`${p}_VALUE`]
  }
}

export function SyncCredentialModal({
  credential,
  defaultProjectId,
  defaultEnvSlug,
  onClose,
}: {
  credential: Credential
  defaultProjectId?: string
  defaultEnvSlug?: string
  onClose: () => void
}) {
  const { data: projectList } = useResource<ProjectList>('/projects')
  const projects = projectList?.items || []

  const [projectId, setProjectId] = useState(
    credential.project_id || defaultProjectId || projects[0]?.id || '',
  )
  const { data: envs } = useResource<Environment[]>(
    projectId ? `/projects/${enc(projectId)}/environments` : null,
  )
  const [envSlug, setEnvSlug] = useState(
    credential.environment_slug || defaultEnvSlug || 'dev',
  )
  const [prefix, setPrefix] = useState(() => sanitizePrefix(credential.name))
  const [path, setPath] = useState('/')
  const [overwrite, setOverwrite] = useState(true)
  const [busy, setBusy] = useState(false)

  const effectiveEnv =
    envs && envs.length > 0
      ? envs.some((e) => e.slug === envSlug)
        ? envSlug
        : envs[0].slug
      : envSlug

  const expectedKeys = previewKeysForKind(credential.kind, prefix)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!projectId || !effectiveEnv || busy) return
    setBusy(true)
    try {
      const res = await api.post<SyncCredentialEnvResponse>(
        `/credentials/${enc(credential.id)}/sync-env`,
        {
          project_id: projectId,
          environment_slug: effectiveEnv,
          prefix: sanitizePrefix(prefix),
          path,
          overwrite,
        },
      )
      invalidate('/projects')
      toast.ok(
        t(
          'Synced {0} variables ({1} created, {2} updated)',
          res.keys.length,
          res.created,
          res.updated,
        ),
      )
      onClose()
    } catch (err) {
      toast.err(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      title={t('Project Credential to Environment Secrets')}
      onClose={onClose}
      footer={
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, width: '100%' }}>
          <button type="button" className="btn btn-ghost" onClick={onClose}>
            {t('Cancel')}
          </button>
          <button
            type="submit"
            form="sync-cred-form"
            className="btn btn-primary"
            disabled={busy || !projectId || !effectiveEnv}
          >
            {busy ? <Spinner /> : <><Layers size={14} /> {t('Sync Variables')}</>}
          </button>
        </div>
      }
    >
      <form id="sync-cred-form" onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <p className="muted small" style={{ margin: 0 }}>
          {t(
            'Projects the non-empty fields of "{0}" directly as encrypted environment variables so `ducksecrets run` and `ducksecrets export` can inject them automatically.',
            credential.name,
          )}
        </p>

        <div className="grid-2">
          <Field required label={t('Target Project')}>
            <select
              required
              value={projectId}
              onChange={(e) => setProjectId(e.target.value)}
            >
              <option value="" disabled>
                {t('Select a project…')}
              </option>
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.slug})
                </option>
              ))}
            </select>
          </Field>

          <Field required label={t('Target Environment')}>
            <select
              required
              value={effectiveEnv}
              onChange={(e) => setEnvSlug(e.target.value)}
              disabled={!projectId}
            >
              {(envs || []).map((env) => (
                <option key={env.id} value={env.slug}>
                  {env.name} ({env.slug})
                </option>
              ))}
            </select>
          </Field>
        </div>

        <div className="grid-2">
          <Field
            required
            label={t('Variable Prefix')}
            help={t('Prefix prepended to each generated secret key')}
          >
            <input
              required
              className="mono"
              value={prefix}
              onChange={(e) => setPrefix(e.target.value.toUpperCase())}
              placeholder="STRIPE_OAUTH"
            />
          </Field>

          <Field optional label={t('Secret Folder Path')} help={t('Default root path /')}>
            <input
              className="mono"
              value={path}
              onChange={(e) => setPath(e.target.value)}
              placeholder="/"
            />
          </Field>
        </div>

        <div className="surface-box" style={{ padding: 12 }}>
          <div className="muted small" style={{ marginBottom: 6 }}>
            {t('Variables to be created/updated (for non-empty fields):')}
          </div>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {expectedKeys.map((k) => (
              <Tag key={k} mono tone="accent">
                {k}
              </Tag>
            ))}
          </div>
        </div>

        <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }} className="small">
          <input
            type="checkbox"
            checked={overwrite}
            onChange={(e) => setOverwrite(e.target.checked)}
          />
          <span>{t('Overwrite existing variables with the same key (records a new secret version)')}</span>
        </label>
      </form>
    </Modal>
  )
}
