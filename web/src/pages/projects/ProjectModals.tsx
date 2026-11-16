import { useState } from 'react'
import { t } from '../../i18n'
import { api, enc, type Project } from '../../lib/api'
import { invalidate } from '../../lib/store'
import { go } from '../../lib/router'
import { Spinner } from '../../ui/common'
import { Modal, confirm, toast } from '../../ui/overlays'
import { Field } from '../../ui/Field'

export function ProjectModal({ initial, onClose }: { initial?: Project; onClose: () => void }) {
  const [name, setName] = useState(initial?.name ?? '')
  const [slug, setSlug] = useState(initial?.slug ?? '')
  const [description, setDescription] = useState(initial?.description ?? '')
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    try {
      if (initial) {
        await api.patch(`/projects/${enc(initial.id)}`, { name, description })
        toast.ok(t('Project updated'))
      } else {
        await api.post('/projects', { name, slug: slug || undefined, description })
        toast.ok(t('Project created with dev, staging, prod environments'))
      }
      invalidate('/projects')
      onClose()
    } catch (err) {
      toast.err(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal title={initial ? t('Edit Project') : t('New Project')} onClose={onClose}>
      <form onSubmit={submit}>
        <Field required label={t('Name')}>
          <input required autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Backend API" />
        </Field>
        {!initial && (
          <Field optional label={t('Slug')} help={t('Unique URL identifier (lowercase letters, digits, hyphens). Leave blank to auto-slugify.')}>
            <input value={slug} onChange={(e) => setSlug(e.target.value)} placeholder="e.g. backend-api" />
          </Field>
        )}
        <Field optional label={t('Description')}>
          <textarea rows={3} value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Optional project description..." />
        </Field>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
          <button type="button" className="btn btn-ghost" onClick={onClose}>{t('Cancel')}</button>
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? <Spinner /> : initial ? t('Save') : t('Create Project')}
          </button>
        </div>
      </form>
    </Modal>
  )
}

export function EnvironmentModal({ projectId, onClose }: { projectId: string; onClose: () => void }) {
  const [name, setName] = useState('')
  const [slug, setSlug] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    try {
      await api.post(`/projects/${enc(projectId)}/environments`, {
        name,
        slug: slug || undefined,
      })
      toast.ok(t('Environment created'))
      invalidate('/projects')
      onClose()
    } catch (err) {
      toast.err(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal title={t('Add Environment')} onClose={onClose}>
      <form onSubmit={submit}>
        <Field required label={t('Name')}>
          <input required autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Preview or Testing" />
        </Field>
        <Field optional label={t('Slug')} help={t('Identifier for CLI and API (e.g. preview, test)')}>
          <input value={slug} onChange={(e) => setSlug(e.target.value)} placeholder="e.g. preview" />
        </Field>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
          <button type="button" className="btn btn-ghost" onClick={onClose}>{t('Cancel')}</button>
          <button type="submit" className="btn btn-primary" disabled={busy}>
            {busy ? <Spinner /> : t('Create Environment')}
          </button>
        </div>
      </form>
    </Modal>
  )
}

export async function removeProject(p: Project) {
  if (
    !(await confirm({
      title: t('Delete {0}?', p.name),
      body: t('This will permanently delete the project, all its environments, and all encrypted secrets.'),
      danger: true,
      confirm: t('Delete Project'),
    }))
  ) {
    return
  }
  api.del(`/projects/${enc(p.id)}`).then(() => {
    invalidate('/projects')
    go('projects')
    toast.ok(t('Project deleted'))
  }, toast.err)
}
