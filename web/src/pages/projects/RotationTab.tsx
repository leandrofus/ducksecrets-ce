import { useMemo, useState, useEffect } from 'react'
import {
  Search,
  X,
  Trash2,
  Pencil,
  RefreshCw,
  Clock,
  Activity,
  Play,
  AlertCircle,
  Sparkles,
  ShieldCheck,
} from 'lucide-react'
import { t } from '../../i18n'
import { api, enc, type Secret, type RotationPolicy, type RotationRunResponse } from '../../lib/api'
import { can, getMe } from '../../lib/session'
import { invalidate, useResource } from '../../lib/store'
import { useMenu, type MenuEntry } from '../../ui/ContextMenu'
import { Empty, Spinner, Tag } from '../../ui/common'
import { Modal, confirm, openDialog, toast } from '../../ui/overlays'
import { Field } from '../../ui/Field'
import {
  HttpProbeConfigForm,
  TcpProbeConfigForm,
  ScriptProbeConfigForm,
} from '../../components/config'

export function RotationView({ projectId, envSlug }: { projectId: string; envSlug: string }) {
  const { data: policies, loading, error } = useResource<RotationPolicy[]>(
    `/projects/${enc(projectId)}/environments/${enc(envSlug)}/rotation`
  )
  const menu = useMenu()

  const runRotation = (secretId: string, secretKey: string) => {
    toast.ok(t('Executing rotation and health verification probe…'))
    api
      .post<RotationRunResponse>(`/projects/${enc(projectId)}/environments/${enc(envSlug)}/secrets/${enc(secretId)}/rotation/run`, {})
      .then((res) => {
        invalidate('/projects')
        if (res.success) {
          toast.ok(t('{0}: {1}', secretKey, res.message))
        } else {
          toast.err(t('{0}: {1}', secretKey, res.message || t('Rotation failed')))
        }
      })
      .catch(toast.err)
  }

  const deletePolicy = async (secretId: string, secretKey: string) => {
    if (
      !(await confirm({
        title: t('Remove rotation policy for {0}?', secretKey),
        body: t('Automated rotation will stop for this secret.'),
        danger: true,
        confirm: t('Remove Policy'),
      }))
    ) {
      return
    }
    api.del(`/projects/${enc(projectId)}/environments/${enc(envSlug)}/secrets/${enc(secretId)}/rotation`).then(() => {
      invalidate('/projects')
      toast.ok(t('Rotation policy removed'))
    }, toast.err)
  }

  const policyActions = (pol: RotationPolicy): MenuEntry[] => [
    { header: pol.secret_key || t('Rotation Policy') },
    {
      label: t('Edit Policy'),
      icon: <Pencil size={14} />,
      onClick: () =>
        openDialog((c) => (
          <RotationPolicyModal
            projectId={projectId}
            envSlug={envSlug}
            secret={{ id: pol.secret_id, key: pol.secret_key || pol.secret_id, path: pol.secret_path || '/' } as Secret}
            existingPolicy={pol}
            onClose={c}
          />
        )),
    },
    { label: t('Run Rotation Now'), icon: <Play size={14} />, onClick: () => runRotation(pol.secret_id, pol.secret_key || '') },
    'sep',
    { label: t('Remove Policy'), icon: <Trash2 size={14} />, danger: true, onClick: () => deletePolicy(pol.secret_id, pol.secret_key || '') },
  ]

  const [q, setQ] = useState('')
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'error'>('all')

  const filteredPolicies = useMemo(() => {
    const words = q.toLowerCase().split(/\s+/).filter(Boolean)
    return (policies || []).filter((pol) => {
      if (statusFilter === 'active' && pol.status === 'error') return false
      if (statusFilter === 'error' && pol.status !== 'error') return false
      return words.every((w) => `${pol.secret_key || ''} ${pol.secret_path || ''} ${pol.generator_type || ''} ${pol.status || ''}`.toLowerCase().includes(w))
    })
  }, [policies, q, statusFilter])

  if (loading) return <div className="center" style={{ padding: 24 }}><Spinner /></div>
  if (error) return <div className="alert alert-bad">{error.message}</div>

  return (
    <div>
      <div className="vault-toolbar">
        <div className="vault-toolbar-left">
          <div className="search">
            <Search size={14} />
            <input placeholder={t('Filter rotation policies…')} value={q} onChange={(e) => setQ(e.currentTarget.value)} />
            {q && <button className="icon-btn" onClick={() => setQ('')}><X size={13} /></button>}
          </div>

          <select
            className="vault-select"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value as 'all' | 'active' | 'error')}
            title={t('Filter by health status')}
          >
            <option value="all">{t('All Statuses')}</option>
            <option value="active">{t('Healthy / Active')}</option>
            <option value="error">{t('Error / Attention')}</option>
          </select>
        </div>

        <div className="vault-toolbar-right">
          <Tag tone="accent">
            <RefreshCw size={12} style={{ marginRight: 4 }} />
            {policies?.length || 0} {t('Active Policies')}
          </Tag>
        </div>
      </div>

      {!policies || policies.length === 0 ? (
        <Empty
          icon={<RefreshCw size={32} />}
          title={t('No rotation policies active')}
        >
          <p>{t('Configure auto-rotation directly from any secret in the Secrets tab by clicking Auto-Rotation…')}</p>
        </Empty>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: 16 }}>
          {filteredPolicies.map((pol) => (
            <div key={pol.id} className="card" onContextMenu={menu(() => policyActions(pol))} style={{ padding: 16, borderRadius: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                <div>
                  <strong style={{ fontSize: 15 }}>{pol.secret_key || t('Secret')}</strong>
                  {pol.secret_path && <span className="muted small" style={{ marginLeft: 6 }}>{pol.secret_path}</span>}
                </div>
                <Tag tone={pol.status === 'error' ? 'bad' : 'good'}>
                  {pol.status.toUpperCase()}
                </Tag>
              </div>

              <div style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 12 }}>
                <div>{t('Interval: every {0} days', Math.round(pol.interval_seconds / 86400))}</div>
                <div>{t('Generator: {0}', pol.generator_type)}</div>
                <div>{t('Health Probe: {0}', pol.verifier_type)}</div>
                <div style={{ marginTop: 4 }}>
                  <Clock size={12} style={{ display: 'inline', marginRight: 4, verticalAlign: 'text-bottom' }} />
                  {t('Next rotation: {0}', new Date(pol.next_rotation_at).toLocaleDateString())}
                </div>
              </div>

              {pol.last_error && (
                <div className="alert alert-bad" style={{ fontSize: 12, padding: 8, marginBottom: 12 }}>
                  <AlertCircle size={13} style={{ display: 'inline', marginRight: 4, verticalAlign: 'text-bottom' }} />
                  {pol.last_error}
                </div>
              )}

              <div style={{ display: 'flex', gap: 8, borderTop: '1px solid var(--border)', paddingTop: 10 }}>
                <button
                  className="btn btn-sm btn-primary"
                  onClick={() => runRotation(pol.secret_id, pol.secret_key || pol.secret_id)}
                >
                  <Play size={13} /> {t('Rotate Now')}
                </button>
                <button
                  className="btn btn-sm btn-ghost"
                  onClick={() =>
                    openDialog((c) => (
                      <RotationPolicyModal
                        projectId={projectId}
                        envSlug={envSlug}
                        secret={{ id: pol.secret_id, key: pol.secret_key || pol.secret_id, path: pol.secret_path || '/' } as Secret}
                        existingPolicy={pol}
                        onClose={c}
                      />
                    ))
                  }
                >
                  <Pencil size={13} /> {t('Edit')}
                </button>
                <button
                  className="icon-btn tone-bad"
                  style={{ marginLeft: 'auto' }}
                  onClick={() => deletePolicy(pol.secret_id, pol.secret_key || pol.secret_id)}
                  title={t('Remove Policy')}
                >
                  <Trash2 size={14} />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export function RotationPolicyModal({
  projectId,
  envSlug,
  secret,
  existingPolicy,
  onClose,
}: {
  projectId: string
  envSlug: string
  secret: Secret
  existingPolicy?: RotationPolicy
  onClose: () => void
}) {
  const [intervalDays, setIntervalDays] = useState(
    existingPolicy ? Math.max(1, Math.round(existingPolicy.interval_seconds / 86400)) : 30
  )
  const [generatorType, setGeneratorType] = useState(existingPolicy?.generator_type || 'password')
  const [passwordLength, setPasswordLength] = useState(() => {
    if (existingPolicy?.generator_config) {
      try {
        const c = JSON.parse(existingPolicy.generator_config)
        if (c.length) return Number(c.length)
      } catch {}
    }
    return 32
  })
  const [valueTemplate, setValueTemplate] = useState(() => {
    if (existingPolicy?.generator_config) {
      try {
        const c = JSON.parse(existingPolicy.generator_config)
        if (c.template) return String(c.template)
      } catch {}
    }
    return ''
  })
  const [verifierType, setVerifierType] = useState(existingPolicy?.verifier_type || 'none')
  const [verifierConfig, setVerifierConfig] = useState(existingPolicy?.verifier_config || '')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (existingPolicy) return
    api
      .get<RotationPolicy>(`/projects/${enc(projectId)}/environments/${enc(envSlug)}/secrets/${enc(secret.id)}/rotation`)
      .then((pol) => {
        if (!pol) return
        setIntervalDays(Math.max(1, Math.round(pol.interval_seconds / 86400)))
        setGeneratorType(pol.generator_type)
        setVerifierType(pol.verifier_type)
        setVerifierConfig(pol.verifier_config || '')
        if (pol.generator_config) {
          try {
            const c = JSON.parse(pol.generator_config)
            if (c.length) setPasswordLength(Number(c.length))
            if (c.template) setValueTemplate(String(c.template))
          } catch {}
        }
      })
      .catch(() => {})
  }, [projectId, envSlug, secret.id, existingPolicy])

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    const genConfigObj: Record<string, unknown> = {}
    if (generatorType === 'password') {
      genConfigObj.length = Number(passwordLength) || 32
    }
    if (valueTemplate.trim()) {
      genConfigObj.template = valueTemplate.trim()
    }
    const genConfig = JSON.stringify(genConfigObj)
    api
      .post(`/projects/${enc(projectId)}/environments/${enc(envSlug)}/secrets/${enc(secret.id)}/rotation`, {
        interval_seconds: intervalDays * 86400,
        generator_type: generatorType,
        generator_config: genConfig,
        verifier_type: verifierType,
        verifier_config: verifierConfig || '{}',
      })
      .then(() => {
        invalidate('/projects')
        toast.ok(t('Rotation policy saved for {0}', secret.key))
        onClose()
      })
      .catch(toast.err)
      .finally(() => setBusy(false))
  }

  return (
    <Modal
      title={t('Configure Auto-Rotation — {0}', secret.key)}
      wide="xl"
      allowFullscreen
      onClose={onClose}
      footer={
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, width: '100%' }}>
          <button type="button" className="btn btn-ghost" onClick={onClose}>{t('Cancel')}</button>
          <button type="submit" form="rotation-form" className="btn btn-primary" disabled={busy}>
            {busy ? <Spinner /> : t('Save Policy')}
          </button>
        </div>
      }
    >
      <form id="rotation-form" onSubmit={submit}>
        <div className="modal-two-col">
          {/* Left Column: Generation Strategy & Scheduling */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <Field label={t('Rotation Frequency')} help={t('How often DuckSecrets generates a new credential')}>
              <select value={intervalDays} onChange={(e) => setIntervalDays(Number(e.target.value))}>
                <option value={1}>{t('Every 24 hours (1 day)')}</option>
                <option value={7}>{t('Every 7 days (Weekly)')}</option>
                <option value={30}>{t('Every 30 days (Monthly)')}</option>
                <option value={90}>{t('Every 90 days (Quarterly)')}</option>
                <option value={365}>{t('Every 365 days (Yearly)')}</option>
              </select>
            </Field>

            <Field label={t('Secret Generator Type')}>
              <select value={generatorType} onChange={(e) => setGeneratorType(e.target.value)}>
                <option value="password">{t('Random Strong Password (alphanumeric + symbols)')}</option>
                <option value="hex">{t('Hex Token (256-bit / 64 chars)')}</option>
                <option value="base64">{t('Base64 Token (256-bit)')}</option>
                <option value="jwt_secret">{t('JWT Signing Key (512-bit HMAC secret)')}</option>
                <option value="uuid">{t('UUIDv4')}</option>
                <option value="rsa">{t('RSA 2048-bit Private Key (PEM)')}</option>
              </select>
            </Field>

            {generatorType === 'password' && (
              <Field label={t('Password Length ({0} characters)', passwordLength)}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <input
                    type="range"
                    min={8}
                    max={128}
                    value={passwordLength}
                    onChange={(e) => setPasswordLength(Number(e.target.value))}
                    style={{ flex: 1 }}
                  />
                  <span className="mono" style={{ width: 40, textAlign: 'right', fontWeight: 600 }}>
                    {passwordLength}
                  </span>
                </div>
              </Field>
            )}

            <Field
              label={t('Value Template / Connection String (Optional)')}
              help={t('Use {{secret}} as placeholder for the generated password. Ideal for compound secrets like DATABASE_URL.')}
            >
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <input
                  className="mono"
                  placeholder="postgres://user:{{secret}}@host:port/dbname"
                  value={valueTemplate}
                  onChange={(e) => setValueTemplate(e.target.value)}
                />
                {secret.value && secret.value !== '••••••••' && (
                  <div style={{ display: 'flex', gap: 6 }}>
                    <button
                      type="button"
                      className="btn btn-xs btn-ghost"
                      onClick={() => {
                        const val = secret.raw_value || secret.value
                        try {
                          const u = new URL(val)
                          if (u.password) {
                            const templated = val.replace(`:${u.password}@`, ':{{secret}}@')
                            setValueTemplate(templated)
                            return
                          }
                        } catch {}
                        setValueTemplate(val.replace(/:[^:@]+@/, ':{{secret}}@'))
                      }}
                    >
                      <Sparkles size={12} />
                      {t('Convert current secret value to template')}
                    </button>
                  </div>
                )}
              </div>
            </Field>
          </div>

          {/* Right Column: Health Probe & Zero-Downtime Rollback Guard */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div className="surface-box">
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{ fontSize: 12, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Activity size={14} style={{ color: 'var(--accent)' }} />
                  {t('Health Verification Probe')}
                </span>
                <Tag tone={verifierType !== 'none' ? 'good' : 'accent'} mono style={{ fontSize: 10 }}>
                  {verifierType.toUpperCase()}
                </Tag>
              </div>
              <p className="muted small" style={{ margin: '0 0 8px 0', fontSize: 11, lineHeight: 1.4 }}>
                {t('A probe connects to the service immediately after rotation. If it fails, DuckSecrets auto-rollbacks to the previous version.')}
              </p>

              <Field label={t('Probe Type')}>
                <select value={verifierType} onChange={(e) => setVerifierType(e.target.value)}>
                  <option value="none">{t('None (Commit rotation immediately)')}</option>
                  <option value="http_probe">{t('HTTP Endpoint Probe (GET/POST test)')}</option>
                  <option value="tcp_probe">{t('TCP Port Probe')}</option>
                  <option value="script" disabled={!getMe()?.allow_scripts || !can('system.manage')}>
                    {t('Custom Verification Command')}
                    {!getMe()?.allow_scripts
                      ? ` (${t('disabled on server — needs DUCKSECRETS_ALLOW_SCRIPTS=1')})`
                      : !can('system.manage')
                        ? ` (${t('requires system.manage role')})`
                        : ''}
                  </option>
                </select>
              </Field>

              {verifierType === 'http_probe' && (
                <div style={{ marginTop: 8 }}>
                  <HttpProbeConfigForm value={verifierConfig} onChange={setVerifierConfig} />
                </div>
              )}

              {verifierType === 'tcp_probe' && (
                <div style={{ marginTop: 8 }}>
                  <TcpProbeConfigForm value={verifierConfig} onChange={setVerifierConfig} />
                </div>
              )}

              {verifierType === 'script' && (
                <div style={{ marginTop: 8 }}>
                  <ScriptProbeConfigForm value={verifierConfig} onChange={setVerifierConfig} />
                </div>
              )}
            </div>

            {/* Zero-Downtime Rollback Guarantee Card */}
            <div className="surface-box" style={{ fontSize: 11 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                <ShieldCheck size={14} className="tone-ok" />
                <strong>{t('Automatic Rollback')}</strong>
              </div>
              <p className="muted small" style={{ margin: 0, lineHeight: 1.4 }}>
                {t('If the health check fails, DuckSecrets restores the previous secret and logs the failure.')}
              </p>
            </div>
          </div>
        </div>
      </form>
    </Modal>
  )
}
