import { useState } from 'react'
import { Sparkles, Activity, Database } from 'lucide-react'
import { t } from '../../i18n'
import { api, enc, type Site } from '../../lib/api'
import { invalidate, useResource } from '../../lib/store'
import { Spinner, Tag } from '../../ui/common'
import { Modal, toast } from '../../ui/overlays'
import { Field } from '../../ui/Field'
import { DynamicEngineConfigForm } from '../../components/config'

export function DynamicProviderModal({ projectId, envSlug, onClose }: { projectId: string; envSlug: string; onClose: () => void }) {
  const { data: sites } = useResource<Site[]>(`/projects/${enc(projectId)}/sites`)
  const [name, setName] = useState('')
  const [engine, setEngine] = useState('postgres')
  const [config, setConfig] = useState('{"connection_url": "postgres://user:password@localhost:5432/app"}')
  const [defaultTTL, setDefaultTTL] = useState(3600)
  const [maxTTL, setMaxTTL] = useState(86400)
  const [enforcedPort, setEnforcedPort] = useState(0)
  const [siteId, setSiteId] = useState('')
  const [roleTemplate, setRoleTemplate] = useState('')
  const [busy, setBusy] = useState(false)
  const [submitErr, setSubmitErr] = useState('')

  const handleEngineChange = (e: string) => {
    setSubmitErr('')
    setEngine(e)
    if (e === 'postgres') {
      setConfig('{"connection_url": "postgres://user:password@localhost:5432/app"}')
      setRoleTemplate('GRANT USAGE ON SCHEMA public TO {{name}}; GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};')
    } else if (e === 'mysql') {
      setConfig('{"dsn": "root:secret@tcp(127.0.0.1:3306)/app"}')
      setRoleTemplate('GRANT SELECT ON *.* TO {{name}};')
    } else if (e === 'redis') {
      setConfig('{"address": "127.0.0.1:6379", "password": "", "acl_rules": "~* +@read"}')
      setRoleTemplate('~* +@read')
    }
  }

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setSubmitErr('')
    api
      .post(`/projects/${enc(projectId)}/environments/${enc(envSlug)}/dynamic`, {
        name,
        engine,
        config,
        default_ttl_seconds: Number(defaultTTL),
        max_ttl_seconds: Number(maxTTL),
        role_template: roleTemplate,
        enforced_port: Number(enforcedPort) || 0,
        site_id: siteId || undefined,
      })
      .then(() => {
        invalidate('/projects')
        toast.ok(t('Dynamic provider created'))
        onClose()
      })
      .catch((err: any) => {
        setSubmitErr(err?.message || String(err))
        toast.err(err)
      })
      .finally(() => setBusy(false))
  }

  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null)
  const [testing, setTesting] = useState(false)

  const testConfig = () => {
    setTesting(true)
    setTestResult(null)
    api
      .post<{ success: boolean; message: string }>(`/projects/${enc(projectId)}/environments/${enc(envSlug)}/dynamic/test-config`, {
        engine,
        config,
      })
      .then((res) => {
        setTestResult(res)
        if (res.success) {
          toast.ok(res.message)
        } else {
          toast.err(res.message)
        }
      })
      .catch((err: any) => {
        setTestResult({ success: false, message: err.message || 'Connection failed' })
        toast.err(err)
      })
      .finally(() => setTesting(false))
  }

  const applyPreset = (template: string) => {
    setRoleTemplate(template)
    toast.ok(t('Preset applied to Role Template'))
  }

  return (
    <Modal
      title={t('Add Dynamic Secret Engine')}
      wide="xl"
      allowFullscreen
      onClose={onClose}
      footer={
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, width: '100%' }}>
          <button type="button" className="btn btn-ghost" onClick={onClose}>{t('Cancel')}</button>
          <button type="submit" form="dynamic-form" className="btn btn-primary" disabled={busy}>
            {busy ? <Spinner /> : t('Create Provider')}
          </button>
        </div>
      }
    >
      <form id="dynamic-form" onSubmit={submit}>
        {submitErr && <div className="alert alert-bad" style={{ marginBottom: 12 }}>{submitErr}</div>}
        <div className="modal-two-col">
          {/* Left Column: Target Engine & Connection Topology */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <Field label={t('Target Engine')}>
              <select value={engine} onChange={(e) => handleEngineChange(e.target.value)}>
                <option value="postgres">PostgreSQL</option>
                <option value="mysql">MySQL / MariaDB</option>
                <option value="redis">Redis (ACL)</option>
              </select>
            </Field>

            <Field label={t('Provider Name')}>
              <input required placeholder="e.g. app-postgres-readonly" value={name} onChange={(e) => setName(e.target.value)} />
            </Field>

            <DynamicEngineConfigForm
              engine={engine}
              value={config}
              onChange={setConfig}
              onRoleTemplateChange={setRoleTemplate}
            />

            <div className="grid-2">
              <Field label={t('Default TTL (seconds)')}>
                <input type="number" min={60} value={defaultTTL} onChange={(e) => setDefaultTTL(Number(e.target.value))} />
              </Field>
              <Field label={t('Max TTL (seconds)')}>
                <input type="number" min={60} value={maxTTL} onChange={(e) => setMaxTTL(Number(e.target.value))} />
              </Field>
            </div>

            <div className="grid-2">
              <Field label={t('Enforced Local Port')} help={t('0 = dynamic ephemeral port')}>
                <input type="number" min={0} max={65535} placeholder="0 (ephemeral)" value={enforcedPort || ''} onChange={(e) => setEnforcedPort(Number(e.target.value))} />
              </Field>

              <Field label={t('Network Site Gateway')} help={t('Optional private VPC jump route')}>
                <select value={siteId} onChange={(e) => setSiteId(e.target.value)}>
                  <option value="">{t('Direct Connection')}</option>
                  {(sites || []).map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name} ({s.online ? t('ONLINE') : t('OFFLINE')})
                    </option>
                  ))}
                </select>
              </Field>
            </div>
          </div>

          {/* Right Column: Role Template & Object Permissions Inspector */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div className="surface-box">
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{ fontSize: 12, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Sparkles size={14} style={{ color: 'var(--accent)' }} />
                  {t('Role Template & Permissions SQL')}
                </span>
                <span className="mono muted small">{t('Placeholder: {{name}}')}</span>
              </div>
              <p className="muted small" style={{ margin: '0 0 8px 0', fontSize: 11, lineHeight: 1.4 }}>
                {t('SQL or ACL statements executed when provisioning each temporary user. Use {{name}} for the generated username.')}
              </p>

              <textarea
                rows={6}
                className="mono"
                style={{ fontSize: 12, lineHeight: 1.4, width: '100%', resize: 'vertical' }}
                value={roleTemplate}
                onChange={(e) => setRoleTemplate(e.target.value)}
                placeholder="GRANT USAGE ON SCHEMA public TO {{name}}; GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};"
              />

              {/* Engine Presets */}
              <div style={{ marginTop: 8 }}>
                <span className="muted small" style={{ fontSize: 11, display: 'block', marginBottom: 4 }}>
                  {t('Quick Permission Presets:')}
                </span>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {engine === 'postgres' && (
                    <>
                      <button
                        type="button"
                        className="btn btn-ghost btn-xs"
                        style={{ border: '1px dashed var(--border)' }}
                        onClick={() => applyPreset('GRANT USAGE ON SCHEMA public TO {{name}}; GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};')}
                      >
                        + {t('Read-Only Public')}
                      </button>
                      <button
                        type="button"
                        className="btn btn-ghost btn-xs"
                        style={{ border: '1px dashed var(--border)' }}
                        onClick={() => applyPreset('GRANT app_readonly TO {{name}};')}
                      >
                        + {t('Group Role (app_readonly)')}
                      </button>
                      <button
                        type="button"
                        className="btn btn-ghost btn-xs"
                        style={{ border: '1px dashed var(--border)' }}
                        onClick={() => applyPreset('GRANT USAGE ON SCHEMA public TO {{name}}; GRANT SELECT, INSERT, UPDATE ON TABLE orders, customers TO {{name}};')}
                      >
                        + {t('Specific Tables')}
                      </button>
                    </>
                  )}
                  {engine === 'mysql' && (
                    <>
                      <button
                        type="button"
                        className="btn btn-ghost btn-xs"
                        style={{ border: '1px dashed var(--border)' }}
                        onClick={() => applyPreset("GRANT SELECT ON *.* TO {{name}};")}
                      >
                        + {t('Read-Only (SELECT)')}
                      </button>
                      <button
                        type="button"
                        className="btn btn-ghost btn-xs"
                        style={{ border: '1px dashed var(--border)' }}
                        onClick={() => applyPreset("GRANT 'app_reader' TO {{name}}; SET DEFAULT ROLE 'app_reader' TO {{name}};")}
                      >
                        + {t('Group Role (MySQL 8+)')}
                      </button>
                    </>
                  )}
                  {engine === 'redis' && (
                    <>
                      <button
                        type="button"
                        className="btn btn-ghost btn-xs"
                        style={{ border: '1px dashed var(--border)' }}
                        onClick={() => applyPreset('~* +@read')}
                      >
                        + {t('Read-Only (~* +@read)')}
                      </button>
                      <button
                        type="button"
                        className="btn btn-ghost btn-xs"
                        style={{ border: '1px dashed var(--border)' }}
                        onClick={() => applyPreset('~cache:* +@all -@dangerous')}
                      >
                        + {t('Restricted Cache Keys')}
                      </button>
                    </>
                  )}
                  {engine === 'pam' && (
                    <button
                      type="button"
                      className="btn btn-ghost btn-xs"
                      style={{ border: '1px dashed var(--border)' }}
                      onClick={() => applyPreset('')}
                    >
                      + {t('Default Shell Access')}
                    </button>
                  )}
                </div>
              </div>
            </div>

            {/* Connection Test Bar */}
            <div className="surface-box" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <Activity size={14} style={{ color: 'var(--accent)' }} />
                <span style={{ fontSize: 12, fontWeight: 600 }}>{t('Verify Topology Connectivity')}</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                {testResult && (
                  <Tag tone={testResult.success ? 'good' : 'bad'} mono>
                    {testResult.success ? t('ONLINE') : t('FAILED')}
                  </Tag>
                )}
                <button
                  type="button"
                  className="btn btn-sm btn-subtle"
                  onClick={testConfig}
                  disabled={testing}
                >
                  {testing ? <Spinner /> : <Activity size={12} />} {t('Test Now')}
                </button>
              </div>
            </div>

            {/* JIT Architecture Info Card */}
            <div className="surface-box" style={{ fontSize: 11 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                <Database size={14} style={{ color: 'var(--accent)' }} />
                <strong>{t('Temporary Credentials')}</strong>
              </div>
              <p className="muted small" style={{ margin: 0, lineHeight: 1.4 }}>
                {t('Credentials are created on demand and removed when their TTL expires. Failed grants roll back.')}
              </p>
            </div>
          </div>
        </div>
      </form>
    </Modal>
  )
}
