import { useEffect, useState } from 'react'
import { KeyRound, ShieldCheck, Globe, UserCheck, Sparkles, Eye, EyeOff } from 'lucide-react'
import { t } from '../../i18n'
import {
  api,
  enc,
  type Credential,
  type CredentialPayload,
  type Environment,
  type GenerateSSHKeyResponse,
  type ProjectList,
} from '../../lib/api'
import { invalidate, useResource } from '../../lib/store'
import { Field } from '../../ui/Field'
import { Spinner, Tag } from '../../ui/common'
import { Modal, toast } from '../../ui/overlays'

export type CredentialKind = 'ssh_key' | 'tls_cert' | 'oauth_api' | 'login'

export const CREDENTIAL_KINDS: {
  id: CredentialKind
  label: string
  sub: string
  icon: typeof KeyRound
  tone: 'accent' | 'ok' | 'muted'
}[] = [
  {
    id: 'ssh_key',
    label: 'SSH Keypair',
    sub: 'Private key, public key, passphrase & target host',
    icon: KeyRound,
    tone: 'accent',
  },
  {
    id: 'tls_cert',
    label: 'TLS Certificate',
    sub: 'X.509 PEM certificate, private key & CA bundle',
    icon: ShieldCheck,
    tone: 'ok',
  },
  {
    id: 'oauth_api',
    label: 'API Key / OAuth',
    sub: 'Client ID, client secret, API token, endpoints & scopes',
    icon: Globe,
    tone: 'accent',
  },
  {
    id: 'login',
    label: 'Account / DB Login',
    sub: 'Username, password, host/URL & database',
    icon: UserCheck,
    tone: 'muted',
  },
]

export function credentialKindLabel(kind: string): string {
  switch (kind) {
    case 'ssh_key':
      return t('SSH Key')
    case 'tls_cert':
      return t('TLS Certificate')
    case 'oauth_api':
      return t('API / OAuth')
    case 'login':
      return t('Login / Account')
    default:
      return kind
  }
}

export function credentialKindTone(kind: string): 'accent' | 'ok' | 'muted' | 'bad' {
  switch (kind) {
    case 'ssh_key':
      return 'accent'
    case 'tls_cert':
      return 'ok'
    case 'oauth_api':
      return 'accent'
    default:
      return 'muted'
  }
}

export function CredentialModal({
  initial,
  defaultProjectId,
  defaultEnvSlug,
  onSaved,
  onClose,
}: {
  initial?: Credential
  defaultProjectId?: string
  defaultEnvSlug?: string
  onSaved?: (c: Credential) => void
  onClose: () => void
}) {
  const { data: projectList } = useResource<ProjectList>('/projects')
  const projects = projectList?.items || []

  const [name, setName] = useState(initial?.name ?? '')
  const [kind, setKind] = useState<CredentialKind>((initial?.kind as CredentialKind) ?? 'ssh_key')
  const [description, setDescription] = useState(initial?.description ?? '')
  const [projectId, setProjectId] = useState(initial?.project_id ?? defaultProjectId ?? '')
  const [envSlug, setEnvSlug] = useState(initial?.environment_slug ?? defaultEnvSlug ?? '')
  const [expiresAt, setExpiresAt] = useState(
    initial?.expires_at ? initial.expires_at.slice(0, 10) : '',
  )

  const { data: projectEnvs } = useResource<Environment[]>(
    projectId ? `/projects/${enc(projectId)}/environments` : null,
  )

  const [payload, setPayload] = useState<CredentialPayload>(initial?.payload ?? {})
  const [loadingPayload, setLoadingPayload] = useState(false)
  const [generatingSSH, setGeneratingSSH] = useState(false)
  const [sshAlgo, setSshAlgo] = useState<'ed25519' | 'rsa4096' | 'ecdsa256'>('ed25519')
  const [showSecrets, setShowSecrets] = useState(false)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (initial && !initial.payload) {
      setLoadingPayload(true)
      api
        .get<Credential>(`/credentials/${enc(initial.id)}`)
        .then((res) => {
          if (res.payload) setPayload(res.payload)
        })
        .catch(toast.err)
        .finally(() => setLoadingPayload(false))
    }
  }, [initial?.id])

  const updateField = <K extends keyof CredentialPayload>(field: K, val: CredentialPayload[K]) => {
    setPayload((prev) => ({ ...prev, [field]: val }))
  }

  const handleGenerateSSH = async () => {
    if (generatingSSH) return
    setGeneratingSSH(true)
    try {
      const res = await api.post<GenerateSSHKeyResponse>('/credentials/generate-ssh', {
        algorithm: sshAlgo,
        comment: name.trim() || 'ducksecrets',
      })
      setPayload((prev) => ({
        ...prev,
        private_key: res.private_key,
        public_key: res.public_key,
        fingerprint: res.fingerprint,
        key_type: res.key_type,
      }))
      toast.ok(t('Generated {0} SSH keypair', sshAlgo.toUpperCase()))
    } catch (err) {
      toast.err(err)
    } finally {
      setGeneratingSSH(false)
    }
  }

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim() || busy) return
    setBusy(true)
    try {
      const expIso = expiresAt ? new Date(expiresAt + 'T23:59:59Z').toISOString() : undefined
      let saved: Credential
      if (initial) {
        saved = await api.patch<Credential>(`/credentials/${enc(initial.id)}`, {
          name: name.trim(),
          kind,
          description: description.trim(),
          project_id: projectId || '',
          environment_slug: projectId ? envSlug : '',
          expires_at: expIso,
          payload,
        })
        toast.ok(t('Credential updated'))
      } else {
        saved = await api.post<Credential>('/credentials', {
          name: name.trim(),
          kind,
          description: description.trim(),
          project_id: projectId || undefined,
          environment_slug: projectId ? envSlug : undefined,
          expires_at: expIso,
          payload,
        })
        toast.ok(t('Credential encrypted and saved'))
      }
      invalidate('/credentials')
      if (projectId) invalidate(`/projects/${enc(projectId)}/credentials`)
      onSaved?.(saved)
      onClose()
    } catch (err) {
      toast.err(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      title={initial ? t('Edit Credential: {0}', initial.name) : t('New Structured Credential')}
      wide="xl"
      allowFullscreen
      onClose={onClose}
      footer={
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
          <button
            type="button"
            className="btn btn-sm btn-ghost"
            onClick={() => setShowSecrets((v) => !v)}
          >
            {showSecrets ? <EyeOff size={14} /> : <Eye size={14} />}{' '}
            {showSecrets ? t('Mask secret fields') : t('Reveal secret fields')}
          </button>
          <div style={{ display: 'flex', gap: 8 }}>
            <button type="button" className="btn btn-ghost" onClick={onClose}>
              {t('Cancel')}
            </button>
            <button type="submit" form="credential-form" className="btn btn-primary" disabled={busy || loadingPayload}>
              {busy ? <Spinner /> : initial ? t('Save Changes') : t('Encrypt & Store')}
            </button>
          </div>
        </div>
      }
    >
      <form id="credential-form" onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        {/* Credential Type Selector */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))', gap: 10 }}>
          {CREDENTIAL_KINDS.map((k) => {
            const Icon = k.icon
            const active = kind === k.id
            return (
              <button
                key={k.id}
                type="button"
                onClick={() => setKind(k.id)}
                className="surface-box"
                style={{
                  textAlign: 'left',
                  cursor: 'pointer',
                  padding: '10px 12px',
                  borderColor: active ? 'var(--accent)' : 'var(--border)',
                  background: active ? 'var(--accent-soft)' : 'var(--surface-2)',
                  transition: 'all 0.12s ease',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <Icon size={15} style={{ color: active ? 'var(--accent)' : 'var(--muted)' }} />
                  <strong style={{ fontSize: 13 }}>{t(k.label)}</strong>
                </div>
                <div className="muted small" style={{ fontSize: 11.5, lineHeight: 1.35 }}>
                  {t(k.sub)}
                </div>
              </button>
            )
          })}
        </div>

        {/* Common Metadata & Optional Project Binding */}
        <div className="grid-2">
          <Field required label={t('Credential Name')} help={t('e.g. Deploy Key GitHub, Stripe Live OAuth, Wildcard TLS')}>
            <input
              required
              autoFocus
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={t('Production SSH Key')}
            />
          </Field>

          <Field optional label={t('Description / Notes')} help={t('Optional context or rotation owner')}>
            <input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder={t('Used by CI runner and bastion hosts')}
            />
          </Field>
        </div>

        <div className="surface-box" style={{ padding: 12 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
            <Field
              optional
              label={t('Project Link')}
              help={t('Leave Global or bind to a specific Project')}
            >
              <select
                value={projectId}
                onChange={(e) => {
                  setProjectId(e.target.value)
                  setEnvSlug('')
                }}
              >
                <option value="">{t('Global Vault (Unbound)')}</option>
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} ({p.slug})
                  </option>
                ))}
              </select>
            </Field>

            <Field
              optional
              label={t('Environment Scope')}
              help={projectId ? t('All environments or a specific one') : t('Select a project first')}
            >
              <select
                value={envSlug}
                disabled={!projectId}
                onChange={(e) => setEnvSlug(e.target.value)}
              >
                <option value="">{t('All Environments (*)')}</option>
                {(projectEnvs || []).map((env) => (
                  <option key={env.id} value={env.slug}>
                    {env.name} ({env.slug})
                  </option>
                ))}
              </select>
            </Field>

            <Field
              optional
              label={t('Expiration Date')}
              help={kind === 'tls_cert' ? t('Auto-detected from X.509 cert if left blank') : t('Track key/token expiry')}
            >
              <input
                type="date"
                value={expiresAt}
                onChange={(e) => setExpiresAt(e.target.value)}
              />
            </Field>
          </div>
        </div>

        {loadingPayload ? (
          <div className="center" style={{ padding: 28 }}>
            <Spinner />
          </div>
        ) : (
          <>
            {/* SSH KEY FORM */}
            {kind === 'ssh_key' && (
              <div className="surface-card" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <strong>{t('SSH Keypair Material')}</strong>
                    {payload.fingerprint && <Tag mono tone="ok">{payload.fingerprint}</Tag>}
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <select
                      value={sshAlgo}
                      onChange={(e) => setSshAlgo(e.target.value as any)}
                      style={{ width: 'auto', padding: '4px 8px', fontSize: 12 }}
                    >
                      <option value="ed25519">Ed25519 (Recommended)</option>
                      <option value="rsa4096">RSA 4096-bit</option>
                      <option value="ecdsa256">ECDSA P-256</option>
                    </select>
                    <button
                      type="button"
                      className="btn btn-xs btn-primary"
                      onClick={handleGenerateSSH}
                      disabled={generatingSSH}
                    >
                      <Sparkles size={12} /> {generatingSSH ? t('Generating…') : t('Generate Keypair')}
                    </button>
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 140px', gap: 12 }}>
                  <Field optional label={t('Default SSH Username')}>
                    <input
                      className="mono"
                      value={payload.username || ''}
                      onChange={(e) => updateField('username', e.target.value)}
                      placeholder="ubuntu / root / git"
                    />
                  </Field>
                  <Field optional label={t('Target Host / Bastion')}>
                    <input
                      className="mono"
                      value={payload.host || ''}
                      onChange={(e) => updateField('host', e.target.value)}
                      placeholder="10.0.1.25 or github.com"
                    />
                  </Field>
                  <Field optional label={t('SSH Port')}>
                    <input
                      type="number"
                      className="mono"
                      value={payload.port || 22}
                      onChange={(e) => updateField('port', Number(e.target.value) || 22)}
                    />
                  </Field>
                </div>

                <Field required label={t('Private Key (OpenSSH / PEM)')}>
                  <textarea
                    rows={6}
                    className="mono"
                    style={showSecrets ? undefined : ({ WebkitTextSecurity: 'disc' } as React.CSSProperties)}
                    value={payload.private_key || ''}
                    onChange={(e) => updateField('private_key', e.target.value)}
                    placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                  />
                </Field>

                <div className="grid-2">
                  <Field
                    optional
                    label={t('Public Key (authorized_keys)')}
                    help={t('Auto-derived on save if private key is unencrypted')}
                  >
                    <textarea
                      rows={3}
                      className="mono"
                      value={payload.public_key || ''}
                      onChange={(e) => updateField('public_key', e.target.value)}
                      placeholder="ssh-ed25519 AAAA... user@host"
                    />
                  </Field>
                  <Field optional label={t('Key Passphrase')}>
                    <input
                      type={showSecrets ? 'text' : 'password'}
                      className="mono"
                      value={payload.passphrase || ''}
                      onChange={(e) => updateField('passphrase', e.target.value)}
                      placeholder={t('Passphrase if private key is encrypted')}
                    />
                  </Field>
                </div>
              </div>
            )}

            {/* TLS CERTIFICATE FORM */}
            {kind === 'tls_cert' && (
              <div className="surface-card" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <strong>{t('X.509 TLS Certificate & Private Key')}</strong>
                  <span className="muted small">
                    {t('Subject, Issuer, SHA-256 fingerprint, and NotAfter expiry are parsed automatically from PEM.')}
                  </span>
                </div>

                <div className="grid-2">
                  <Field required label={t('Certificate PEM (Fullchain or Leaf)')}>
                    <textarea
                      rows={6}
                      className="mono"
                      value={payload.certificate || ''}
                      onChange={(e) => updateField('certificate', e.target.value)}
                      placeholder="-----BEGIN CERTIFICATE-----"
                    />
                  </Field>
                  <Field optional label={t('Private Key PEM')}>
                    <textarea
                      rows={6}
                      className="mono"
                      style={showSecrets ? undefined : ({ WebkitTextSecurity: 'disc' } as React.CSSProperties)}
                      value={payload.private_key || ''}
                      onChange={(e) => updateField('private_key', e.target.value)}
                      placeholder="-----BEGIN PRIVATE KEY-----"
                    />
                  </Field>
                </div>

                <div className="grid-2">
                  <Field optional label={t('Intermediate / Root CA Bundle')}>
                    <textarea
                      rows={3}
                      className="mono"
                      value={payload.ca_chain || ''}
                      onChange={(e) => updateField('ca_chain', e.target.value)}
                      placeholder="-----BEGIN CERTIFICATE-----"
                    />
                  </Field>
                  <Field optional label={t('Private Key Passphrase')}>
                    <input
                      type={showSecrets ? 'text' : 'password'}
                      className="mono"
                      value={payload.passphrase || ''}
                      onChange={(e) => updateField('passphrase', e.target.value)}
                      placeholder={t('Passphrase if private key is encrypted')}
                    />
                  </Field>
                </div>
              </div>
            )}

            {/* OAUTH / API KEY FORM */}
            {kind === 'oauth_api' && (
              <div className="surface-card" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <strong>{t('API Key / OAuth 2.0 Client Credentials')}</strong>

                <div className="grid-2">
                  <Field optional label={t('Provider / Service')} help={t('e.g. AWS, GitHub, Stripe, Google Cloud, Auth0')}>
                    <input
                      value={payload.provider || ''}
                      onChange={(e) => updateField('provider', e.target.value)}
                      placeholder="Stripe / GitHub / AWS / OpenAI"
                    />
                  </Field>
                  <Field optional label={t('Scopes / Permissions')}>
                    <input
                      className="mono"
                      value={payload.scopes || ''}
                      onChange={(e) => updateField('scopes', e.target.value)}
                      placeholder="read:org, repo,offline_access"
                    />
                  </Field>
                </div>

                <div className="grid-2">
                  <Field optional label={t('Client ID / Access Key ID')}>
                    <input
                      className="mono"
                      value={payload.client_id || ''}
                      onChange={(e) => updateField('client_id', e.target.value)}
                      placeholder="AKIA... or client_id"
                    />
                  </Field>
                  <Field optional label={t('Client Secret / Secret Access Key')}>
                    <input
                      type={showSecrets ? 'text' : 'password'}
                      className="mono"
                      value={payload.client_secret || ''}
                      onChange={(e) => updateField('client_secret', e.target.value)}
                      placeholder="sk_live_... or client_secret"
                    />
                  </Field>
                </div>

                <Field optional label={t('Bearer / API Token')} help={t('If using a standalone API token or webhook signing secret')}>
                  <input
                    type={showSecrets ? 'text' : 'password'}
                    className="mono"
                    value={payload.api_key || ''}
                    onChange={(e) => updateField('api_key', e.target.value)}
                    placeholder="ghp_... / whsec_..."
                  />
                </Field>

                <div className="grid-2">
                  <Field optional label={t('OAuth Token URL')}>
                    <input
                      className="mono"
                      value={payload.token_url || ''}
                      onChange={(e) => updateField('token_url', e.target.value)}
                      placeholder="https://oauth2.googleapis.com/token"
                    />
                  </Field>
                  <Field optional label={t('Base API Endpoint URL')}>
                    <input
                      className="mono"
                      value={payload.endpoint_url || ''}
                      onChange={(e) => updateField('endpoint_url', e.target.value)}
                      placeholder="https://api.stripe.com/v1"
                    />
                  </Field>
                </div>
              </div>
            )}

            {/* LOGIN / ACCOUNT / DB FORM */}
            {kind === 'login' && (
              <div className="surface-card" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <strong>{t('Account / Database / Server Login')}</strong>

                <div className="grid-2">
                  <Field required label={t('Username / Principal')}>
                    <input
                      className="mono"
                      value={payload.username || ''}
                      onChange={(e) => updateField('username', e.target.value)}
                      placeholder="admin@example.com or db_admin"
                    />
                  </Field>
                  <Field optional label={t('Password')}>
                    <input
                      type={showSecrets ? 'text' : 'password'}
                      className="mono"
                      value={payload.password || ''}
                      onChange={(e) => updateField('password', e.target.value)}
                      placeholder="••••••••••••"
                    />
                  </Field>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 140px 1fr', gap: 12 }}>
                  <Field optional label={t('Host / Endpoint')}>
                    <input
                      className="mono"
                      value={payload.host || ''}
                      onChange={(e) => updateField('host', e.target.value)}
                      placeholder="db.internal.net"
                    />
                  </Field>
                  <Field optional label={t('Port')}>
                    <input
                      type="number"
                      className="mono"
                      value={payload.port || ''}
                      onChange={(e) => updateField('port', Number(e.target.value) || undefined)}
                      placeholder="5432"
                    />
                  </Field>
                  <Field optional label={t('Database / Service Name')}>
                    <input
                      className="mono"
                      value={payload.database || ''}
                      onChange={(e) => updateField('database', e.target.value)}
                      placeholder="production_db"
                    />
                  </Field>
                </div>

                <Field optional label={t('Console / Login URL')}>
                  <input
                    className="mono"
                    value={payload.url || ''}
                    onChange={(e) => updateField('url', e.target.value)}
                    placeholder="https://console.aws.amazon.com"
                  />
                </Field>
              </div>
            )}
          </>
        )}
      </form>
    </Modal>
  )
}
