import { useEffect, useState } from 'react'
import { Copy, Check, Eye, EyeOff, Pencil, Layers } from 'lucide-react'
import { t } from '../../i18n'
import { api, enc, type Credential } from '../../lib/api'
import { allowed } from '../../lib/access'
import { copy, dateTime } from '../../lib/format'
import { Spinner, Tag } from '../../ui/common'
import { Modal, openDialog, toast } from '../../ui/overlays'
import { CredentialModal, credentialKindLabel, credentialKindTone } from './CredentialModal'
import { SyncCredentialModal } from './SyncCredentialModal'

function CopyField({
  label,
  value,
  secret = false,
  multiline = false,
}: {
  label: string
  value?: string
  secret?: boolean
  multiline?: boolean
}) {
  const [revealed, setRevealed] = useState(!secret)
  const [copied, setCopied] = useState(false)

  if (!value) return null

  const doCopy = () => {
    copy(value).then((ok) => {
      if (!ok) return
      setCopied(true)
      toast.ok(t('{0} copied to clipboard', label))
      setTimeout(() => setCopied(false), 1600)
    })
  }

  return (
    <div className="surface-box" style={{ padding: '10px 12px' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, marginBottom: 6 }}>
        <span className="muted small" style={{ fontWeight: 600 }}>
          {label}
        </span>
        <div style={{ display: 'flex', gap: 4 }}>
          {secret && (
            <button type="button" className="btn btn-xs btn-ghost" onClick={() => setRevealed((v) => !v)}>
              {revealed ? <EyeOff size={12} /> : <Eye size={12} />} {revealed ? t('Hide') : t('Reveal')}
            </button>
          )}
          <button type="button" className="btn btn-xs btn-ghost" onClick={doCopy}>
            {copied ? <Check size={12} /> : <Copy size={12} />} {copied ? t('Copied') : t('Copy')}
          </button>
        </div>
      </div>
      {multiline ? (
        <pre
          className="mono code-block"
          style={{
            margin: 0,
            maxHeight: 160,
            overflowY: 'auto',
            ...(revealed ? {} : ({ WebkitTextSecurity: 'disc' } as React.CSSProperties)),
          }}
        >
          {revealed ? value : '••••••••••••••••••••••••••••••••••••••••'}
        </pre>
      ) : (
        <div className="mono" style={{ fontSize: 13, wordBreak: 'break-all' }}>
          {revealed ? value : '••••••••••••••••••••••••'}
        </div>
      )}
    </div>
  )
}

export function CredentialInspectorModal({
  credential,
  onClose,
}: {
  credential: Credential
  onClose: () => void
}) {
  const [full, setFull] = useState<Credential>(credential)
  const [loading, setLoading] = useState(!credential.payload)

  useEffect(() => {
    if (!credential.payload) {
      setLoading(true)
      api
        .get<Credential>(`/credentials/${enc(credential.id)}`)
        .then(setFull)
        .catch(toast.err)
        .finally(() => setLoading(false))
    }
  }, [credential.id])

  const p = full.payload || {}

  return (
    <Modal
      title={full.name}
      wide
      onClose={onClose}
      footer={
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => {
                onClose()
                openDialog((c) => <SyncCredentialModal credential={full} onClose={c} />)
              }}
            >
              <Layers size={14} /> {t('Sync to Environment (.env)…')}
            </button>
            {allowed('credentials.write') && (
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => {
                  onClose()
                  openDialog((c) => <CredentialModal initial={full} onClose={c} />)
                }}
              >
                <Pencil size={14} /> {t('Edit')}
              </button>
            )}
          </div>
          <button type="button" className="btn btn-primary" onClick={onClose}>
            {t('Done')}
          </button>
        </div>
      }
    >
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <Tag tone={credentialKindTone(full.kind)}>{credentialKindLabel(full.kind)}</Tag>
          {full.project_name ? (
            <Tag tone="accent">
              {full.project_name}
              {full.environment_slug ? ` · ${full.environment_slug}` : ' · *'}
            </Tag>
          ) : (
            <Tag tone="muted">{t('Global Vault')}</Tag>
          )}
          {full.expires_at && (
            <span className="muted small">
              {t('Expires')}: <strong>{dateTime(full.expires_at)}</strong>
            </span>
          )}
        </div>

        {full.description && <p className="muted small" style={{ margin: 0 }}>{full.description}</p>}

        {loading ? (
          <div className="center" style={{ padding: 32 }}>
            <Spinner />
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {full.kind === 'ssh_key' && (
              <>
                <div className="grid-2">
                  <CopyField label={t('SSH Username')} value={p.username} />
                  <CopyField label={t('Target Host')} value={p.host ? (p.port && p.port !== 22 ? `${p.host}:${p.port}` : p.host) : undefined} />
                </div>
                <CopyField label={t('SHA-256 Fingerprint')} value={p.fingerprint} />
                <CopyField label={t('Public Key (authorized_keys)')} value={p.public_key} multiline />
                <CopyField label={t('Private Key (OpenSSH / PEM)')} value={p.private_key} secret multiline />
                <CopyField label={t('Key Passphrase')} value={p.passphrase} secret />
              </>
            )}

            {full.kind === 'tls_cert' && (
              <>
                <div className="grid-2">
                  <CopyField label={t('Subject')} value={p.subject} />
                  <CopyField label={t('Issuer CA')} value={p.issuer} />
                </div>
                <CopyField label={t('SHA-256 Fingerprint')} value={p.fingerprint} />
                <CopyField label={t('Certificate PEM')} value={p.certificate} multiline />
                <CopyField label={t('Private Key PEM')} value={p.private_key} secret multiline />
                <CopyField label={t('CA Chain PEM')} value={p.ca_chain} multiline />
                <CopyField label={t('Key Passphrase')} value={p.passphrase} secret />
              </>
            )}

            {full.kind === 'oauth_api' && (
              <>
                <div className="grid-2">
                  <CopyField label={t('Provider')} value={p.provider} />
                  <CopyField label={t('Scopes')} value={p.scopes} />
                </div>
                <CopyField label={t('Client ID / Access Key ID')} value={p.client_id} />
                <CopyField label={t('Client Secret / Secret Key')} value={p.client_secret} secret />
                <CopyField label={t('API Key / Bearer Token')} value={p.api_key} secret />
                <div className="grid-2">
                  <CopyField label={t('Token URL')} value={p.token_url} />
                  <CopyField label={t('Endpoint URL')} value={p.endpoint_url} />
                </div>
              </>
            )}

            {full.kind === 'login' && (
              <>
                <div className="grid-2">
                  <CopyField label={t('Username')} value={p.username} />
                  <CopyField label={t('Password')} value={p.password} secret />
                </div>
                <div className="grid-2">
                  <CopyField label={t('Host')} value={p.host ? (p.port ? `${p.host}:${p.port}` : p.host) : undefined} />
                  <CopyField label={t('Database')} value={p.database} />
                </div>
                <CopyField label={t('URL')} value={p.url} />
              </>
            )}

            <CopyField
              label={t('CLI Quick Usage (ducksecrets cred)')}
              value={
                full.kind === 'ssh_key'
                  ? `ducksecrets cred ssh connect "${full.name}"\nducksecrets cred ssh export "${full.name}" --dir=~/.ssh`
                  : full.kind === 'login'
                    ? p.database
                      ? `ducksecrets cred db connect "${full.name}"\nducksecrets cred db get "${full.name}" --format=env`
                      : `ducksecrets cred login get "${full.name}"\nducksecrets cred login get "${full.name}" --field=password`
                    : full.kind === 'tls_cert'
                      ? `ducksecrets cred tls export "${full.name}" --dir=./certs\nducksecrets cred tls get "${full.name}" --field=cert`
                      : `ducksecrets cred api get "${full.name}" --format=env\nducksecrets cred api get "${full.name}" --field=api_key`
              }
              multiline
            />
          </div>
        )}
      </div>
    </Modal>
  )
}
