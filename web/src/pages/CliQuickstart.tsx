import { t } from '../i18n'
import { Download, Terminal } from 'lucide-react'
import type { ProjectList } from '../lib/api'
import { getMe } from '../lib/session'
import { useResource } from '../lib/store'
import { CopyBlock } from '../ui/CopyBlock'

export function CliQuickstart() {
  const { data: projectList } = useResource<ProjectList>('/projects')
  const firstSlug = projectList?.items?.[0]?.slug || 'my-app'
  const origin = typeof window !== 'undefined' ? window.location.origin : 'https://vault.example.com'
  const me = getMe()
  const selfSigned = Boolean(me?.self_signed)
  const tlsFingerprint = me?.tls_fingerprint || ''
  const curlFlags = selfSigned ? '-kfsSL' : '-fsSL'
  const cliTlsFlag = selfSigned && tlsFingerprint ? ` --tls-fingerprint ${tlsFingerprint}` : ''

  const installCmd = `curl ${curlFlags} ${origin}/install.sh | sudo sh`
  const directDownloadCmd = `curl ${curlFlags} ${origin}/download/ducksecrets -o ducksecrets && chmod +x ducksecrets`
  const loginUserAndConnect = `ducksecrets login --server ${origin} --user your-username\nducksecrets connect postgres-prod --project ${firstSlug} --env prod`
  const loginAndRun = `ducksecrets login --server ${origin} --token duck_st_YOUR_TOKEN\nducksecrets run --project ${firstSlug} --env prod -- npm start`
  const exportCmd = `ducksecrets export --project ${firstSlug} --env prod --format dotenv > .env`
  const ciEnvSnippet = `export DUCKSECRETS_SERVER="${origin}"\nexport DUCKSECRETS_TOKEN="duck_st_YOUR_TOKEN"${selfSigned && tlsFingerprint ? `\nexport DUCKSECRETS_TLS_FINGERPRINT="${tlsFingerprint}"` : ''}\nducksecrets run --project ${firstSlug} --env prod -- ./deploy.sh`

  return (
    <div className="page narrow">
      <div className="page-head">
        <div className="page-title">
          <Terminal size={20} />
          <h1>{t('CLI & Quickstart')}</h1>
        </div>
        <div className="page-actions">
          <a className="btn btn-sm btn-primary" href="/download/ducksecrets" download="ducksecrets">
            <Download size={14} /> {t('Download CLI Binary')}
          </a>
        </div>
      </div>

      <div className="page-body" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        {selfSigned && (
          <div className="alert alert-warn" style={{ marginBottom: 0 }}>
            <div>
              <strong>{t('Self-signed HTTPS active on this server.')}</strong>{' '}
              {t('The installer uses curl -k once to fetch install.sh, which embeds and pins the server certificate into /etc/ducksecrets/server.crt and cli.json so subsequent CLI commands (login, site list, connect) verify TLS automatically. If you use manual download without install.sh, pass:')}{' '}
              <code className="mono">{cliTlsFlag.trim() || '--insecure'}</code>
            </div>
          </div>
        )}

        <CopyBlock
          title={t('1. Install the DuckSecrets CLI')}
          subtitle={t('Downloads the CLI directly from this server, installs it to /usr/local/bin (with sudo) or ~/.local/bin, and pins server TLS trust.')}
          badge="Linux / macOS"
          code={installCmd}
        />

        <CopyBlock
          title={t('Direct Binary Download (Manual)')}
          subtitle={t('Download the static binary served directly by your DuckSecrets instance.')}
          code={directDownloadCmd}
        />

        <CopyBlock
          title={t('2. Sign In (User/Password) & Managed DB Tunnels')}
          subtitle={t('Human users can sign in with username & password and open ephemeral database tunnels (PostgreSQL, MySQL, Redis) with automatic credential revocation.')}
          code={loginUserAndConnect}
        />

        <CopyBlock
          title={t('3. Credentials Vault CLI (cred ssh / db / login / tls / api)')}
          subtitle={t('Each credential type has its own dedicated subcommand with type-specific flags and validations.')}
          code={`# 1. SSH Keys (cred ssh)
ducksecrets cred ssh set "Bastion Prod" --generate=ed25519 --user=ubuntu --host=10.0.1.25 --port=22
ducksecrets cred ssh connect "Bastion Prod"
ducksecrets cred ssh get "Bastion Prod" --field=public_key

# 2. Databases (cred db)
ducksecrets cred db set "Analytics PG" --engine=postgres --host=10.0.1.50 --db=analytics --user=readonly --password=secret
ducksecrets cred db connect "Analytics PG"

# 3. Logins, TLS & API/OAuth (cred login / cred tls / cred api)
ducksecrets cred login set "AWS Console" --user=admin@acme.com --url=https://console.aws.amazon.com
ducksecrets cred tls set "Wildcard TLS" --cert-file=./fullchain.pem --key-file=./privkey.pem
ducksecrets cred api set "Stripe Live" --provider=Stripe --api-key=sk_live_12345`}
        />

        <CopyBlock
          title={t('4. Token Auth & Inject Secrets into Any Process')}
          subtitle={t('Secrets are injected into the child process memory without writing plaintext .env files to disk.')}
          code={loginAndRun}
        />

        <CopyBlock
          title={t('Export as .env / JSON / YAML')}
          subtitle={t('Optional export for tools that require a file format.')}
          code={exportCmd}
        />

        <CopyBlock
          title={t('CI/CD & Container Usage')}
          subtitle={t('Use a scoped Service Token (duck_st_*) with environment, path, and CIDR restrictions.')}
          code={ciEnvSnippet}
        />

        <CopyBlock
          title={t('5. HashiCorp Vault HTTP v1 Compatibility (/v1/*)')}
          subtitle={t('DuckSecrets natively speaks the full HashiCorp Vault v1 protocol (X-Vault-Token, Userpass, AppRole, KV v2 with versioning & subkeys, Credentials CRUD, Dynamic Database Leases, Transit Encryption-as-a-Service, and Response Wrapping).')}
          badge="Vault v1 API"
          code={`# 1. Authenticate (Token, Userpass, or AppRole)
export VAULT_ADDR="${origin}"
export VAULT_TOKEN="duck_st_YOUR_TOKEN"${selfSigned ? '\nexport VAULT_SKIP_VERIFY=true' : ''}

# 2. KV v2 Secrets Engine (/v1/secret/data, metadata, subkeys, delete, undelete, destroy)
vault kv get secret/${firstSlug}/prod
vault kv put secret/${firstSlug}/prod API_KEY="live_123"
vault kv get -subkeys secret/${firstSlug}/prod

# 3. Credentials Engine (/v1/creds/data/<project>/<name>) & SSH Key Generator (/v1/creds/generate-ssh)
curl ${selfSigned ? '-k ' : ''}-H "X-Vault-Token: $VAULT_TOKEN" ${origin}/v1/creds/data/${firstSlug}/Bastion%20Prod

# 4. Dynamic Database Leases (/v1/database/creds & /v1/sys/leases/renew|revoke)
vault read database/creds/${firstSlug}/prod/postgres-main

# 5. Transit Encryption-as-a-Service (/v1/transit/encrypt, decrypt, hmac, random)
vault write transit/encrypt/app-key plaintext=$(echo -n "my-secret" | base64)
vault write transit/random/32 format=hex

# 6. Response Wrapping (X-Vault-Wrap-TTL header + /v1/sys/wrapping/unwrap)
vault kv get -wrap-ttl=5m secret/${firstSlug}/prod`}
        />
      </div>
    </div>
  )
}
