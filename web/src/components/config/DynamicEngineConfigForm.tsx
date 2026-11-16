import { useState, useEffect } from 'react'
import { Eye, EyeOff } from 'lucide-react'
import { t } from '../../i18n'
import { can, getMe } from '../../lib/session'
import { Field } from '../../ui/Field'
import { ConfigToggle } from './ConfigToggle'

export interface DynamicEngineConfigFormProps {
  engine: string
  value: string
  onChange: (val: string) => void
  onRoleTemplateChange: (val: string) => void
}

export function DynamicEngineConfigForm({
  engine,
  value,
  onChange,
  onRoleTemplateChange,
}: DynamicEngineConfigFormProps) {
  const [mode, setMode] = useState<'form' | 'raw'>('form')

  // Postgres states
  const [pgHost, setPgHost] = useState('127.0.0.1')
  const [pgPort, setPgPort] = useState('5432')
  const [pgDatabase, setPgDatabase] = useState('app')
  const [pgUsername, setPgUsername] = useState('postgres')
  const [pgPassword, setPgPassword] = useState('')
  const [pgSSLMode, setPgSSLMode] = useState('disable')
  const [showPgPass, setShowPgPass] = useState(false)

  // MySQL states
  const [myHost, setMyHost] = useState('127.0.0.1')
  const [myPort, setMyPort] = useState('3306')
  const [myDatabase, setMyDatabase] = useState('app')
  const [myUsername, setMyUsername] = useState('root')
  const [myPassword, setMyPassword] = useState('')
  const [showMyPass, setShowMyPass] = useState(false)

  // Redis states
  const [redHost, setRedHost] = useState('127.0.0.1')
  const [redPort, setRedPort] = useState('6379')
  const [redUsername, setRedUsername] = useState('default')
  const [redPassword, setRedPassword] = useState('')
  const [redAclRules, setRedAclRules] = useState('~* +@read')
  const [showRedPass, setShowRedPass] = useState(false)

  // PAM states
  const [pamMode, setPamMode] = useState('tunnel')
  const [pamHost, setPamHost] = useState('127.0.0.1')
  const [pamPort, setPamPort] = useState('22')
  const [pamShell, setPamShell] = useState('/bin/bash')
  const [pamGroups, setPamGroups] = useState('developers')
  const [pamSudo, setPamSudo] = useState(false)
  const [pamProvCmd, setPamProvCmd] = useState('')
  const [pamRevCmd, setPamRevCmd] = useState('')

  const parseConfigToForm = (rawVal: string): boolean => {
    if (!rawVal || rawVal.trim() === '' || rawVal.trim() === '{}') return true
    try {
      const parsed = JSON.parse(rawVal)
      if (engine === 'postgres' && parsed.connection_url) {
        try {
          const u = new URL(parsed.connection_url)
          setPgHost(u.hostname || '127.0.0.1')
          setPgPort(u.port || '5432')
          setPgDatabase(u.pathname.replace(/^\//, '') || 'app')
          setPgUsername(decodeURIComponent(u.username || 'postgres'))
          setPgPassword(decodeURIComponent(u.password || ''))
          setPgSSLMode(u.searchParams.get('sslmode') || 'disable')
        } catch {
          return false
        }
      } else if (engine === 'mysql' && parsed.dsn) {
        const match = parsed.dsn.match(/^(?:([^:@]+)(?::(.*))?@)?(?:tcp\(([^:]+):(\d+)\))?\/(.*)$/)
        if (match) {
          if (match[1]) setMyUsername(match[1])
          if (match[2] !== undefined) setMyPassword(match[2])
          if (match[3]) setMyHost(match[3])
          if (match[4]) setMyPort(match[4])
          if (match[5]) setMyDatabase(match[5])
        }
      } else if (engine === 'redis') {
        if (parsed.address) {
          const idx = parsed.address.lastIndexOf(':')
          if (idx > 0) {
            setRedHost(parsed.address.slice(0, idx) || '127.0.0.1')
            setRedPort(parsed.address.slice(idx + 1) || '6379')
          } else {
            setRedHost(parsed.address)
          }
        }
        if (parsed.username !== undefined) setRedUsername(parsed.username)
        if (parsed.password !== undefined) setRedPassword(parsed.password)
        if (parsed.acl_rules !== undefined) setRedAclRules(parsed.acl_rules)
      } else if (engine === 'pam') {
        if (parsed.mode) setPamMode(parsed.mode)
        if (parsed.host) setPamHost(parsed.host)
        if (parsed.port) setPamPort(String(parsed.port))
        if (parsed.default_shell) setPamShell(parsed.default_shell)
        if (parsed.groups) setPamGroups(parsed.groups)
        if (parsed.sudo_access !== undefined) setPamSudo(Boolean(parsed.sudo_access))
        if (parsed.provision_cmd) setPamProvCmd(parsed.provision_cmd)
        if (parsed.revoke_cmd) setPamRevCmd(parsed.revoke_cmd)
      }
      return true
    } catch {
      return false
    }
  }

  useEffect(() => {
    if (!value || value.trim() === '' || value.trim() === '{}') {
      if (engine === 'postgres') updatePostgres()
      else if (engine === 'mysql') updateMySQL()
      else if (engine === 'redis') updateRedis()
      else if (engine === 'pam') updatePAM()
      return
    }
    if (!parseConfigToForm(value)) {
      setMode('raw')
    }
  }, [engine])

  const handleModeChange = (nextMode: 'form' | 'raw') => {
    if (nextMode === 'form' && !parseConfigToForm(value)) {
      setMode('raw')
      return
    }
    setMode(nextMode)
  }

  const updatePostgres = (h = pgHost, p = pgPort, db = pgDatabase, u = pgUsername, pass = pgPassword, ssl = pgSSLMode) => {
    setPgHost(h)
    setPgPort(p)
    setPgDatabase(db)
    setPgUsername(u)
    setPgPassword(pass)
    setPgSSLMode(ssl)

    const userInfo = pass ? `${encodeURIComponent(u)}:${encodeURIComponent(pass)}` : encodeURIComponent(u)
    const sslParam = ssl && ssl !== 'disable' ? `?sslmode=${ssl}` : '?sslmode=disable'
    const connStr = `postgres://${userInfo}@${h}:${p}/${db}${sslParam}`
    onChange(JSON.stringify({ connection_url: connStr }, null, 2))
  }

  const updateMySQL = (h = myHost, p = myPort, db = myDatabase, u = myUsername, pass = myPassword) => {
    setMyHost(h)
    setMyPort(p)
    setMyDatabase(db)
    setMyUsername(u)
    setMyPassword(pass)

    const userInfo = pass ? `${u}:${pass}` : u
    const dsn = `${userInfo}@tcp(${h}:${p})/${db}`
    onChange(JSON.stringify({ dsn }, null, 2))
  }

  const updateRedis = (h = redHost, p = redPort, u = redUsername, pass = redPassword, acl = redAclRules) => {
    setRedHost(h)
    setRedPort(p)
    setRedUsername(u)
    setRedPassword(pass)
    setRedAclRules(acl)

    const payload: Record<string, unknown> = {
      address: `${h}:${p}`,
    }
    if (u && u !== 'default') payload.username = u
    if (pass) payload.password = pass
    if (acl) payload.acl_rules = acl
    onChange(JSON.stringify(payload, null, 2))
  }

  const updatePAM = (
    modeVal = pamMode,
    h = pamHost,
    p = pamPort,
    sh = pamShell,
    grps = pamGroups,
    sudo = pamSudo,
    prov = pamProvCmd,
    rev = pamRevCmd
  ) => {
    setPamMode(modeVal)
    setPamHost(h)
    setPamPort(p)
    setPamShell(sh)
    setPamGroups(grps)
    setPamSudo(sudo)
    setPamProvCmd(prov)
    setPamRevCmd(rev)

    const payload: Record<string, unknown> = {
      mode: modeVal,
      default_shell: sh,
      groups: grps,
      sudo_access: sudo,
    }
    if (h) payload.host = h
    if (p) payload.port = Number(p) || 22
    if (modeVal === 'command') {
      if (prov) payload.provision_cmd = prov
      if (rev) payload.revoke_cmd = rev
    }
    onChange(JSON.stringify(payload, null, 2))
  }

  const allowScripts = Boolean(getMe()?.allow_scripts)
  const canManageSystem = can('system.manage')
  const hostExecAllowed = allowScripts && canManageSystem
  const restrictedSuffix = !allowScripts
    ? ` (${t('disabled on server — needs DUCKSECRETS_ALLOW_SCRIPTS=1')})`
    : !canManageSystem
      ? ` (${t('requires system.manage role')})`
      : ''

  return (
    <div className="config-box" style={{ marginBottom: 12 }}>
      <ConfigToggle mode={mode} onChange={handleModeChange} label={t('Target Connection & Driver Settings')} />

      {mode === 'raw' ? (
        <Field label={t('Raw Engine JSON Config')} help={t('Encrypted with project vault key before storage')}>
          <textarea
            required
            rows={5}
            className="mono small"
            value={value}
            onChange={(e) => onChange(e.target.value)}
          />
        </Field>
      ) : (
        <div>
          {engine === 'postgres' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 8 }}>
                <Field label={t('Host / Hostname')}>
                  <input
                    required
                    placeholder="localhost or db.internal"
                    value={pgHost}
                    onChange={(e) => updatePostgres(e.target.value, pgPort, pgDatabase, pgUsername, pgPassword, pgSSLMode)}
                  />
                </Field>
                <Field label={t('Port')}>
                  <input
                    required
                    type="number"
                    min={1}
                    max={65535}
                    value={pgPort}
                    onChange={(e) => updatePostgres(pgHost, e.target.value, pgDatabase, pgUsername, pgPassword, pgSSLMode)}
                  />
                </Field>
              </div>

              <div className="grid-2">
                <Field label={t('Database Name')}>
                  <input
                    required
                    placeholder="app"
                    value={pgDatabase}
                    onChange={(e) => updatePostgres(pgHost, pgPort, e.target.value, pgUsername, pgPassword, pgSSLMode)}
                  />
                </Field>
                <Field label={t('SSL Mode')}>
                  <select
                    value={pgSSLMode}
                    onChange={(e) => updatePostgres(pgHost, pgPort, pgDatabase, pgUsername, pgPassword, e.target.value)}
                  >
                    <option value="disable">disable (unencrypted / local)</option>
                    <option value="require">require (TLS required)</option>
                    <option value="verify-ca">verify-ca</option>
                    <option value="verify-full">verify-full</option>
                  </select>
                </Field>
              </div>

              <div className="grid-2">
                <Field label={t('Admin Username')}>
                  <input
                    required
                    placeholder="postgres"
                    value={pgUsername}
                    onChange={(e) => updatePostgres(pgHost, pgPort, pgDatabase, e.target.value, pgPassword, pgSSLMode)}
                  />
                </Field>
                <Field label={t('Admin Password')}>
                  <div className="password-input-wrap">
                    <input
                      type={showPgPass ? 'text' : 'password'}
                      autoComplete="new-password"
                      placeholder="Password"
                      value={pgPassword}
                      onChange={(e) => updatePostgres(pgHost, pgPort, pgDatabase, pgUsername, e.target.value, pgSSLMode)}
                    />
                    <button
                      type="button"
                      className="icon-btn"
                      onClick={() => setShowPgPass(!showPgPass)}
                    >
                      {showPgPass ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                  </div>
                </Field>
              </div>

              <div style={{ marginTop: 4 }}>
                <span className="muted small" style={{ display: 'block', marginBottom: 4 }}>{t('Role Template Presets:')}</span>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  <button
                    type="button"
                    className="btn btn-xs btn-ghost"
                    onClick={() =>
                      onRoleTemplateChange(
                        'GRANT USAGE ON SCHEMA public TO {{name}}; GRANT SELECT ON ALL TABLES IN SCHEMA public TO {{name}};'
                      )
                    }
                  >
                    + Read-Only (SELECT)
                  </button>
                  <button
                    type="button"
                    className="btn btn-xs btn-ghost"
                    onClick={() =>
                      onRoleTemplateChange(
                        'GRANT USAGE ON SCHEMA public TO {{name}}; GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {{name}};'
                      )
                    }
                  >
                    + Read-Write (CRUD)
                  </button>
                  <button
                    type="button"
                    className="btn btn-xs btn-ghost"
                    onClick={() =>
                      onRoleTemplateChange(
                        'GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO {{name}};'
                      )
                    }
                  >
                    + Schema Admin
                  </button>
                </div>
              </div>
            </div>
          )}

          {engine === 'mysql' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 8 }}>
                <Field label={t('Host / Hostname')}>
                  <input
                    required
                    placeholder="127.0.0.1 or mysql.internal"
                    value={myHost}
                    onChange={(e) => updateMySQL(e.target.value, myPort, myDatabase, myUsername, myPassword)}
                  />
                </Field>
                <Field label={t('Port')}>
                  <input
                    required
                    type="number"
                    min={1}
                    max={65535}
                    value={myPort}
                    onChange={(e) => updateMySQL(myHost, e.target.value, myDatabase, myUsername, myPassword)}
                  />
                </Field>
              </div>

              <Field label={t('Database Name')}>
                <input
                  required
                  placeholder="app"
                  value={myDatabase}
                  onChange={(e) => updateMySQL(myHost, myPort, e.target.value, myUsername, myPassword)}
                />
              </Field>

              <div className="grid-2">
                <Field label={t('Admin Username')}>
                  <input
                    required
                    placeholder="root"
                    value={myUsername}
                    onChange={(e) => updateMySQL(myHost, myPort, myDatabase, e.target.value, myPassword)}
                  />
                </Field>
                <Field label={t('Admin Password')}>
                  <div className="password-input-wrap">
                    <input
                      type={showMyPass ? 'text' : 'password'}
                      autoComplete="new-password"
                      placeholder="Password"
                      value={myPassword}
                      onChange={(e) => updateMySQL(myHost, myPort, myDatabase, myUsername, e.target.value)}
                    />
                    <button
                      type="button"
                      className="icon-btn"
                      onClick={() => setShowMyPass(!showMyPass)}
                    >
                      {showMyPass ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                  </div>
                </Field>
              </div>

              <div style={{ marginTop: 4 }}>
                <span className="muted small" style={{ display: 'block', marginBottom: 4 }}>{t('Grant Template Presets:')}</span>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  <button
                    type="button"
                    className="btn btn-xs btn-ghost"
                    onClick={() => onRoleTemplateChange('GRANT SELECT ON *.* TO {{name}};')}
                  >
                    + Read-Only (SELECT)
                  </button>
                  <button
                    type="button"
                    className="btn btn-xs btn-ghost"
                    onClick={() => onRoleTemplateChange('GRANT SELECT, INSERT, UPDATE, DELETE ON *.* TO {{name}};')}
                  >
                    + Read-Write (CRUD)
                  </button>
                  <button
                    type="button"
                    className="btn btn-xs btn-ghost"
                    onClick={() => onRoleTemplateChange('GRANT ALL PRIVILEGES ON *.* TO {{name}};')}
                  >
                    + Full Privileges
                  </button>
                </div>
              </div>
            </div>
          )}

          {engine === 'redis' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 8 }}>
                <Field label={t('Redis Host')}>
                  <input
                    required
                    placeholder="127.0.0.1 or redis.internal"
                    value={redHost}
                    onChange={(e) => updateRedis(e.target.value, redPort, redUsername, redPassword, redAclRules)}
                  />
                </Field>
                <Field label={t('Port')}>
                  <input
                    required
                    type="number"
                    min={1}
                    max={65535}
                    value={redPort}
                    onChange={(e) => updateRedis(redHost, e.target.value, redUsername, redPassword, redAclRules)}
                  />
                </Field>
              </div>

              <div className="grid-2">
                <Field label={t('Admin Username (ACL)')}>
                  <input
                    placeholder="default"
                    value={redUsername}
                    onChange={(e) => updateRedis(redHost, redPort, e.target.value, redPassword, redAclRules)}
                  />
                </Field>
                <Field label={t('Admin Password (Optional)')}>
                  <div className="password-input-wrap">
                    <input
                      type={showRedPass ? 'text' : 'password'}
                      autoComplete="new-password"
                      placeholder="Optional"
                      value={redPassword}
                      onChange={(e) => updateRedis(redHost, redPort, redUsername, e.target.value, redAclRules)}
                    />
                    <button
                      type="button"
                      className="icon-btn"
                      onClick={() => setShowRedPass(!showRedPass)}
                    >
                      {showRedPass ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                  </div>
                </Field>
              </div>

              <Field label={t('ACL Rules')} help={t('Default Redis ACL permissions granted to temporary users')}>
                <input
                  className="mono"
                  placeholder="~* +@read"
                  value={redAclRules}
                  onChange={(e) => {
                    updateRedis(redHost, redPort, redUsername, redPassword, e.target.value)
                    onRoleTemplateChange(e.target.value)
                  }}
                />
              </Field>

              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                <span className="muted small" style={{ alignSelf: 'center' }}>{t('ACL Presets:')}</span>
                <button
                  type="button"
                  className="btn btn-xs btn-ghost"
                  onClick={() => {
                    updateRedis(redHost, redPort, redUsername, redPassword, '~* +@read')
                    onRoleTemplateChange('~* +@read')
                  }}
                >
                  + Read-Only (~* +@read)
                </button>
                <button
                  type="button"
                  className="btn btn-xs btn-ghost"
                  onClick={() => {
                    updateRedis(redHost, redPort, redUsername, redPassword, '~* +@read +@write')
                    onRoleTemplateChange('~* +@read +@write')
                  }}
                >
                  + Read-Write (~* +@read +@write)
                </button>
                <button
                  type="button"
                  className="btn btn-xs btn-ghost"
                  onClick={() => {
                    updateRedis(redHost, redPort, redUsername, redPassword, '~* +@all')
                    onRoleTemplateChange('~* +@all')
                  }}
                >
                  + Full Admin (~* +@all)
                </button>
              </div>
            </div>
          )}

          {engine === 'pam' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 8 }}>
                <Field label={t('Target SSH Host / IP')}>
                  <input
                    required
                    placeholder="10.0.1.25 or bastion.internal"
                    value={pamHost}
                    onChange={(e) =>
                      updatePAM(pamMode, e.target.value, pamPort, pamShell, pamGroups, pamSudo, pamProvCmd, pamRevCmd)
                    }
                  />
                </Field>
                <Field label={t('SSH Port')}>
                  <input
                    required
                    type="number"
                    min={1}
                    max={65535}
                    value={pamPort}
                    onChange={(e) =>
                      updatePAM(pamMode, pamHost, e.target.value, pamShell, pamGroups, pamSudo, pamProvCmd, pamRevCmd)
                    }
                  />
                </Field>
              </div>
              <Field label={t('Execution Mode')}>
                <select
                  value={pamMode}
                  onChange={(e) =>
                    updatePAM(e.target.value, pamHost, pamPort, pamShell, pamGroups, pamSudo, pamProvCmd, pamRevCmd)
                  }
                >
                  <option value="tunnel">{t('Remote SSH Tunnel Relay (Zero host scripts — recommended)')}</option>
                  <option value="local" disabled={!hostExecAllowed}>
                    {t('Local System (Host useradd / userdel via PAM)')}{restrictedSuffix}
                  </option>
                  <option value="simulated">{t('Simulated / Safe Dry-Run (Logs commands for testing)')}</option>
                  <option value="command" disabled={!hostExecAllowed}>
                    {t('Custom Provisioning Command Hooks')}{restrictedSuffix}
                  </option>
                </select>
              </Field>
              {!allowScripts ? (
                <div className="alert alert-warn small" style={{ marginBottom: 0 }}>
                  {t('Host OS execution ("local" useradd/userdel and "command" hooks) is disabled on this server. To enable it, start ducksecretsd with -allow-scripts or set DUCKSECRETS_ALLOW_SCRIPTS=1 in /etc/ducksecrets/env (requires system.manage). Use "Remote SSH Tunnel Relay" or "Simulated" otherwise.')}
                </div>
              ) : !canManageSystem ? (
                <div className="alert alert-warn small" style={{ marginBottom: 0 }}>
                  {t('Configuring "local" or "command" PAM execution requires the system.manage permission. Use "Remote SSH Tunnel Relay" or "Simulated" instead.')}
                </div>
              ) : (
                <div className="muted small surface-box" style={{ padding: '6px 10px' }}>
                  {t('Host script execution is enabled (-allow-scripts / DUCKSECRETS_ALLOW_SCRIPTS=1): "local" runs useradd/chpasswd/userdel on the ducksecretsd host; "tunnel" relays SSH traffic cleanly without modifying local OS users.')}
                </div>
              )}

              <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 8 }}>
                <Field label={t('Default Login Shell')}>
                  <select
                    value={pamShell}
                    onChange={(e) =>
                      updatePAM(pamMode, pamHost, pamPort, e.target.value, pamGroups, pamSudo, pamProvCmd, pamRevCmd)
                    }
                  >
                    <option value="/bin/bash">/bin/bash</option>
                    <option value="/bin/zsh">/bin/zsh</option>
                    <option value="/bin/sh">/bin/sh</option>
                    <option value="/usr/sbin/nologin">/usr/sbin/nologin</option>
                  </select>
                </Field>
                <Field label={t('Supplementary Groups')}>
                  <input
                    placeholder="developers,docker"
                    value={pamGroups}
                    onChange={(e) =>
                      updatePAM(pamMode, pamHost, pamPort, pamShell, e.target.value, pamSudo, pamProvCmd, pamRevCmd)
                    }
                  />
                </Field>
              </div>

              <label className="check" style={{ padding: '4px 0' }}>
                <input
                  type="checkbox"
                  checked={pamSudo}
                  onChange={(e) =>
                    updatePAM(pamMode, pamHost, pamPort, pamShell, pamGroups, e.target.checked, pamProvCmd, pamRevCmd)
                  }
                />
                <span>{t('Grant temporary Sudo privileges (via /etc/sudoers.d/ducksecrets-*)')}</span>
              </label>

              {pamMode === 'command' && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 4 }}>
                  <Field
                    label={t('Custom Provisioning Command')}
                    help={t('Use {{username}}, {{password}}, and {{expiry}} placeholders')}
                  >
                    <input
                      className="mono small"
                      placeholder="useradd -m -s /bin/bash {{username}} && echo '{{username}}:{{password}}' | chpasswd"
                      value={pamProvCmd}
                      onChange={(e) =>
                        updatePAM(pamMode, pamHost, pamPort, pamShell, pamGroups, pamSudo, e.target.value, pamRevCmd)
                      }
                    />
                  </Field>

                  <Field label={t('Custom Revocation Command')} help={t('Use {{username}} placeholder')}>
                    <input
                      className="mono small"
                      placeholder="userdel -r -f {{username}}"
                      value={pamRevCmd}
                      onChange={(e) =>
                        updatePAM(pamMode, pamHost, pamPort, pamShell, pamGroups, pamSudo, pamProvCmd, e.target.value)
                      }
                    />
                  </Field>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
