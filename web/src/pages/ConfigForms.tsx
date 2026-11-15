import { useState, useEffect } from 'react'
import { t } from '../i18n'
import {
  Sliders,
  Code,
  Plus,
  Trash2,
  Eye,
  EyeOff,
  Terminal,
} from 'lucide-react'
import { Field } from '../ui/Field'

interface ConfigToggleProps {
  mode: 'form' | 'raw'
  onChange: (mode: 'form' | 'raw') => void
  label?: string
}

export function ConfigToggle({ mode, onChange, label }: ConfigToggleProps) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
      {label && <span style={{ fontWeight: 600, fontSize: 13 }}>{label}</span>}
      <div style={{ display: 'inline-flex', padding: 2, background: 'var(--surface-2)', borderRadius: 6, border: '1px solid var(--border)' }}>
        <button
          type="button"
          className={`btn btn-xs ${mode === 'form' ? 'btn-primary' : 'btn-ghost'}`}
          style={{ borderRadius: 4, padding: '2px 8px', fontSize: 12, display: 'inline-flex', alignItems: 'center', gap: 4 }}
          onClick={() => onChange('form')}
        >
          <Sliders size={12} />
          {t('Form View')}
        </button>
        <button
          type="button"
          className={`btn btn-xs ${mode === 'raw' ? 'btn-primary' : 'btn-ghost'}`}
          style={{ borderRadius: 4, padding: '2px 8px', fontSize: 12, display: 'inline-flex', alignItems: 'center', gap: 4 }}
          onClick={() => onChange('raw')}
        >
          <Code size={12} />
          {t('Raw JSON')}
        </button>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------
// HTTP PROBE CONFIG FORM
// ---------------------------------------------------------------------

interface HeaderPair {
  id: string
  key: string
  value: string
}

export function HttpProbeConfigForm({ value, onChange }: { value: string; onChange: (val: string) => void }) {
  const [mode, setMode] = useState<'form' | 'raw'>('form')
  const [url, setUrl] = useState('https://api.example.com/health')
  const [method, setMethod] = useState('GET')
  const [timeout, setTimeoutSec] = useState(5)
  const [headers, setHeaders] = useState<HeaderPair[]>([
    { id: '1', key: 'Authorization', value: 'Bearer {{secret}}' },
  ])

  const syncFromValue = (rawVal: string): boolean => {
    if (!rawVal || rawVal.trim() === '' || rawVal.trim() === '{}') return true
    try {
      const parsed = JSON.parse(rawVal)
      if (parsed.url !== undefined) setUrl(parsed.url)
      if (parsed.method !== undefined) setMethod(parsed.method)
      if (parsed.timeout_seconds !== undefined) setTimeoutSec(Number(parsed.timeout_seconds) || 5)
      if (parsed.headers && typeof parsed.headers === 'object') {
        const pairs: HeaderPair[] = Object.entries(parsed.headers).map(([k, v], idx) => ({
          id: String(idx + 1),
          key: k,
          value: String(v),
        }))
        setHeaders(pairs)
      }
      return true
    } catch {
      return false
    }
  }

  // Parse external JSON string into form state on init or emit initial defaults if empty
  useEffect(() => {
    if (!value || value.trim() === '' || value.trim() === '{}') {
      updateForm(url, method, timeout, headers)
      return
    }
    if (!syncFromValue(value)) {
      setMode('raw')
    }
  }, [])

  const handleModeChange = (nextMode: 'form' | 'raw') => {
    if (nextMode === 'form' && !syncFromValue(value)) {
      setMode('raw')
      return
    }
    setMode(nextMode)
  }

  const updateForm = (nextUrl: string, nextMethod: string, nextTimeout: number, nextHeaders: HeaderPair[]) => {
    setUrl(nextUrl)
    setMethod(nextMethod)
    setTimeoutSec(nextTimeout)
    setHeaders(nextHeaders)

    const headerMap: Record<string, string> = {}
    for (const h of nextHeaders) {
      if (h.key.trim()) {
        headerMap[h.key.trim()] = h.value
      }
    }

    const payload: any = {
      url: nextUrl.trim(),
      method: nextMethod,
      timeout_seconds: nextTimeout,
    }
    if (Object.keys(headerMap).length > 0) {
      payload.headers = headerMap
    }
    onChange(JSON.stringify(payload, null, 2))
  }

  const addHeader = (k = '', v = '') => {
    const next = [...headers, { id: Math.random().toString(36).slice(2), key: k, value: v }]
    updateForm(url, method, timeout, next)
  }

  const removeHeader = (id: string) => {
    const next = headers.filter((h) => h.id !== id)
    updateForm(url, method, timeout, next)
  }

  const changeHeader = (id: string, field: 'key' | 'value', val: string) => {
    const next = headers.map((h) => (h.id === id ? { ...h, [field]: val } : h))
    updateForm(url, method, timeout, next)
  }

  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 8, padding: 12, background: 'var(--surface-1)' }}>
      <ConfigToggle mode={mode} onChange={handleModeChange} label={t('HTTP Health Probe Settings')} />

      {mode === 'raw' ? (
        <Field label={t('Raw JSON Configuration')} help={t('Supports {{secret}} interpolation in headers')}>
          <textarea
            className="mono small"
            rows={6}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            placeholder='{"url": "https://api.example.com/health", "method": "GET", "headers": {"Authorization": "Bearer {{secret}}"}}'
          />
        </Field>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', gap: 8 }}>
            <Field label={t('Method')}>
              <select
                value={method}
                onChange={(e) => updateForm(url, e.target.value, timeout, headers)}
              >
                <option value="GET">GET</option>
                <option value="POST">POST</option>
                <option value="HEAD">HEAD</option>
                <option value="PUT">PUT</option>
                <option value="DELETE">DELETE</option>
              </select>
            </Field>

            <Field label={t('Target URL')}>
              <input
                required
                type="url"
                placeholder="https://api.example.com/health"
                value={url}
                onChange={(e) => updateForm(e.target.value, method, timeout, headers)}
              />
            </Field>
          </div>

          <Field label={t('Probe Timeout (seconds)')} help={t('Maximum time allowed before health check fails')}>
            <input
              type="number"
              min={1}
              max={60}
              value={timeout}
              onChange={(e) => updateForm(url, method, Math.max(1, Number(e.target.value) || 5), headers)}
            />
          </Field>

          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
              <span style={{ fontSize: 13, fontWeight: 500 }}>
                {t('HTTP Request Headers')}
                <span className="muted small" style={{ marginLeft: 8, fontWeight: 400 }}>
                  ({t('Use {{secret}} for candidate secret')})
                </span>
              </span>
              <button type="button" className="btn btn-xs btn-ghost" onClick={() => addHeader()}>
                <Plus size={12} /> {t('Add Header')}
              </button>
            </div>

            {headers.length === 0 ? (
              <p className="muted small" style={{ margin: '4px 0' }}>{t('No custom headers configured.')}</p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {headers.map((h) => (
                  <div key={h.id} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 32px', gap: 6, alignItems: 'center' }}>
                    <input
                      placeholder="Header Name (e.g. Authorization)"
                      value={h.key}
                      onChange={(e) => changeHeader(h.id, 'key', e.target.value)}
                    />
                    <input
                      placeholder="Value (e.g. Bearer {{secret}})"
                      value={h.value}
                      onChange={(e) => changeHeader(h.id, 'value', e.target.value)}
                    />
                    <button
                      type="button"
                      className="icon-btn"
                      style={{ color: '#ef4444' }}
                      title={t('Remove Header')}
                      onClick={() => removeHeader(h.id)}
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>
                ))}
              </div>
            )}

            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 8 }}>
              <span className="muted small" style={{ alignSelf: 'center' }}>{t('Presets:')}</span>
              <button
                type="button"
                className="btn btn-xs btn-ghost"
                onClick={() => addHeader('Authorization', 'Bearer {{secret}}')}
              >
                + Bearer Auth
              </button>
              <button
                type="button"
                className="btn btn-xs btn-ghost"
                onClick={() => addHeader('X-API-Key', '{{secret}}')}
              >
                + X-API-Key
              </button>
              <button
                type="button"
                className="btn btn-xs btn-ghost"
                onClick={() => addHeader('Content-Type', 'application/json')}
              >
                + Content-Type JSON
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------
// TCP PROBE CONFIG FORM
// ---------------------------------------------------------------------

export function TcpProbeConfigForm({ value, onChange }: { value: string; onChange: (val: string) => void }) {
  const [mode, setMode] = useState<'form' | 'raw'>('form')
  const [host, setHost] = useState('127.0.0.1')
  const [port, setPort] = useState('5432')
  const [timeout, setTimeoutSec] = useState(3)

  const syncFromValue = (rawVal: string): boolean => {
    if (!rawVal || rawVal.trim() === '' || rawVal.trim() === '{}') return true
    try {
      const parsed = JSON.parse(rawVal)
      if (parsed.address) {
        const parts = parsed.address.split(':')
        if (parts.length >= 2) {
          setHost(parts.slice(0, -1).join(':'))
          setPort(parts[parts.length - 1])
        } else {
          setHost(parsed.address)
        }
      }
      if (parsed.timeout_seconds !== undefined) {
        setTimeoutSec(Number(parsed.timeout_seconds) || 3)
      }
      return true
    } catch {
      return false
    }
  }

  useEffect(() => {
    if (!value || value.trim() === '' || value.trim() === '{}') {
      updateForm(host, port, timeout)
      return
    }
    if (!syncFromValue(value)) {
      setMode('raw')
    }
  }, [])

  const handleModeChange = (nextMode: 'form' | 'raw') => {
    if (nextMode === 'form' && !syncFromValue(value)) {
      setMode('raw')
      return
    }
    setMode(nextMode)
  }

  const updateForm = (nextHost: string, nextPort: string, nextTimeout: number) => {
    setHost(nextHost)
    setPort(nextPort)
    setTimeoutSec(nextTimeout)

    const payload = {
      address: `${nextHost.trim()}:${nextPort.trim()}`,
      timeout_seconds: nextTimeout,
    }
    onChange(JSON.stringify(payload, null, 2))
  }

  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 8, padding: 12, background: 'var(--surface-1)' }}>
      <ConfigToggle mode={mode} onChange={handleModeChange} label={t('TCP Port Probe Settings')} />

      {mode === 'raw' ? (
        <Field label={t('Raw JSON Configuration')}>
          <textarea
            className="mono small"
            rows={4}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            placeholder='{"address": "127.0.0.1:5432", "timeout_seconds": 3}'
          />
        </Field>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 8 }}>
            <Field label={t('Host / IP Address')}>
              <input
                required
                placeholder="127.0.0.1 or db.internal"
                value={host}
                onChange={(e) => updateForm(e.target.value, port, timeout)}
              />
            </Field>
            <Field label={t('TCP Port')}>
              <input
                required
                type="number"
                min={1}
                max={65535}
                placeholder="5432"
                value={port}
                onChange={(e) => updateForm(host, e.target.value, timeout)}
              />
            </Field>
          </div>

          <Field label={t('Connect Timeout (seconds)')}>
            <input
              type="number"
              min={1}
              max={30}
              value={timeout}
              onChange={(e) => updateForm(host, port, Math.max(1, Number(e.target.value) || 3))}
            />
          </Field>
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------
// SCRIPT PROBE CONFIG FORM
// ---------------------------------------------------------------------

export function ScriptProbeConfigForm({ value, onChange }: { value: string; onChange: (val: string) => void }) {
  const [command, setCommand] = useState('curl -sf http://localhost:8080/health')

  useEffect(() => {
    if (!value || value.trim() === '' || value.trim() === '{}') {
      onChange(JSON.stringify({ command }, null, 2))
      return
    }
    try {
      const parsed = JSON.parse(value)
      if (parsed.command) setCommand(parsed.command)
    } catch {
      setCommand(value)
    }
  }, [])

  const handleCommandChange = (cmd: string) => {
    setCommand(cmd)
    onChange(JSON.stringify({ command: cmd }, null, 2))
  }

  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 8, padding: 12, background: 'var(--surface-1)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
        <Terminal size={14} style={{ color: 'var(--accent)' }} />
        <span style={{ fontWeight: 600, fontSize: 13 }}>{t('Custom Script Health Check')}</span>
      </div>

      <Field
        label={t('Shell Command')}
        help={t('Executed with candidate secret in $DUCKSECRETS_NEW_VALUE environment variable')}
      >
        <textarea
          rows={3}
          className="mono small"
          placeholder="curl -sf http://localhost:8080/health || exit 1"
          value={command}
          onChange={(e) => handleCommandChange(e.target.value)}
        />
      </Field>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 8 }}>
        <span className="muted small" style={{ alignSelf: 'center' }}>{t('Examples:')}</span>
        <button
          type="button"
          className="btn btn-xs btn-ghost"
          onClick={() => handleCommandChange('curl -sf http://localhost:8080/health')}
        >
          curl health
        </button>
        <button
          type="button"
          className="btn btn-xs btn-ghost"
          onClick={() => handleCommandChange('pg_isready -h localhost -p 5432')}
        >
          pg_isready
        </button>
        <button
          type="button"
          className="btn btn-xs btn-ghost"
          onClick={() => handleCommandChange('redis-cli -a "$DUCKSECRETS_NEW_VALUE" ping')}
        >
          redis auth ping
        </button>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------
// DYNAMIC SECRETS ENGINE CONFIG FORM
// ---------------------------------------------------------------------

interface DynamicEngineConfigFormProps {
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
  const [pamMode, setPamMode] = useState('local')
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
        // Parse Go MySQL DSN supporting passwords containing '@' (e.g. user:p@ss@tcp(host:3306)/db)
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

  // Parse initial config or emit initial engine defaults when empty
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

    const payload: any = {
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

    const payload: any = {
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

  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: 8, padding: 12, background: 'var(--surface-1)', marginBottom: 12 }}>
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
          {/* POSTGRESQL FORM */}
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

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
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

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                <Field label={t('Admin Username')}>
                  <input
                    required
                    placeholder="postgres"
                    value={pgUsername}
                    onChange={(e) => updatePostgres(pgHost, pgPort, pgDatabase, e.target.value, pgPassword, pgSSLMode)}
                  />
                </Field>
                <Field label={t('Admin Password')}>
                  <div style={{ position: 'relative' }}>
                    <input
                      type={showPgPass ? 'text' : 'password'}
                      placeholder="Password"
                      value={pgPassword}
                      onChange={(e) => updatePostgres(pgHost, pgPort, pgDatabase, pgUsername, e.target.value, pgSSLMode)}
                    />
                    <button
                      type="button"
                      className="icon-btn"
                      style={{ position: 'absolute', right: 6, top: '50%', transform: 'translateY(-50%)' }}
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

          {/* MYSQL FORM */}
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

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                <Field label={t('Admin Username')}>
                  <input
                    required
                    placeholder="root"
                    value={myUsername}
                    onChange={(e) => updateMySQL(myHost, myPort, myDatabase, e.target.value, myPassword)}
                  />
                </Field>
                <Field label={t('Admin Password')}>
                  <div style={{ position: 'relative' }}>
                    <input
                      type={showMyPass ? 'text' : 'password'}
                      placeholder="Password"
                      value={myPassword}
                      onChange={(e) => updateMySQL(myHost, myPort, myDatabase, myUsername, e.target.value)}
                    />
                    <button
                      type="button"
                      className="icon-btn"
                      style={{ position: 'absolute', right: 6, top: '50%', transform: 'translateY(-50%)' }}
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

          {/* REDIS FORM */}
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

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                <Field label={t('Admin Username (ACL)')}>
                  <input
                    placeholder="default"
                    value={redUsername}
                    onChange={(e) => updateRedis(redHost, redPort, e.target.value, redPassword, redAclRules)}
                  />
                </Field>
                <Field label={t('Admin Password (Optional)')}>
                  <div style={{ position: 'relative' }}>
                    <input
                      type={showRedPass ? 'text' : 'password'}
                      placeholder="Optional"
                      value={redPassword}
                      onChange={(e) => updateRedis(redHost, redPort, redUsername, e.target.value, redAclRules)}
                    />
                    <button
                      type="button"
                      className="icon-btn"
                      style={{ position: 'absolute', right: 6, top: '50%', transform: 'translateY(-50%)' }}
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

          {/* PAM FORM */}
          {engine === 'pam' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <Field label={t('Execution Mode')}>
                <select
                  value={pamMode}
                  onChange={(e) =>
                    updatePAM(e.target.value, pamHost, pamPort, pamShell, pamGroups, pamSudo, pamProvCmd, pamRevCmd)
                  }
                >
                  <option value="local">{t('Local System (Host useradd / userdel via PAM)')}</option>
                  <option value="simulated">{t('Simulated / Safe Dry-Run (Logs commands for testing)')}</option>
                  <option value="command">{t('Custom Provisioning Command Hooks')}</option>
                </select>
              </Field>

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

              <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 0' }}>
                <input
                  type="checkbox"
                  id="pam-sudo"
                  checked={pamSudo}
                  onChange={(e) =>
                    updatePAM(pamMode, pamHost, pamPort, pamShell, pamGroups, e.target.checked, pamProvCmd, pamRevCmd)
                  }
                />
                <label htmlFor="pam-sudo" style={{ fontSize: 13, cursor: 'pointer', margin: 0 }}>
                  {t('Grant temporary Sudo privileges (via /etc/sudoers.d/ducksecrets-*)')}
                </label>
              </div>

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
