import { useState, useEffect } from 'react'
import { Plus, Trash2, Terminal } from 'lucide-react'
import { t } from '../../i18n'
import { can, getMe } from '../../lib/session'
import { Field } from '../../ui/Field'
import { ConfigToggle } from './ConfigToggle'

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

    const payload: Record<string, unknown> = {
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
    <div className="config-box">
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
                      className="icon-btn tone-bad"
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
    <div className="config-box">
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

export function ScriptProbeConfigForm({ value, onChange }: { value: string; onChange: (val: string) => void }) {
  const [command, setCommand] = useState('curl -sf http://localhost:8080/health')
  const allowScripts = Boolean(getMe()?.allow_scripts)
  const canManageSystem = can('system.manage')

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
    <div className="config-box">
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
        <Terminal size={14} style={{ color: 'var(--accent)' }} />
        <span style={{ fontWeight: 600, fontSize: 13 }}>{t('Custom Script Health Check')}</span>
      </div>

      {(!allowScripts || !canManageSystem) ? (
        <div className="alert alert-warn small" style={{ marginBottom: 10 }}>
          {!allowScripts
            ? t('Custom script probes are disabled on this server. Start ducksecretsd with -allow-scripts or set DUCKSECRETS_ALLOW_SCRIPTS=1 in /etc/ducksecrets/env to enable them.')
            : t('Configuring custom script probes requires the system.manage permission.')}
        </div>
      ) : (
        <div className="muted small surface-box" style={{ marginBottom: 10, padding: '6px 10px' }}>
          {t('Host script execution is enabled on this server (-allow-scripts / DUCKSECRETS_ALLOW_SCRIPTS=1).')}
        </div>
      )}

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
