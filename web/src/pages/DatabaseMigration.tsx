import { t } from '../i18n'
import { useState } from 'react'
import { Database, CheckCircle2, AlertCircle, RefreshCw, ArrowRight } from 'lucide-react'
import { api } from '../lib/api'
import type { DatabaseInfo, TestDatabaseResponse, MigrateDatabaseResponse } from '../lib/api'
import { invalidate, useResource } from '../lib/store'
import { Field } from '../ui/Field'
import { Spinner, Tag } from '../ui/common'
import { confirm, toast } from '../ui/overlays'

export function DatabaseMigration() {
  const { data: info, error, loading } = useResource<DatabaseInfo>('/system/database')
  const [pgUrl, setPgUrl] = useState('')
  const [testing, setTesting] = useState(false)
  const [testResult, setTestResult] = useState<TestDatabaseResponse | null>(null)
  const [testErr, setTestErr] = useState<string | null>(null)
  const [migrating, setMigrating] = useState(false)
  const [migrationReport, setMigrationReport] = useState<MigrateDatabaseResponse | null>(null)

  const testConnection = async () => {
    if (!pgUrl.trim()) return
    setTesting(true)
    setTestResult(null)
    setTestErr(null)
    try {
      const res = await api.post<TestDatabaseResponse>('/system/database/test', {
        postgres_url: pgUrl.trim(),
      })
      setTestResult(res)
    } catch (err: any) {
      setTestErr(err.message || 'Connection failed')
    } finally {
      setTesting(false)
    }
  }

  const runMigration = async () => {
    if (!pgUrl.trim()) return
    if (
      !(await confirm({
        title: t('Migrate to PostgreSQL?'),
        body: t(
          'This will copy all existing projects, encrypted secrets, users, sessions, and audit events to the target PostgreSQL database and hot-swap the active connection. This operation cannot be reversed.'
        ),
        confirm: t('Start Migration'),
      }))
    ) {
      return
    }

    setMigrating(true)
    setMigrationReport(null)
    try {
      const res = await api.post<MigrateDatabaseResponse>('/system/database/migrate', {
        postgres_url: pgUrl.trim(),
      })
      setMigrationReport(res)
      toast.ok(t('Successfully migrated to PostgreSQL!'))
      invalidate('/system/database')
    } catch (err: any) {
      toast.err(err)
    } finally {
      setMigrating(false)
    }
  }

  return (
    <div className="page">
      <div className="page-head">
        <div className="page-title">
          <Database size={22} />
          <h1>{t('Database Engine')}</h1>
          {loading && <Spinner />}
        </div>
      </div>

      <div className="page-body" style={{ maxWidth: 720 }}>
        {error && <div className="alert alert-bad">{error.message}</div>}

        <div style={{ border: '1px solid var(--border)', borderRadius: 8, padding: 20, marginBottom: 24, background: 'var(--bg-subtle)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div>
              <h3 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
                {info?.engine === 'postgres' ? 'PostgreSQL' : 'SQLite (WAL mode)'}
                <Tag tone={info?.engine === 'postgres' ? 'accent' : 'ok'}>
                  {info?.engine === 'postgres' ? t('Production Engine') : t('Default Zero-Config')}
                </Tag>
              </h3>
              <p className="muted small" style={{ margin: '6px 0 0' }}>
                {info?.engine === 'postgres'
                  ? t('DuckSecrets is operating on high-availability PostgreSQL with concurrent advisory write locks.')
                  : t('DuckSecrets started zero-config on embedded SQLite. You can migrate to PostgreSQL without downtime at any time.')}
              </p>
            </div>
            <button className="icon-btn" title={t('Refresh')} onClick={() => invalidate('/system/database')}>
              <RefreshCw size={15} />
            </button>
          </div>
        </div>

        {info?.is_postgres && (
          <div className="alert alert-ok" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <CheckCircle2 size={18} />
            <span>{t('Your DuckSecrets instance is already running on PostgreSQL.')}</span>
          </div>
        )}

        {info?.can_migrate && (
          <div style={{ border: '1px solid var(--border)', borderRadius: 8, padding: 20, background: 'var(--bg)' }}>
            <h3 style={{ marginTop: 0 }}>{t('Migrate to PostgreSQL')}</h3>
            <p className="muted small" style={{ marginBottom: 16 }}>
              {t(
                'Enter your target PostgreSQL connection string. The migration will initialize tables, stream all existing records, verify row counts, and hot-swap the daemon to PostgreSQL.'
              )}
            </p>

            <Field
              label={t('PostgreSQL Connection URL')}
              help={t('e.g. postgres://user:password@db.example.com:5432/ducksecrets?sslmode=require')}
            >
              <input
                className="mono"
                style={{ fontSize: 13 }}
                value={pgUrl}
                onChange={(e) => {
                  setPgUrl(e.target.value)
                  setTestResult(null)
                  setTestErr(null)
                }}
                placeholder="postgres://user:password@localhost:5432/ducksecrets?sslmode=disable"
              />
            </Field>

            {testResult && (
              <div className="alert alert-ok" style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
                <CheckCircle2 size={16} />
                <span>{testResult.message}</span>
              </div>
            )}

            {testErr && (
              <div className="alert alert-bad" style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
                <AlertCircle size={16} />
                <span>{testErr}</span>
              </div>
            )}

            {migrationReport && (
              <div className="alert alert-ok" style={{ marginTop: 16 }}>
                <strong>{t('Migration Completed!')}</strong>
                <p style={{ margin: '4px 0 0' }}>{migrationReport.message}</p>
                <p className="muted small" style={{ marginTop: 8 }}>
                  {t('To make this permanent across daemon restarts, set DUCKSECRETS_DB in your environment.')}
                </p>
              </div>
            )}

            <div style={{ display: 'flex', gap: 10, marginTop: 20, justifyContent: 'flex-end' }}>
              <button
                type="button"
                className="btn btn-sm"
                onClick={testConnection}
                disabled={testing || migrating || !pgUrl.trim()}
              >
                {testing ? <Spinner /> : t('Test Connection')}
              </button>

              <button
                type="button"
                className="btn btn-primary btn-sm"
                onClick={runMigration}
                disabled={testing || migrating || !pgUrl.trim()}
              >
                {migrating ? <Spinner /> : <><ArrowRight size={14} /> {t('Migrate Database')}</>}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
