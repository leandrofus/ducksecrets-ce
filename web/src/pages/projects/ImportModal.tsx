import { useState, useMemo } from 'react'
import { Upload, Eye, EyeOff, Search, X, Trash2 } from 'lucide-react'
import { t } from '../../i18n'
import { api, enc, type Secret, type ImportSecretsResponse, type ImportSecretItem } from '../../lib/api'
import { parseEnvContent, type ParsedSecretItem } from '../../lib/env'
import { invalidate } from '../../lib/store'
import { Spinner, Tag } from '../../ui/common'
import { Modal, toast } from '../../ui/overlays'
import { Field } from '../../ui/Field'

export function ImportModal({
  projectId,
  envSlug,
  existingSecrets,
  onClose,
}: {
  projectId: string
  envSlug: string
  existingSecrets: Secret[]
  onClose: () => void
}) {
  const [step, setStep] = useState<'paste' | 'select'>('paste')
  const [rawText, setRawText] = useState('')
  const [targetPath, setTargetPath] = useState('/')
  const [overwrite, setOverwrite] = useState(true)
  const [items, setItems] = useState<ParsedSecretItem[]>([])
  const [filterQuery, setFilterQuery] = useState('')
  const [showValues, setShowValues] = useState(false)
  const [busy, setBusy] = useState(false)

  const existingKeyMap = useMemo(() => {
    const map = new Map<string, Secret>()
    for (const s of existingSecrets) {
      map.set(s.key, s)
    }
    return map
  }, [existingSecrets])

  const handleParse = (e: React.FormEvent) => {
    e.preventDefault()
    const parsed = parseEnvContent(rawText)
    if (parsed.length === 0) {
      toast.err(t('No valid key-value pairs or secrets found in pasted content'))
      return
    }
    const newItems: ParsedSecretItem[] = parsed.map((p, idx) => ({
      id: `${p.key}_${idx}_${Date.now()}`,
      key: p.key,
      value: p.value,
      comment: p.comment,
      selected: true,
    }))
    setItems(newItems)
    setStep('select')
  }

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (ev) => {
      const text = ev.target?.result
      if (typeof text === 'string') {
        setRawText(text)
      }
    }
    reader.readAsText(file)
  }

  const toggleSelectAll = () => {
    const allSelected = items.every((i) => i.selected)
    setItems(items.map((i) => ({ ...i, selected: !allSelected })))
  }

  const toggleItem = (id: string) => {
    setItems(items.map((i) => (i.id === id ? { ...i, selected: !i.selected } : i)))
  }

  const removeItem = (id: string) => {
    setItems(items.filter((i) => i.id !== id))
  }

  const updateItemKey = (id: string, newKey: string) => {
    setItems(items.map((i) => (i.id === id ? { ...i, key: newKey } : i)))
  }

  const updateItemValue = (id: string, newVal: string) => {
    setItems(items.map((i) => (i.id === id ? { ...i, value: newVal } : i)))
  }

  const selectedCount = items.filter((i) => i.selected).length
  const newCount = items.filter((i) => i.selected && !existingKeyMap.has(i.key)).length
  const overwriteCount = items.filter((i) => i.selected && existingKeyMap.has(i.key)).length

  const filteredItems = useMemo(() => {
    const q = filterQuery.toLowerCase().trim()
    if (!q) return items
    return items.filter((i) => i.key.toLowerCase().includes(q) || i.value.toLowerCase().includes(q))
  }, [items, filterQuery])

  const submitImport = async () => {
    const selected = items.filter((i) => i.selected)
    if (selected.length === 0) {
      toast.err(t('Please select at least one secret to import'))
      return
    }
    setBusy(true)
    try {
      const res = await api.post<ImportSecretsResponse>(
        `/projects/${enc(projectId)}/environments/${enc(envSlug)}/secrets/import`,
        {
          path: targetPath,
          overwrite,
          secrets: selected.map((s): ImportSecretItem => ({
            key: s.key,
            value: s.value,
            comment: s.comment,
          })),
        }
      )
      invalidate('/projects')
      toast.ok(
        t('Successfully imported {0} secrets ({1} created, {2} updated)', res.total, res.created, res.updated)
      )
      onClose()
    } catch (err: unknown) {
      toast.err(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      title={step === 'paste' ? t('Import Secrets into {0}', envSlug) : t('Select Secrets to Import ({0} found)', items.length)}
      wide
      onClose={onClose}
    >
      {step === 'paste' ? (
        <form onSubmit={handleParse}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
            <span className="muted small">
              {t('Paste your .env, JSON, or YAML content, or choose a file from your computer:')}
            </span>
            <label className="btn btn-xs btn-ghost" style={{ cursor: 'pointer', margin: 0 }}>
              <Upload size={12} />
              {t('Choose File…')}
              <input type="file" style={{ display: 'none' }} accept=".env*,.txt,.json,.yaml,.yml" onChange={handleFileUpload} />
            </label>
          </div>

          <Field label={t('.env or Key-Value Content')}>
            <textarea
              required
              autoFocus
              className="mono"
              rows={12}
              style={{ fontSize: 13, width: '100%' }}
              placeholder={`# Paste your .env file here\nPORT=8080\nDATABASE_URL="postgres://user:password@localhost:5432/app"\nAPI_KEY=sk_live_123456789`}
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
            />
          </Field>

          <div className="grid-2" style={{ marginTop: 12 }}>
            <Field label={t('Target Path / Folder')} help={t('Default root path /')}>
              <input value={targetPath} onChange={(e) => setTargetPath(e.target.value)} placeholder="/" />
            </Field>

            <label className="check" style={{ alignSelf: 'center', marginTop: 12 }}>
              <input
                type="checkbox"
                checked={overwrite}
                onChange={(e) => setOverwrite(e.target.checked)}
              />
              <span>{t('Overwrite existing secrets (creates new version)')}</span>
            </label>
          </div>

          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
            <button type="button" className="btn btn-ghost" onClick={onClose}>{t('Cancel')}</button>
            <button type="submit" className="btn btn-primary" disabled={!rawText.trim()}>
              {t('Parse Secrets & Select →')}
            </button>
          </div>
        </form>
      ) : (
        <div>
          <div
            className="surface-box"
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '10px 12px',
              marginBottom: 12,
              fontSize: 13,
            }}
          >
            <div>
              <strong>{t('{0} selected', selectedCount)}</strong>
              <span className="muted" style={{ marginLeft: 8 }}>
                ({newCount} {t('new')}, {overwriteCount} {t('will overwrite')})
              </span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <button type="button" className="btn btn-xs btn-ghost" onClick={toggleSelectAll}>
                {items.every((i) => i.selected) ? t('Deselect All') : t('Select All')}
              </button>
              <button type="button" className="btn btn-xs btn-ghost" onClick={() => setShowValues(!showValues)}>
                {showValues ? <EyeOff size={12} /> : <Eye size={12} />} {showValues ? t('Hide Values') : t('Show Values')}
              </button>
            </div>
          </div>

          <div style={{ marginBottom: 10 }}>
            <div className="search" style={{ width: '100%' }}>
              <Search size={14} />
              <input
                placeholder={t('Filter parsed secrets…')}
                value={filterQuery}
                onChange={(e) => setFilterQuery(e.target.value)}
              />
              {filterQuery && (
                <button type="button" className="icon-btn" onClick={() => setFilterQuery('')}>
                  <X size={13} />
                </button>
              )}
            </div>
          </div>

          <div
            style={{
              maxHeight: 380,
              overflowY: 'auto',
              border: '1px solid var(--border)',
              borderRadius: 6,
              background: 'var(--surface)',
            }}
          >
            <table className="table" style={{ margin: 0 }}>
              <thead>
                <tr>
                  <th style={{ width: 36, textAlign: 'center' }}>
                    <input
                      type="checkbox"
                      checked={items.length > 0 && items.every((i) => i.selected)}
                      onChange={toggleSelectAll}
                    />
                  </th>
                  <th style={{ width: 220 }}>{t('Key')}</th>
                  <th>{t('Value')}</th>
                  <th style={{ width: 120 }}>{t('Status')}</th>
                  <th style={{ width: 36 }} />
                </tr>
              </thead>
              <tbody>
                {filteredItems.map((item) => {
                  const existing = existingKeyMap.get(item.key)
                  return (
                    <tr key={item.id} style={{ opacity: item.selected ? 1 : 0.5 }}>
                      <td style={{ textAlign: 'center' }}>
                        <input
                          type="checkbox"
                          checked={item.selected}
                          onChange={() => toggleItem(item.id)}
                        />
                      </td>
                      <td>
                        <input
                          className="mono"
                          style={{ fontSize: 13, fontWeight: 600, padding: '2px 6px' }}
                          value={item.key}
                          onChange={(e) => updateItemKey(item.id, e.target.value.toUpperCase())}
                        />
                      </td>
                      <td>
                        <input
                          type={showValues ? 'text' : 'password'}
                          className="mono"
                          style={{ fontSize: 13, padding: '2px 6px', width: '100%' }}
                          value={item.value}
                          onChange={(e) => updateItemValue(item.id, e.target.value)}
                        />
                      </td>
                      <td>
                        {existing ? (
                          <Tag tone="warn" title={t('Already exists (v{0}). Importing will create v{1}.', existing.version, existing.version + 1)}>
                            {t('OVERWRITE')}
                          </Tag>
                        ) : (
                          <Tag tone="good">
                            {t('NEW')}
                          </Tag>
                        )}
                      </td>
                      <td style={{ textAlign: 'center' }}>
                        <button
                          type="button"
                          className="icon-btn tone-bad"
                          title={t('Remove from import')}
                          onClick={() => removeItem(item.id)}
                        >
                          <Trash2 size={13} />
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 16 }}>
            <button type="button" className="btn btn-ghost" onClick={() => setStep('paste')}>
              {t('← Edit Raw Text')}
            </button>
            <div style={{ display: 'flex', gap: 8 }}>
              <button type="button" className="btn btn-ghost" onClick={onClose}>
                {t('Cancel')}
              </button>
              <button
                type="button"
                className="btn btn-primary"
                disabled={busy || selectedCount === 0}
                onClick={submitImport}
              >
                {busy ? <Spinner /> : t('Import {0} Secrets', selectedCount)}
              </button>
            </div>
          </div>
        </div>
      )}
    </Modal>
  )
}
