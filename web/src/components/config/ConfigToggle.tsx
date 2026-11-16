import { Sliders, Code } from 'lucide-react'
import { t } from '../../i18n'

export interface ConfigToggleProps {
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
          onClick={() => onChange('form')}
        >
          <Sliders size={12} />
          {t('Form View')}
        </button>
        <button
          type="button"
          className={`btn btn-xs ${mode === 'raw' ? 'btn-primary' : 'btn-ghost'}`}
          onClick={() => onChange('raw')}
        >
          <Code size={12} />
          {t('Raw JSON')}
        </button>
      </div>
    </div>
  )
}
