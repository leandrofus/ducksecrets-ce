import type { ReactNode } from 'react'
import { t } from '../i18n'

/** A labelled form control, with optional help below it and optional/required indicator. */
export function Field({
  label,
  children,
  help,
  span,
  optional,
  required,
}: {
  label: ReactNode
  children: ReactNode
  help?: ReactNode
  span?: boolean
  optional?: boolean
  required?: boolean
}) {
  return (
    <label className={`field${span ? ' span-2' : ''}`}>
      <span className="field-label">
        <span className="field-label-main">{label}</span>
        {required && <span className="field-req" title={t('Required')}>*</span>}
        {optional && <span className="field-opt">{t('Optional')}</span>}
      </span>
      {children}
      {help && <small className="help">{help}</small>}
    </label>
  )
}
