import { KeyRound } from 'lucide-react'
import { t } from '../i18n'
import { CredentialsListView } from './credentials/CredentialsListView'

export { CredentialModal } from './credentials/CredentialModal'
export { CredentialsListView } from './credentials/CredentialsListView'

export function Credentials() {
  return (
    <div className="page">
      <div className="page-head">
        <div className="page-title">
          <KeyRound size={20} />
          <h1>{t('Credentials Vault')}</h1>
        </div>
      </div>

      <div className="page-body">
        <CredentialsListView />
      </div>
    </div>
  )
}
