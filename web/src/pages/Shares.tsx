import { useEffect, useState } from 'react'
import { Flame, Plus } from 'lucide-react'
import { api, type ShareMetadata } from '../lib/api'
import { t } from '../i18n'
import { ShareCreateForm } from './shares/ShareCreateForm'
import { ShareCreatedCard } from './shares/ShareCreatedCard'
import { ActiveSharesTable } from './shares/ActiveSharesTable'

export function Shares() {
  const [tab, setTab] = useState<'create' | 'active'>('create')
  const [createdUrl, setCreatedUrl] = useState<string | null>(null)
  const [activeShares, setActiveShares] = useState<ShareMetadata[]>([])
  const [loadingShares, setLoadingShares] = useState(false)

  const loadActiveShares = () => {
    setLoadingShares(true)
    api
      .get<ShareMetadata[]>('/shares')
      .then((data) => {
        setActiveShares(data)
        setLoadingShares(false)
      })
      .catch(() => {
        setLoadingShares(false)
      })
  }

  useEffect(() => {
    if (tab === 'active') {
      loadActiveShares()
    }
  }, [tab])

  return (
    <div className="page narrow">
      <div className="page-head">
        <div className="page-title">
          <Flame size={20} style={{ color: 'var(--accent)' }} />
          <h1>{t('Ephemeral Secret Sharing')}</h1>
        </div>
        <div className="page-actions">
          <button
            className={`btn btn-sm ${tab === 'create' ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => setTab('create')}
          >
            <Plus size={14} />
            <span>{t('New Share')}</span>
          </button>
          <button
            className={`btn btn-sm ${tab === 'active' ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => setTab('active')}
          >
            <Flame size={14} />
            <span>{t('Active Shares')}</span>
          </button>
        </div>
      </div>

      <div className="page-body">
        {tab === 'create' ? (
          <div className="surface-card" style={{ padding: 24 }}>
            {createdUrl ? (
              <ShareCreatedCard
                createdUrl={createdUrl}
                onReset={() => setCreatedUrl(null)}
              />
            ) : (
              <ShareCreateForm onCreated={(url) => setCreatedUrl(url)} />
            )}
          </div>
        ) : (
          <div className="surface-card" style={{ padding: 20 }}>
            <h2 style={{ fontSize: 16, fontWeight: 600, marginBottom: 14 }}>
              {t('Your Active Shares')}
            </h2>
            <ActiveSharesTable
              shares={activeShares}
              loading={loadingShares}
              onRemoved={(id) => setActiveShares((prev) => prev.filter((s) => s.id !== id))}
            />
          </div>
        )}
      </div>
    </div>
  )
}
