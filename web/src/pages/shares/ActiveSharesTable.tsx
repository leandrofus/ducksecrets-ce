import { Copy, Flame, Lock, Trash2 } from 'lucide-react'
import { api, enc, type ShareMetadata } from '../../lib/api'
import { copy, dateTime } from '../../lib/format'
import { t } from '../../i18n'
import { Spinner, Tag } from '../../ui/common'
import { confirm, toast } from '../../ui/overlays'
import { useMenu, type MenuEntry } from '../../ui/ContextMenu'

export function ActiveSharesTable({
  shares,
  loading,
  onRemoved,
}: {
  shares: ShareMetadata[]
  loading: boolean
  onRemoved: (id: string) => void
}) {
  const menu = useMenu()

  const handleDeleteShare = async (id: string) => {
    const ok = await confirm({
      title: t('Revoke share?'),
      body: t('Are you sure you want to revoke this secret share immediately?'),
      danger: true,
      confirm: t('Revoke & Burn'),
    })
    if (!ok) return

    try {
      await api.del(`/shares/${enc(id)}`)
      toast.ok(t('Share revoked successfully.'))
      onRemoved(id)
    } catch (err: any) {
      toast.err(err.message || t('Failed to revoke share.'))
    }
  }

  const shareActions = (s: ShareMetadata): MenuEntry[] => [
    { header: s.id },
    {
      label: t('Copy Share Link Base'),
      icon: <Copy size={14} />,
      onClick: () => {
        copy(`${window.location.origin}/#/share/${enc(s.id)}`).then((ok) => {
          if (ok) toast.ok(t('Share link base copied'))
        })
      },
    },
    'sep',
    {
      label: t('Revoke & Burn immediately'),
      icon: <Trash2 size={14} />,
      danger: true,
      onClick: () => handleDeleteShare(s.id),
    },
  ]

  if (loading) {
    return (
      <div className="center" style={{ padding: 32 }}>
        <Spinner />
      </div>
    )
  }

  if (shares.length === 0) {
    return (
      <div className="empty" style={{ padding: '40px 20px' }}>
        <Flame size={32} style={{ opacity: 0.35, marginBottom: 4 }} />
        <p className="muted">{t('No active shares. All previous shares have been burned or expired.')}</p>
      </div>
    )
  }

  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>{t('Share ID')}</th>
            <th>{t('Views Remaining')}</th>
            <th>{t('Protection')}</th>
            <th>{t('Expires')}</th>
            <th style={{ textAlign: 'right' }}>{t('Actions')}</th>
          </tr>
        </thead>
        <tbody>
          {shares.map((s) => {
            const rem = Math.max(0, s.max_views - s.view_count)
            return (
              <tr key={s.id} onContextMenu={menu(() => shareActions(s))}>
                <td className="mono">{s.id}</td>
                <td>
                  <Tag tone={rem > 0 ? 'accent' : 'muted'} mono>
                    {rem} / {s.max_views}
                  </Tag>
                </td>
                <td>
                  {s.has_passphrase ? (
                    <span className="tone-ok" style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                      <Lock size={12} /> {t('Passphrase')}
                    </span>
                  ) : (
                    <span className="muted">{t('Standard')}</span>
                  )}
                </td>
                <td className="muted small">{dateTime(s.expires_at)}</td>
                <td style={{ textAlign: 'right' }}>
                  <button
                    className="icon-btn tone-bad"
                    title={t('Revoke & Burn immediately')}
                    onClick={() => handleDeleteShare(s.id)}
                  >
                    <Trash2 size={15} />
                  </button>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
