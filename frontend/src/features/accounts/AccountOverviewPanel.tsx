import { Card } from '@/components/common/Card';
import { CopyButton } from '@/components/common/CopyButton';
import { KeyValueList } from '@/components/common/KeyValueList';
import { ACCOUNT_STATUS_HINTS } from '@/lib/constants';
import { formatDateTime } from '@/lib/dates';
import { formatCellValue, humaniseField } from '@/lib/formatters';
import type { Account } from '@/types/account';

export interface AccountOverviewPanelProps {
  account?: Account;
  isLoading?: boolean;
}

/**
 * The account record itself.
 *
 * The status row carries its own explanation, because this is where a reader
 * is most likely to misattribute it. "Review required" is the source system's
 * flag; MuleGuard neither sets it nor acts on it, and a reader who assumes
 * otherwise may believe the platform has taken action against an account.
 */
export function AccountOverviewPanel({ account, isLoading }: AccountOverviewPanelProps) {
  return (
    <Card title="Account">
      <KeyValueList
        columns={2}
        entries={[
          {
            label: 'Identifier',
            value: account ? (
              <span className="flex items-center gap-1">
                <span className="font-mono text-xs">{account.id}</span>
                <CopyButton value={account.id} label={`Copy account id ${account.id}`} />
              </span>
            ) : isLoading ? (
              '…'
            ) : (
              '—'
            ),
            wide: true,
          },
          { label: 'Type', value: account ? humaniseField(account.account_type) : '—' },
          {
            label: 'Source status',
            value: account ? humaniseField(account.status) : '—',
            help: account
              ? (ACCOUNT_STATUS_HINTS[account.status] ??
                'As reported by the source system. MuleGuard does not set it.')
              : undefined,
          },
          { label: 'Opened', value: formatDateTime(account?.created_at) },
          {
            label: 'First recorded here',
            value: formatDateTime(account?.record_created_at),
            help: 'When this account was loaded into MuleGuard, which is usually later than it was opened.',
          },
          {
            label: 'Evidence reference',
            value: account ? (
              <span className="flex items-center gap-1">
                <span className="font-mono text-2xs">ACCOUNT:{account.id}</span>
                <CopyButton value={`ACCOUNT:${account.id}`} label="Copy evidence reference" />
              </span>
            ) : (
              '—'
            ),
            wide: true,
          },
        ]}
      />

      {account?.metadata_json && Object.keys(account.metadata_json).length > 0 ? (
        <div className="mt-4 border-t border-ink-200 pt-3 dark:border-ink-700">
          <h3 className="mb-1.5 text-2xs font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
            Source system fields
          </h3>
          <dl className="space-y-1">
            {Object.entries(account.metadata_json).map(([key, value]) => (
              <div key={key} className="flex gap-2 text-2xs">
                <dt className="shrink-0 font-medium text-ink-600 dark:text-ink-300">
                  {humaniseField(key)}
                </dt>
                <dd className="min-w-0 break-words font-mono text-ink-800 dark:text-ink-100">
                  {formatCellValue(value)}
                </dd>
              </div>
            ))}
          </dl>
        </div>
      ) : null}
    </Card>
  );
}
