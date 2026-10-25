import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';

import { Badge } from '@/components/common/Badge';
import { Drawer } from '@/components/common/Drawer';
import { ErrorState } from '@/components/common/ErrorState';
import { KeyValueList } from '@/components/common/KeyValueList';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { StatusPill } from '@/components/common/StatusPill';
import { useApiError } from '@/hooks/useApiError';
import { formatAmount } from '@/lib/amounts';
import { formatDateTime } from '@/lib/dates';
import { formatCellValue, humaniseField, truncateId } from '@/lib/formatters';
import { queryKeys } from '@/lib/queryKeys';
import { paths } from '@/routes/paths';

import { TransactionEvidencePanel } from './TransactionEvidencePanel';
import { fetchTransaction } from './transactionsApi';

export interface TransactionDetailDrawerProps {
  transactionId: string | null;
  onClose: () => void;
}

/**
 * One transaction, in a side panel.
 *
 * A drawer rather than a page: a transaction is almost always looked at while
 * scanning a list, and losing the list to open one row means losing the place
 * in it. Closing returns to the same scroll position and the same filters.
 *
 * `metadata_json` is rendered as whatever it holds. It comes from the source
 * system and its shape varies by deployment, so the panel prints the keys it
 * finds rather than assuming a schema it cannot rely on.
 */
export function TransactionDetailDrawer({
  transactionId,
  onClose,
}: TransactionDetailDrawerProps) {
  const query = useQuery({
    queryKey: queryKeys.transactions.detail(transactionId ?? ''),
    queryFn: () => fetchTransaction(transactionId!),
    enabled: Boolean(transactionId),
  });

  const error = useApiError(query.error);
  const detail = query.data;
  const transaction = detail?.transaction;

  return (
    <Drawer
      open={Boolean(transactionId)}
      onClose={onClose}
      title="Transaction"
      width="lg"
    >
      {query.isLoading ? (
        <LoadingSpinner label="Loading transaction" />
      ) : error ? (
        <ErrorState error={error} onRetry={() => void query.refetch()} />
      ) : !transaction ? null : (
        <div className="space-y-5">
          <KeyValueList
            columns={2}
            entries={[
              { label: 'Amount', value: formatAmount(transaction.amount, transaction.currency), mono: true },
              { label: 'Status', value: <StatusPill kind="transaction" value={transaction.status} /> },
              { label: 'Occurred', value: formatDateTime(transaction.occurred_at) },
              { label: 'Recorded', value: formatDateTime(transaction.record_created_at) },
              {
                label: 'Sender',
                value: (
                  <Link
                    to={paths.account(transaction.sender_account_id)}
                    className="font-mono text-accent-700 hover:underline dark:text-accent-300"
                  >
                    {truncateId(transaction.sender_account_id, 10)}
                  </Link>
                ),
              },
              {
                label: 'Receiver',
                value: (
                  <Link
                    to={paths.account(transaction.receiver_account_id)}
                    className="font-mono text-accent-700 hover:underline dark:text-accent-300"
                  >
                    {truncateId(transaction.receiver_account_id, 10)}
                  </Link>
                ),
              },
            ]}
          />

          {detail?.sender_account || detail?.receiver_account ? (
            <div className="border-t border-ink-200 pt-3 dark:border-ink-700">
              <h3 className="mb-1.5 text-2xs font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
                Accounts
              </h3>
              <ul className="space-y-1.5">
                {(
                  [
                    ['Sender', detail.sender_account],
                    ['Receiver', detail.receiver_account],
                  ] as const
                ).map(([side, account]) =>
                  account ? (
                    <li key={side} className="flex flex-wrap items-center gap-2 text-2xs">
                      <span className="font-semibold text-ink-600 dark:text-ink-300">{side}</span>
                      <Link
                        to={paths.account(account.id)}
                        className="font-mono text-accent-700 hover:underline dark:text-accent-300"
                      >
                        {truncateId(account.id, 10)}
                      </Link>
                      <Badge tone="neutral">{humaniseField(account.account_type)}</Badge>
                      <Badge
                        tone="neutral"
                        title="As reported by the source system. MuleGuard does not set it."
                      >
                        {humaniseField(account.status)}
                      </Badge>
                      <span className="text-ink-500 dark:text-ink-400">
                        opened {formatDateTime(account.created_at)}
                      </span>
                    </li>
                  ) : null,
                )}
              </ul>
            </div>
          ) : null}

          <div className="border-t border-ink-200 pt-3 dark:border-ink-700">
            <h3 className="mb-1.5 text-2xs font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
              As evidence
            </h3>
            <TransactionEvidencePanel
              transactionId={transaction.id}
              transaction={transaction}
            />
          </div>

          {transaction.metadata_json && Object.keys(transaction.metadata_json).length > 0 ? (
            <div className="border-t border-ink-200 pt-3 dark:border-ink-700">
              <h3 className="mb-1.5 text-2xs font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
                Source system fields
              </h3>
              <dl className="space-y-1">
                {Object.entries(transaction.metadata_json).map(([key, value]) => (
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
              <p className="mt-2 text-2xs text-ink-500 dark:text-ink-400">
                Carried through from the source system unchanged. MuleGuard does not interpret
                these fields and does not score on them.
              </p>
            </div>
          ) : null}

          {detail?.caveats && detail.caveats.length > 0 ? (
            <ul className="space-y-1 border-t border-ink-200 pt-3 dark:border-ink-700">
              {detail.caveats.map((caveat) => (
                <li key={caveat} className="text-2xs text-ink-600 dark:text-ink-300">
                  — {caveat}
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      )}
    </Drawer>
  );
}
