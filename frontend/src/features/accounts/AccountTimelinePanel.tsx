import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';

import { TransactionsActivityChart } from '@/components/charts/TransactionsActivityChart';
import { Card } from '@/components/common/Card';
import { DataTable, type Column } from '@/components/common/DataTable';
import { ErrorState } from '@/components/common/ErrorState';
import { Pagination } from '@/components/common/Pagination';
import { StatusPill } from '@/components/common/StatusPill';
import { useApiError } from '@/hooks/useApiError';
import { formatAmount } from '@/lib/amounts';
import { CHANNEL_LABELS } from '@/lib/constants';
import { formatDateTime } from '@/lib/dates';
import { truncateId } from '@/lib/formatters';
import { queryKeys } from '@/lib/queryKeys';
import { pageInfo } from '@/types/common';
import { isFundMovement, type AccountTransaction } from '@/types/transaction';

import { fetchAccountTransactions } from '@/features/transactions/transactionsApi';

export interface AccountTimelinePanelProps {
  accountId: string;
  page: number;
  pageSize: number;
  onPageChange: (page: number) => void;
  onPageSizeChange: (pageSize: number) => void;
  /** Open the full detail drawer for one row. */
  onSelect?: (transactionId: string) => void;
}

/**
 * The account's own transactions, in and out.
 *
 * This endpoint returns direction and counterparty rather than sender and
 * receiver, because the request named the account they are relative to — which
 * is exactly what a reader of one account's timeline wants. The chart above
 * the table is built from the same page of rows, so it describes what is on
 * screen rather than a separate aggregate that might disagree with it.
 */
export function AccountTimelinePanel({
  accountId,
  page,
  pageSize,
  onPageChange,
  onPageSizeChange,
  onSelect,
}: AccountTimelinePanelProps) {
  const query = useQuery({
    queryKey: queryKeys.accounts.transactions(accountId, page, { account_id: accountId }),
    queryFn: () =>
      fetchAccountTransactions(accountId, {
        page,
        page_size: pageSize,
        sort_by: 'occurred_at',
        sort_order: 'desc',
      }),
  });

  const error = useApiError(query.error);
  const rows = useMemo(() => query.data?.items ?? [], [query.data?.items]);

  /**
   * Daily buckets from the rows on screen.
   *
   * Only completed transfers contribute to the value series: adding a failed
   * transfer's amount to a daily total would produce a figure that disagrees
   * with every aggregate elsewhere in the platform.
   */
  const buckets = useMemo(() => {
    const byDay = new Map<string, { count: number; value: number }>();

    for (const row of rows) {
      const day = row.occurred_at.slice(0, 10);
      const entry = byDay.get(day) ?? { count: 0, value: 0 };

      entry.count += 1;
      if (isFundMovement(row)) entry.value += row.amount;

      byDay.set(day, entry);
    }

    return [...byDay.entries()]
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([bucket, entry]) => ({ bucket, count: entry.count, value: entry.value }));
  }, [rows]);

  const columns: Array<Column<AccountTransaction>> = [
    {
      key: 'occurred_at',
      header: 'Occurred',
      render: (row) => (
        <span className="whitespace-nowrap text-xs tabular text-ink-700 dark:text-ink-200">
          {formatDateTime(row.occurred_at)}
        </span>
      ),
      width: '19%',
    },
    {
      key: 'direction',
      header: 'Direction',
      render: (row) => (
        <span className="text-xs">
          {row.direction === 'inbound' ? (
            <span className="text-ink-700 dark:text-ink-200">In</span>
          ) : row.direction === 'outbound' ? (
            <span className="text-ink-700 dark:text-ink-200">Out</span>
          ) : (
            <span className="text-ink-500 dark:text-ink-400">Self</span>
          )}
        </span>
      ),
      width: '10%',
    },
    {
      key: 'counterparty_account_id',
      header: 'Counterparty',
      render: (row) =>
        row.counterparty_account_id ? (
          <span className="font-mono text-xs" title={row.counterparty_account_id}>
            {truncateId(row.counterparty_account_id, 8)}
          </span>
        ) : (
          <span className="text-2xs text-ink-400 dark:text-ink-500">—</span>
        ),
      width: '17%',
    },
    {
      key: 'amount',
      header: 'Amount',
      numeric: true,
      render: (row) => (
        <span className="whitespace-nowrap text-xs font-medium">
          {formatAmount(row.amount, row.currency)}
        </span>
      ),
      width: '17%',
    },
    {
      key: 'channel',
      header: 'Channel',
      render: (row) => (
        <span className="text-xs text-ink-700 dark:text-ink-200">
          {CHANNEL_LABELS[row.channel] ?? row.channel}
        </span>
      ),
      hideOnSmall: true,
      width: '11%',
    },
    {
      key: 'status',
      header: 'Status',
      render: (row) => <StatusPill kind="transaction" value={row.status} />,
      width: '13%',
    },
    {
      key: 'reference',
      header: 'Reference',
      render: (row) => (
        <span className="font-mono text-2xs text-ink-600 dark:text-ink-300" title={row.reference}>
          {truncateId(row.reference, 8)}
        </span>
      ),
      hideOnSmall: true,
      width: '13%',
    },
  ];

  return (
    <Card
      title="Transactions"
      description="This account's own ledger, with direction relative to it."
      caveats={query.data?.caveats}
      flush
    >
      <div className="px-4 pt-4">
        {error ? (
          <ErrorState error={error} onRetry={() => void query.refetch()} compact />
        ) : (
          <TransactionsActivityChart
            buckets={buckets}
            granularity="day"
            isLoading={query.isLoading}
            height={180}
          />
        )}
        <p className="mt-1 text-2xs text-ink-500 dark:text-ink-400">
          Built from the rows on this page, so it moves with the pager. The value line counts
          completed transfers only.
        </p>
      </div>

      <div className="mt-3">
        <DataTable
          caption="Transactions involving this account"
          columns={columns}
          rows={rows}
          rowKey={(row) => row.id}
          isLoading={query.isLoading}
          isRefetching={query.isRefetching}
          onRowClick={onSelect ? (row) => onSelect(row.id) : undefined}
          emptyTitle="No transactions recorded"
          emptyMessage="This account has no transactions in the ledger."
        />

        {query.data ? (
          <Pagination
            meta={pageInfo(query.data)!}
            onPageChange={onPageChange}
            onPageSizeChange={onPageSizeChange}
            requestedPageSize={pageSize}
          />
        ) : null}
      </div>
    </Card>
  );
}
