import { Link } from 'react-router-dom';

import { Badge } from '@/components/common/Badge';
import { DataTable, type Column } from '@/components/common/DataTable';
import { StatusPill } from '@/components/common/StatusPill';
import { formatAmount } from '@/lib/amounts';
import { CHANNEL_LABELS } from '@/lib/constants';
import { formatDateTime } from '@/lib/dates';
import { truncateId } from '@/lib/formatters';
import { paths } from '@/routes/paths';
import { directionFor, isFundMovement, type Transaction } from '@/types/transaction';

export interface TransactionsTableProps {
  rows: Transaction[];
  isLoading?: boolean;
  isRefetching?: boolean;
  sortBy?: string | null;
  sortOrder?: 'asc' | 'desc';
  onSortChange?: (key: string, order: 'asc' | 'desc') => void;
  onRowClick?: (row: Transaction) => void;
  selectedId?: string | null;
  /** When set, direction is shown relative to this account. */
  perspectiveAccountId?: string | null;
  emptyMessage?: string;
}

/**
 * The transaction ledger.
 *
 * The column that earns its place is "Counts in totals". It is derived, not
 * served: the API returns a status, and only `COMPLETED` is fund movement.
 * Every aggregate in the platform applies that rule, so an analyst who sums
 * the amount column by eye and compares it to the dashboard would otherwise
 * find a discrepancy with no way to explain it. The rule is stated on the row.
 *
 * Direction is likewise derived, and only where it means something. The global
 * ledger has no direction — a transfer is outbound for one party and inbound
 * for the other — so the sign appears only when the view names the account it
 * is relative to.
 */
export function TransactionsTable({
  rows,
  isLoading,
  isRefetching,
  sortBy,
  sortOrder,
  onSortChange,
  onRowClick,
  selectedId,
  perspectiveAccountId,
  emptyMessage,
}: TransactionsTableProps) {
  const columns: Array<Column<Transaction>> = [
    {
      key: 'occurred_at',
      header: 'Occurred',
      sortable: true,
      render: (row) => (
        <span className="text-xs tabular text-ink-700 dark:text-ink-200">
          {formatDateTime(row.occurred_at)}
        </span>
      ),
      width: '16%',
    },
    {
      key: 'reference',
      header: 'Reference',
      render: (row) => (
        <span className="font-mono text-xs text-ink-700 dark:text-ink-200" title={row.reference}>
          {truncateId(row.reference, 8)}
        </span>
      ),
      hideOnSmall: true,
      width: '13%',
    },
    {
      key: 'sender_account_id',
      header: 'From',
      render: (row) => (
        <Link
          to={paths.account(row.sender_account_id)}
          title={row.sender_account_id}
          className="font-mono text-xs text-accent-700 hover:underline dark:text-accent-300"
        >
          {truncateId(row.sender_account_id, 6)}
        </Link>
      ),
      width: '13%',
    },
    {
      key: 'receiver_account_id',
      header: 'To',
      render: (row) => (
        <Link
          to={paths.account(row.receiver_account_id)}
          title={row.receiver_account_id}
          className="font-mono text-xs text-accent-700 hover:underline dark:text-accent-300"
        >
          {truncateId(row.receiver_account_id, 6)}
        </Link>
      ),
      width: '13%',
    },
    {
      key: 'amount',
      header: 'Amount',
      numeric: true,
      sortable: true,
      render: (row) => {
        const direction = directionFor(row, perspectiveAccountId);

        return (
          <span className="whitespace-nowrap text-xs font-medium">
            {direction ? (
              <span
                aria-label={direction === 'inbound' ? 'Inbound' : 'Outbound'}
                title={direction === 'inbound' ? 'Into this account' : 'Out of this account'}
                className="mr-1 text-ink-500 dark:text-ink-400"
              >
                {direction === 'inbound' ? '+' : '−'}
              </span>
            ) : null}
            {formatAmount(row.amount, row.currency)}
          </span>
        );
      },
      width: '15%',
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
      width: '10%',
    },
    {
      key: 'status',
      header: 'Status',
      render: (row) => <StatusPill kind="transaction" value={row.status} />,
      width: '10%',
    },
    {
      key: 'fund_movement',
      header: 'Counts in totals',
      render: (row) =>
        isFundMovement(row) ? (
          <Badge tone="neutral" title="A completed transfer. Included in every aggregate.">
            Yes
          </Badge>
        ) : (
          <Badge
            tone="neutral"
            title="Not a completed transfer, so it is excluded from inbound, outbound and velocity figures."
          >
            No
          </Badge>
        ),
      hideOnSmall: true,
      width: '10%',
    },
  ];

  return (
    <DataTable
      caption="Transactions, with whether each one counts towards aggregate totals"
      columns={columns}
      rows={rows}
      rowKey={(row) => row.id}
      isLoading={isLoading}
      isRefetching={isRefetching}
      sortBy={sortBy}
      sortOrder={sortOrder}
      onSortChange={onSortChange}
      onRowClick={onRowClick}
      selectedKey={selectedId}
      emptyTitle="No transactions match these filters"
      emptyMessage={emptyMessage ?? 'Widen the date range, or clear the amount filter.'}
    />
  );
}
