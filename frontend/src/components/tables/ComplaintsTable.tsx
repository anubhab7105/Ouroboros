import { Link } from 'react-router-dom';

import { Badge } from '@/components/common/Badge';
import { DataTable, type Column } from '@/components/common/DataTable';
import { formatAmount, formatCount } from '@/lib/amounts';
import { formatDate } from '@/lib/dates';
import { humaniseEnum, truncateId } from '@/lib/formatters';
import { paths } from '@/routes/paths';
import type { Complaint } from '@/types/complaint';

export interface ComplaintsTableProps {
  rows: Complaint[];
  isLoading?: boolean;
  isRefetching?: boolean;
  sortBy?: string | null;
  sortOrder?: 'asc' | 'desc';
  onSortChange?: (key: string, order: 'asc' | 'desc') => void;
  onRowClick?: (row: Complaint) => void;
  selectedId?: string | null;
  emptyMessage?: string;
}

/**
 * Cybercrime complaints.
 *
 * "Account named by complainant" is the allegation carried through from the
 * complaint as filed. It is not a MuleGuard finding, and the column header
 * says so, because an account named by a victim who mistyped a UPI handle is a
 * common and entirely innocent occurrence.
 *
 * The narrative column says whether there is one, not what it says. The raw
 * text is a victim's own account of what happened to them and needs its own
 * permission to read, so the list reports its existence and no more.
 */
export function ComplaintsTable({
  rows,
  isLoading,
  isRefetching,
  sortBy,
  sortOrder,
  onSortChange,
  onRowClick,
  selectedId,
  emptyMessage,
}: ComplaintsTableProps) {
  const columns: Array<Column<Complaint>> = [
    {
      key: 'reported_at',
      header: 'Reported',
      sortable: true,
      render: (row) => (
        <span className="whitespace-nowrap text-xs tabular text-ink-700 dark:text-ink-200">
          {formatDate(row.reported_at)}
        </span>
      ),
      width: '11%',
    },
    {
      key: 'reference',
      header: 'Reference',
      render: (row) => (
        <span className="font-mono text-xs text-ink-700 dark:text-ink-200" title={row.reference}>
          {truncateId(row.reference, 10)}
        </span>
      ),
      width: '13%',
    },
    {
      key: 'category',
      header: 'Category',
      render: (row) => (
        <span className="text-xs text-ink-700 dark:text-ink-200">
          {humaniseEnum(row.category)}
        </span>
      ),
      width: '15%',
    },
    {
      key: 'amount',
      header: 'Reported loss',
      numeric: true,
      sortable: true,
      render: (row) => (
        <span
          className="text-xs tabular"
          title="The amount stated in the complaint. Not independently verified."
        >
          {formatAmount(row.amount, row.currency)}
        </span>
      ),
      width: '13%',
    },
    {
      key: 'suspected_account_id',
      header: "Account named by complainant",
      render: (row) =>
        row.suspected_account_id ? (
          <Link
            to={paths.account(row.suspected_account_id)}
            className="font-mono text-xs text-accent-700 hover:underline dark:text-accent-300"
            title={`${row.suspected_account_id} — named in the complaint as filed, not a MuleGuard finding`}
          >
            {truncateId(row.suspected_account_id, 6)}
          </Link>
        ) : (
          <span className="text-2xs text-ink-400 dark:text-ink-500">Not named</span>
        ),
      hideOnSmall: true,
      width: '14%',
    },
    {
      key: 'correlation_count',
      header: 'Correlations',
      numeric: true,
      sortable: true,
      // Present only when the list was requested with
      // `include_correlation_count`; absent is "not counted", not "none".
      render: (row) =>
        (row.correlation_count ?? 0) > 0 ? (
          <Badge
            tone="accent"
            title="Accounts, transactions or entities this complaint has been linked to."
          >
            {formatCount(row.correlation_count ?? 0)}
          </Badge>
        ) : (
          <span
            className="text-2xs text-ink-400 dark:text-ink-500"
            title="No link found. Correlation runs as part of an analysis run."
          >
            None
          </span>
        ),
      width: '11%',
    },
    {
      key: 'narrative_available',
      header: 'Narrative',
      render: (row) =>
        row.narrative_available ? (
          <Badge
            tone="neutral"
            title="The complaint has a narrative. Reading it needs the complaint-narrative permission, because it is the victim's own account of what happened."
          >
            On file
          </Badge>
        ) : (
          <span className="text-2xs text-ink-400 dark:text-ink-500">None</span>
        ),
      hideOnSmall: true,
      width: '12%',
    },
    {
      key: 'transaction_reference',
      header: 'Transaction named',
      render: (row) =>
        row.transaction_reference ? (
          <Link
            to={`${paths.transactions}?reference=${encodeURIComponent(row.transaction_reference)}`}
            className="font-mono text-2xs text-accent-700 hover:underline dark:text-accent-300"
            title={`${row.transaction_reference} — as given in the complaint. A tier 1 correlation is this reference matching a transaction that exists.`}
          >
            {truncateId(row.transaction_reference, 8)}
          </Link>
        ) : (
          <span className="text-2xs text-ink-400 dark:text-ink-500">—</span>
        ),
      hideOnSmall: true,
      width: '11%',
    },
  ];

  return (
    <DataTable
      caption="Cybercrime complaints and how many correlations each has"
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
      emptyTitle="No complaints match these filters"
      emptyMessage={emptyMessage ?? 'Complaint data is loaded from the Data page.'}
    />
  );
}
