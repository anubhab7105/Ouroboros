import { Link } from 'react-router-dom';

import { Badge } from '@/components/common/Badge';
import { DataTable, type Column } from '@/components/common/DataTable';
import { SeverityBadge } from '@/components/common/SeverityBadge';
import { StatusPill } from '@/components/common/StatusPill';
import { formatScore } from '@/lib/amounts';
import { formatDateTime, formatRelative } from '@/lib/dates';
import { truncateId, truncateText } from '@/lib/formatters';
import { paths } from '@/routes/paths';
import type { Alert } from '@/types/alert';

export interface AlertsTableProps {
  rows: Alert[];
  isLoading?: boolean;
  isRefetching?: boolean;
  sortBy?: string | null;
  sortOrder?: 'asc' | 'desc';
  onSortChange?: (key: string, order: 'asc' | 'desc') => void;
  onRowClick?: (row: Alert) => void;
  selectedId?: string | null;
  emptyMessage?: string;
}

/**
 * The triage queue.
 *
 * Age is measured from `first_seen_at`, not from the last analysis run.
 * Deduplication updates an existing alert rather than raising a new one, so an
 * alert that has re-fired nightly for a fortnight is a fortnight old — showing
 * it as "2 hours ago" would hide exactly the thing a triage queue exists to
 * surface. Both instants are available: the relative age in the cell, the
 * absolute first-seen on hover.
 *
 * Unassigned alerts are called out, because an alert nobody owns is the one
 * that sits in the queue indefinitely.
 */
export function AlertsTable({
  rows,
  isLoading,
  isRefetching,
  sortBy,
  sortOrder,
  onSortChange,
  onRowClick,
  selectedId,
  emptyMessage,
}: AlertsTableProps) {
  const columns: Array<Column<Alert>> = [
    {
      key: 'priority',
      header: 'Priority',
      sortable: true,
      render: (row) => <SeverityBadge severity={row.priority} />,
      width: '10%',
    },
    {
      key: 'title',
      header: 'Alert',
      render: (row) => (
        <div className="min-w-0">
          <Link
            to={paths.alert(row.id)}
            className="block truncate text-xs font-medium text-accent-700 hover:underline dark:text-accent-300"
            title={row.title}
          >
            {truncateText(row.title, 72)}
          </Link>
          <p className="mt-0.5 flex flex-wrap items-center gap-1 text-2xs text-ink-500 dark:text-ink-400">
            <Link
              to={paths.account(row.account_id)}
              className="font-mono hover:underline"
              title={row.account_id}
            >
              {truncateId(row.account_id, 6)}
            </Link>
            {row.rule_codes.length > 0 ? (
              <span title={row.rule_codes.join(', ')}>
                · {row.rule_codes.length === 1 ? row.rule_codes[0] : `${row.rule_codes.length} rules`}
              </span>
            ) : null}
          </p>
        </div>
      ),
      width: '31%',
    },
    {
      key: 'score',
      header: 'Score',
      numeric: true,
      sortable: true,
      render: (row) => (
        <span
          className="text-xs tabular"
          title={
            row.score === null || row.score === undefined
              ? 'This alert was raised by rules alone and carries no fused score.'
              : 'Investigative priority score, 0-100. Not a probability of guilt.'
          }
        >
          {formatScore(row.score)}
        </span>
      ),
      width: '9%',
    },
    {
      key: 'state',
      header: 'State',
      render: (row) => <StatusPill kind="alert" value={row.state} />,
      width: '13%',
    },
    {
      key: 'assigned_to',
      header: 'Owner',
      render: (row) =>
        row.assigned_to ? (
          <span className="text-xs text-ink-700 dark:text-ink-200">{row.assigned_to}</span>
        ) : (
          <Badge tone="warning" title="No analyst owns this alert yet.">
            Unassigned
          </Badge>
        ),
      hideOnSmall: true,
      width: '13%',
    },
    {
      key: 'first_seen_at',
      header: 'Age',
      sortable: true,
      render: (row) => (
        <span
          className="whitespace-nowrap text-xs text-ink-600 dark:text-ink-300"
          title={`First seen ${formatDateTime(row.first_seen_at)}; last re-observed ${formatDateTime(
            row.last_seen_at,
          )}`}
        >
          {formatRelative(row.first_seen_at)}
        </span>
      ),
      width: '12%',
    },
    {
      key: 'case_count',
      header: 'Case',
      // `case_count` is optional on the wire: absent means "not computed",
      // which is not the same as zero, so only a positive count claims a case.
      render: (row) =>
        (row.case_count ?? 0) > 0 ? (
          <Badge tone="accent" title="An investigation has been opened from this alert.">
            Opened
          </Badge>
        ) : (
          <span className="text-2xs text-ink-400 dark:text-ink-500">—</span>
        ),
      hideOnSmall: true,
      width: '12%',
    },
  ];

  return (
    <DataTable
      caption="Alerts awaiting triage, oldest signature first"
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
      emptyTitle="No alerts match these filters"
      emptyMessage={
        emptyMessage ?? 'An empty queue may mean nothing has been analysed yet — check the Data page.'
      }
    />
  );
}
