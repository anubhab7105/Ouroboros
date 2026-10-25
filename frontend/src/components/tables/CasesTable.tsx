import { Link } from 'react-router-dom';

import { Badge } from '@/components/common/Badge';
import { DataTable, type Column } from '@/components/common/DataTable';
import { SeverityBadge } from '@/components/common/SeverityBadge';
import { StatusPill } from '@/components/common/StatusPill';
import { formatDate, formatDateTime, formatRelative } from '@/lib/dates';
import { truncateId, truncateText } from '@/lib/formatters';
import { paths } from '@/routes/paths';
import type { InvestigationCase } from '@/types/case';

export interface CasesTableProps {
  rows: InvestigationCase[];
  isLoading?: boolean;
  isRefetching?: boolean;
  sortBy?: string | null;
  sortOrder?: 'asc' | 'desc';
  onSortChange?: (key: string, order: 'asc' | 'desc') => void;
  emptyMessage?: string;
}

/**
 * The case list.
 *
 * A closed case shows its disposition, because "Closed" alone is the least
 * informative thing a case list can say: closed as confirmed fraud and closed
 * as a false positive are opposite outcomes, and the difference is what a
 * reviewer or an auditor is scanning for.
 *
 * There are no evidence or note counts: the list endpoint does not return
 * them, and they are available on the case itself. "From alert" is here
 * instead, because a case opened directly rather than from a triaged alert
 * started from someone's judgement rather than from a detection, which is
 * worth seeing at a glance.
 */
export function CasesTable({
  rows,
  isLoading,
  isRefetching,
  sortBy,
  sortOrder,
  onSortChange,
  emptyMessage,
}: CasesTableProps) {
  const columns: Array<Column<InvestigationCase>> = [
    {
      key: 'priority',
      header: 'Priority',
      sortable: true,
      render: (row) => <SeverityBadge severity={row.priority} />,
      width: '10%',
    },
    {
      key: 'title',
      header: 'Case',
      render: (row) => (
        <div className="min-w-0">
          <Link
            to={paths.case(row.id)}
            className="block truncate text-xs font-medium text-accent-700 hover:underline dark:text-accent-300"
            title={row.title}
          >
            {truncateText(row.title, 72)}
          </Link>
          {row.account_id ? (
            <Link
              to={paths.account(row.account_id)}
              className="mt-0.5 block font-mono text-2xs text-ink-500 hover:underline dark:text-ink-400"
              title={row.account_id}
            >
              {truncateId(row.account_id, 6)}
            </Link>
          ) : null}
        </div>
      ),
      width: '30%',
    },
    {
      key: 'status',
      header: 'Status',
      sortable: true,
      render: (row) => (
        <div className="flex flex-col gap-1">
          <StatusPill kind="case" value={row.status} />
          {row.status === 'CLOSED' ? (
            <StatusPill kind="disposition" value={row.disposition ?? null} />
          ) : null}
        </div>
      ),
      width: '16%',
    },
    {
      key: 'assignee_username',
      header: 'Assignee',
      render: (row) =>
        row.assignee_username ?? row.assignee_id ? (
          <span className="text-xs text-ink-700 dark:text-ink-200">
            {row.assignee_username ?? truncateId(row.assignee_id, 6)}
          </span>
        ) : (
          <Badge tone="warning" title="Nobody is working this case.">
            Unassigned
          </Badge>
        ),
      hideOnSmall: true,
      width: '13%',
    },
    {
      key: 'alert_id',
      header: 'From alert',
      render: (row) =>
        row.alert_id ? (
          <Link
            to={paths.alert(row.alert_id)}
            className="font-mono text-2xs text-accent-700 hover:underline dark:text-accent-300"
            title={row.alert_id}
          >
            {truncateId(row.alert_id, 6)}
          </Link>
        ) : (
          <span
            className="text-2xs text-ink-400 dark:text-ink-500"
            title="Opened directly rather than from a triaged alert."
          >
            Direct
          </span>
        ),
      hideOnSmall: true,
      width: '10%',
    },
    {
      key: 'created_at',
      header: 'Opened',
      sortable: true,
      render: (row) => (
        <span className="whitespace-nowrap text-xs tabular text-ink-600 dark:text-ink-300">
          {formatDate(row.created_at)}
        </span>
      ),
      hideOnSmall: true,
      width: '10%',
    },
    {
      key: 'updated_at',
      header: 'Last activity',
      sortable: true,
      render: (row) => (
        <span
          className="whitespace-nowrap text-xs text-ink-600 dark:text-ink-300"
          title={formatDateTime(row.updated_at)}
        >
          {formatRelative(row.updated_at)}
        </span>
      ),
      width: '14%',
    },
  ];

  return (
    <DataTable
      caption="Investigation cases with status and disposition"
      columns={columns}
      rows={rows}
      rowKey={(row) => row.id}
      isLoading={isLoading}
      isRefetching={isRefetching}
      sortBy={sortBy}
      sortOrder={sortOrder}
      onSortChange={onSortChange}
      emptyTitle="No cases match these filters"
      emptyMessage={emptyMessage ?? 'Cases are opened from an alert during triage.'}
    />
  );
}
