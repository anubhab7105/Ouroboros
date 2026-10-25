import { Link } from 'react-router-dom';

import { Badge } from '@/components/common/Badge';
import { CopyButton } from '@/components/common/CopyButton';
import { DataTable, type Column } from '@/components/common/DataTable';
import { RiskBadge } from '@/components/common/RiskBadge';
import { formatCount } from '@/lib/amounts';
import { ACCOUNT_STATUS_HINTS } from '@/lib/constants';
import { formatDate } from '@/lib/dates';
import { humaniseEnum, truncateId } from '@/lib/formatters';
import { paths } from '@/routes/paths';
import type { Account } from '@/types/account';

export interface AccountsTableProps {
  rows: Account[];
  isLoading?: boolean;
  isRefetching?: boolean;
  sortBy?: string | null;
  sortOrder?: 'asc' | 'desc';
  onSortChange?: (key: string, order: 'asc' | 'desc') => void;
  emptyMessage?: string;
}

/**
 * The account list.
 *
 * Account ids are the thing analysts copy into other systems, so each row
 * carries a copy control rather than making them select truncated text. The
 * status column is explicitly labelled as the source system's view: MuleGuard
 * never freezes or closes an account, and an analyst must not read "DORMANT"
 * here as something the platform did.
 *
 * There are no open-alert or open-case counts, because the list endpoint does
 * not return them — they come from `/accounts/{id}/summary`, one account at a
 * time. Rather than firing a request per row, each row links to the filtered
 * alert list, which is where the analyst was heading anyway.
 *
 * The assessment columns appear only when the list was requested with
 * `include_latest_assessment`; without it every account reads "Not assessed",
 * which is why the page always sets it.
 */
export function AccountsTable({
  rows,
  isLoading,
  isRefetching,
  sortBy,
  sortOrder,
  onSortChange,
  emptyMessage,
}: AccountsTableProps) {
  const columns: Array<Column<Account>> = [
    {
      key: 'id',
      header: 'Account',
      render: (row) => (
        <span className="flex items-center gap-1">
          <Link
            to={paths.account(row.id)}
            className="font-mono text-xs font-medium text-accent-700 hover:underline dark:text-accent-300"
            title={row.id}
          >
            {truncateId(row.id, 8)}
          </Link>
          <CopyButton value={row.id} label={`Copy account id ${row.id}`} />
        </span>
      ),
      width: '19%',
    },
    {
      key: 'risk_score',
      header: 'Priority',
      sortable: true,
      render: (row) => (
        <RiskBadge
          band={row.latest_assessment?.risk_band ?? null}
          score={row.latest_assessment?.score ?? null}
        />
      ),
      width: '13%',
    },
    {
      key: 'account_type',
      header: 'Type',
      render: (row) => (
        <span className="text-xs text-ink-700 dark:text-ink-200">
          {humaniseEnum(row.account_type)}
        </span>
      ),
      hideOnSmall: true,
      width: '11%',
    },
    {
      key: 'status',
      header: 'Source status',
      render: (row) => (
        <Badge
          tone="neutral"
          title={ACCOUNT_STATUS_HINTS[row.status] ?? 'As reported by the source system.'}
        >
          {humaniseEnum(row.status)}
        </Badge>
      ),
      hideOnSmall: true,
      width: '13%',
    },
    {
      key: 'rules',
      header: 'Rules fired',
      numeric: true,
      render: (row) =>
        row.latest_assessment?.indicator_count ? (
          <span
            className="text-xs tabular"
            title="Risk indicators recorded on the latest assessment. Open the account to see which rules fired and what each measured."
          >
            {formatCount(row.latest_assessment.indicator_count)}
          </span>
        ) : (
          <span className="text-2xs text-ink-400 dark:text-ink-500">—</span>
        ),
      hideOnSmall: true,
      width: '9%',
    },
    {
      key: 'explained',
      header: 'Explained',
      render: (row) =>
        !row.latest_assessment ? (
          <span className="text-2xs text-ink-400 dark:text-ink-500">—</span>
        ) : row.latest_assessment.explanation_available ? (
          <Badge tone="neutral" title="The assessment carries a written explanation.">
            Yes
          </Badge>
        ) : (
          <Badge
            tone="warning"
            title="No written explanation was recorded, so this score cannot be justified from the assessment alone."
          >
            No
          </Badge>
        ),
      hideOnSmall: true,
      width: '10%',
    },
    {
      key: 'links',
      header: <span className="mg-visually-hidden">Related</span>,
      render: (row) => (
        <span className="flex flex-wrap gap-x-2 text-2xs">
          <Link
            to={`${paths.alerts}?account_id=${encodeURIComponent(row.id)}`}
            className="text-accent-700 hover:underline dark:text-accent-300"
          >
            Alerts
          </Link>
          <Link
            to={paths.graphForAccount(row.id)}
            className="text-accent-700 hover:underline dark:text-accent-300"
          >
            Network
          </Link>
        </span>
      ),
      hideOnSmall: true,
      width: '11%',
    },
    {
      key: 'assessed_at',
      header: 'Assessed',
      render: (row) =>
        row.latest_assessment?.as_of ? (
          <span className="text-xs tabular text-ink-600 dark:text-ink-300">
            {formatDate(row.latest_assessment.as_of)}
          </span>
        ) : (
          <span
            className="text-xs text-ink-400 dark:text-ink-500"
            title="No analysis run has assessed this account."
          >
            Never
          </span>
        ),
      hideOnSmall: true,
      width: '12%',
    },
    {
      key: 'created_at',
      header: 'Opened',
      sortable: true,
      render: (row) => (
        <span className="text-xs tabular text-ink-600 dark:text-ink-300">
          {formatDate(row.created_at)}
        </span>
      ),
      width: '12%',
    },
  ];

  return (
    <DataTable
      caption="Accounts with their latest investigative priority assessment"
      columns={columns}
      rows={rows}
      rowKey={(row) => row.id}
      isLoading={isLoading}
      isRefetching={isRefetching}
      sortBy={sortBy}
      sortOrder={sortOrder}
      onSortChange={onSortChange}
      emptyTitle="No accounts match these filters"
      emptyMessage={emptyMessage ?? 'Clear a filter, or load account data from the Data page.'}
    />
  );
}
