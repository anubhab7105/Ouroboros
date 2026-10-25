import { Badge } from '@/components/common/Badge';
import { DataTable, type Column } from '@/components/common/DataTable';
import { formatDateTime } from '@/lib/dates';
import { humaniseEnum, truncateId } from '@/lib/formatters';
import type { AuditEvent } from '@/types/audit';

export interface AuditTableProps {
  rows: AuditEvent[];
  isLoading?: boolean;
  isRefetching?: boolean;
  sortBy?: string | null;
  sortOrder?: 'asc' | 'desc';
  onSortChange?: (key: string, order: 'asc' | 'desc') => void;
  onRowClick?: (row: AuditEvent) => void;
  selectedId?: string | null;
  emptyMessage?: string;
}

/** The server types `outcome` as a plain string, so unknown values survive. */
const OUTCOME_TONE: Record<string, 'neutral' | 'warning' | 'danger'> = {
  SUCCESS: 'neutral',
  WARNING: 'warning',
  FAILURE: 'danger',
  DENIED: 'warning',
};

const OUTCOME_HINT: Record<string, string> = {
  SUCCESS: 'The action completed.',
  WARNING: 'The action completed with a caveat recorded in its metadata.',
  FAILURE: 'The action was attempted and failed.',
  DENIED: 'The action was refused: the actor lacked the permission.',
};

/**
 * The audit trail.
 *
 * Denied attempts are shown with the same prominence as successful ones. A
 * log that only records what worked answers the wrong question: an auditor
 * reviewing this platform is usually looking for who tried to do something
 * they could not.
 *
 * IP and user-agent arrive hashed from the server and are displayed as
 * hashes. They are there to let an auditor tell two sessions apart, not to
 * locate a person.
 */
export function AuditTable({
  rows,
  isLoading,
  isRefetching,
  sortBy,
  sortOrder,
  onSortChange,
  onRowClick,
  selectedId,
  emptyMessage,
}: AuditTableProps) {
  const columns: Array<Column<AuditEvent>> = [
    {
      key: 'created_at',
      header: 'When',
      sortable: true,
      render: (row) => (
        <span className="whitespace-nowrap text-xs tabular text-ink-700 dark:text-ink-200">
          {formatDateTime(row.created_at)}
        </span>
      ),
      width: '16%',
    },
    {
      key: 'actor_username',
      header: 'Actor',
      render: (row) => (
        <span className="text-xs text-ink-700 dark:text-ink-200">
          {row.actor_username ?? (row.actor_id ? truncateId(row.actor_id, 6) : 'System')}
          {row.actor_role ? (
            <span className="block text-2xs text-ink-500 dark:text-ink-400">
              {humaniseEnum(row.actor_role)}
            </span>
          ) : null}
        </span>
      ),
      width: '15%',
    },
    {
      key: 'action',
      header: 'Action',
      render: (row) => (
        <span className="font-mono text-2xs text-ink-700 dark:text-ink-200">{row.action}</span>
      ),
      width: '22%',
    },
    {
      key: 'resource',
      header: 'Resource',
      render: (row) =>
        row.resource_type ? (
          <span className="text-2xs text-ink-700 dark:text-ink-200">
            {humaniseEnum(row.resource_type)}
            {row.resource_id ? (
              <span
                className="block font-mono text-ink-500 dark:text-ink-400"
                title={row.resource_id}
              >
                {truncateId(row.resource_id, 8)}
              </span>
            ) : null}
          </span>
        ) : (
          <span className="text-2xs text-ink-400 dark:text-ink-500">—</span>
        ),
      hideOnSmall: true,
      width: '18%',
    },
    {
      key: 'outcome',
      header: 'Outcome',
      render: (row) => (
        <Badge tone={OUTCOME_TONE[row.outcome] ?? 'neutral'} title={OUTCOME_HINT[row.outcome]}>
          {humaniseEnum(row.outcome)}
        </Badge>
      ),
      width: '12%',
    },
    {
      key: 'request_id',
      header: 'Request',
      render: (row) =>
        row.request_id ? (
          <span
            className="font-mono text-2xs text-ink-500 dark:text-ink-400"
            title={`Request ${row.request_id}. Quote this when reporting a problem.`}
          >
            {truncateId(row.request_id, 6)}
          </span>
        ) : (
          <span className="text-2xs text-ink-400 dark:text-ink-500">—</span>
        ),
      hideOnSmall: true,
      width: '17%',
    },
  ];

  return (
    <DataTable
      caption="Audit events, including attempts that were denied"
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
      emptyTitle="No audit events match these filters"
      emptyMessage={emptyMessage ?? 'Widen the time range, or clear the action filter.'}
    />
  );
}
