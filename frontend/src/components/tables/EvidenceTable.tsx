import { Link } from 'react-router-dom';

import { Badge } from '@/components/common/Badge';
import { Button } from '@/components/common/Button';
import { CopyButton } from '@/components/common/CopyButton';
import { DataTable, type Column } from '@/components/common/DataTable';
import { Tooltip } from '@/components/common/Tooltip';
import { formatDateTime } from '@/lib/dates';
import { truncateId } from '@/lib/formatters';
import { paths } from '@/routes/paths';
import type { CaseEvidence } from '@/types/case';
import { EVIDENCE_TYPE_LABELS, EVIDENCE_TYPE_MEANING } from '@/types/evidence';

export interface EvidenceTableProps {
  rows: CaseEvidence[];
  isLoading?: boolean;
  /** Supplied only when the viewer may remove evidence. */
  onRemove?: (item: CaseEvidence) => void;
  /** Open the snapshot taken when the item was attached. */
  onInspect?: (item: CaseEvidence) => void;
  emptyMessage?: string;
}

/** Deep link to the referenced record, where one exists. */
function evidenceLink(item: CaseEvidence): string | null {
  switch (item.evidence_type) {
    case 'ACCOUNT':
      return paths.account(item.evidence_id);
    case 'ALERT':
      return paths.alert(item.evidence_id);
    case 'COMPLAINT':
      return paths.complaint(item.evidence_id);
    case 'TRANSACTION':
      return `${paths.transactions}?reference=${encodeURIComponent(item.evidence_id)}`;
    case 'GRAPH_PATH':
    case 'MODEL_ASSESSMENT':
    case 'ENTITY_LINK':
    default:
      // These have no standalone page; the snapshot is the record.
      return null;
  }
}

/**
 * Evidence attached to a case.
 *
 * Two things this table is careful about:
 *
 * - **Removal is a soft delete.** A removed row stays, struck through. A
 *   report generated last week cited these references, and silently dropping
 *   them would make that report unreconstructible — the one outcome to avoid
 *   in an evidential context. The server returns removed rows only when the
 *   request sets `include_inactive`, so their presence here depends on that.
 *
 * - **Every row says what its kind of evidence can establish.** A transaction
 *   is a record of a transfer; a network path is a shape in the data and not a
 *   tracing of particular funds. That distinction decides what a report may
 *   claim, so it travels with the item rather than living in a training doc.
 */
export function EvidenceTable({
  rows,
  isLoading,
  onRemove,
  onInspect,
  emptyMessage,
}: EvidenceTableProps) {
  const columns: Array<Column<CaseEvidence>> = [
    {
      key: 'evidence_type',
      header: 'Kind',
      render: (row) => (
        <Tooltip content={EVIDENCE_TYPE_MEANING[row.evidence_type] ?? 'Attached evidence.'}>
          <Badge tone="neutral">
            {EVIDENCE_TYPE_LABELS[row.evidence_type] ?? row.evidence_type}
          </Badge>
        </Tooltip>
      ),
      width: '18%',
    },
    {
      key: 'evidence_id',
      header: 'Reference',
      render: (row) => {
        const href = evidenceLink(row);
        const reference = `${row.evidence_type}:${row.evidence_id}`;
        const removed = row.is_active === false;

        return (
          <span className={removed ? 'flex items-center gap-1 opacity-60' : 'flex items-center gap-1'}>
            {href ? (
              <Link
                to={href}
                className={`font-mono text-xs text-accent-700 hover:underline dark:text-accent-300 ${
                  removed ? 'line-through' : ''
                }`}
                title={row.evidence_id}
              >
                {truncateId(row.evidence_id, 10)}
              </Link>
            ) : (
              <span
                className={`font-mono text-xs text-ink-700 dark:text-ink-200 ${
                  removed ? 'line-through' : ''
                }`}
                title={row.evidence_id}
              >
                {truncateId(row.evidence_id, 10)}
              </span>
            )}
            <CopyButton value={reference} label={`Copy evidence reference ${reference}`} />
          </span>
        );
      },
      width: '26%',
    },
    {
      key: 'added',
      header: 'Attached',
      render: (row) => (
        <span className="text-2xs text-ink-600 dark:text-ink-300">
          {formatDateTime(row.record_created_at)}
          {row.added_by_username ?? row.added_by ? (
            <span className="block text-ink-500 dark:text-ink-400">
              by {row.added_by_username ?? truncateId(row.added_by, 6)}
            </span>
          ) : null}
        </span>
      ),
      width: '20%',
    },
    {
      key: 'state',
      header: 'State',
      render: (row) =>
        row.is_active === false ? (
          <Badge
            tone="neutral"
            title="Removed from the case, but retained so reports generated earlier stay reconstructible."
          >
            Removed
          </Badge>
        ) : (
          <Badge tone="neutral" title="Cited in reports generated from this case.">
            Active
          </Badge>
        ),
      width: '12%',
    },
    {
      key: 'snapshot',
      header: 'Snapshot',
      render: (row) =>
        row.evidence_snapshot_json ? (
          onInspect ? (
            <Button size="sm" variant="ghost" onClick={() => onInspect(row)}>
              View
            </Button>
          ) : (
            <Badge
              tone="neutral"
              title="What the record looked like when it was attached, so a later change to it is visible."
            >
              Held
            </Badge>
          )
        ) : (
          <span
            className="text-2xs text-ink-400 dark:text-ink-500"
            title="No snapshot was captured, so this reference depends on the live record."
          >
            None
          </span>
        ),
      hideOnSmall: true,
      width: onRemove ? '12%' : '24%',
    },
    ...(onRemove
      ? [
          {
            key: 'actions',
            header: <span className="mg-visually-hidden">Actions</span>,
            render: (row: CaseEvidence) =>
              row.is_active === false ? null : (
                <Button size="sm" variant="ghost" onClick={() => onRemove(row)}>
                  Remove
                </Button>
              ),
            width: '12%',
          } satisfies Column<CaseEvidence>,
        ]
      : []),
  ];

  return (
    <DataTable
      caption="Evidence attached to this case, including items since removed"
      columns={columns}
      rows={rows}
      rowKey={(row) => row.id}
      isLoading={isLoading}
      emptyTitle="No evidence attached"
      emptyMessage={
        emptyMessage ??
        'Attach the alert, transactions and complaints the conclusion rests on. A report with no evidence index is not much use to a referral.'
      }
    />
  );
}
