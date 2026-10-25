import { Badge } from '@/components/common/Badge';
import { CopyButton } from '@/components/common/CopyButton';
import { DataTable, type Column } from '@/components/common/DataTable';
import { EmptyState } from '@/components/common/EmptyState';
import { Tooltip } from '@/components/common/Tooltip';
import { formatCount } from '@/lib/amounts';
import { formatDateTime } from '@/lib/dates';
import { truncateId } from '@/lib/formatters';
import type { AlertEvidence } from '@/types/alert';
import { EVIDENCE_TYPE_LABELS, EVIDENCE_TYPE_MEANING } from '@/types/evidence';

export interface AlertEvidencePanelProps {
  rows: AlertEvidence[];
  total?: number;
  truncated?: boolean;
  isLoading?: boolean;
}

/**
 * The evidence the alert was raised on.
 *
 * Alert evidence cannot be removed — there is no endpoint for it — which is
 * right: the evidence is the reason the alert exists, and an alert whose
 * grounds could be edited away would be unreviewable. The panel therefore has
 * no remove control and does not pretend to.
 *
 * Truncation is called out. An alert raised on three hundred transactions
 * shows a bounded slice here, and a reader who takes the slice for the whole
 * set will misjudge how strong the finding is.
 */
export function AlertEvidencePanel({
  rows,
  total,
  truncated,
  isLoading,
}: AlertEvidencePanelProps) {
  const columns: Array<Column<AlertEvidence>> = [
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
      width: '22%',
    },
    {
      key: 'evidence_id',
      header: 'Reference',
      render: (row) => {
        const reference = `${row.evidence_type}:${row.evidence_id}`;

        return (
          <span className="flex items-center gap-1">
            <span className="font-mono text-xs text-ink-800 dark:text-ink-100" title={row.evidence_id}>
              {truncateId(row.evidence_id, 12)}
            </span>
            <CopyButton value={reference} label={`Copy evidence reference ${reference}`} />
          </span>
        );
      },
      width: '34%',
    },
    {
      key: 'snapshot',
      header: 'Snapshot',
      render: (row) =>
        row.evidence_snapshot_json ? (
          <Badge
            tone="neutral"
            title="The record as it stood when the alert was raised, so a later change to it stays visible."
          >
            Held
          </Badge>
        ) : (
          <span className="text-2xs text-ink-400 dark:text-ink-500">None</span>
        ),
      hideOnSmall: true,
      width: '14%',
    },
    {
      key: 'attached',
      header: 'Attached',
      render: (row) => (
        <span className="text-2xs text-ink-600 dark:text-ink-300">
          {formatDateTime(row.record_created_at)}
          {row.created_by_username ? (
            <span className="block text-ink-500 dark:text-ink-400">
              by {row.created_by_username}
            </span>
          ) : null}
        </span>
      ),
      width: '30%',
    },
  ];

  if (!isLoading && rows.length === 0) {
    return (
      <EmptyState
        title="No evidence recorded on this alert"
        message="An alert with no evidence cannot be checked against the records it came from. If the rule pack is misconfigured, this is what that looks like."
        compact
      />
    );
  }

  return (
    <div>
      <DataTable
        caption="Evidence the alert was raised on"
        columns={columns}
        rows={rows}
        rowKey={(row) => row.id}
        isLoading={isLoading}
        emptyTitle="No evidence recorded"
      />

      {truncated ? (
        <p className="mt-2 text-2xs text-ink-700 dark:text-ink-200">
          Showing {formatCount(rows.length)} of {formatCount(total ?? rows.length)} items. The rest
          are reachable through the alert's own evidence endpoint; this panel is bounded.
        </p>
      ) : null}
    </div>
  );
}
