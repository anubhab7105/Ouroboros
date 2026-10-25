import { Link } from 'react-router-dom';

import { Badge } from '@/components/common/Badge';
import { Card } from '@/components/common/Card';
import { CopyButton } from '@/components/common/CopyButton';
import { KeyValueList } from '@/components/common/KeyValueList';
import { SeverityBadge } from '@/components/common/SeverityBadge';
import { StatusPill } from '@/components/common/StatusPill';
import { formatDateTime, formatRelative } from '@/lib/dates';
import { truncateId } from '@/lib/formatters';
import { paths } from '@/routes/paths';
import type { CaseDetail } from '@/types/case';

export interface CaseSummaryPanelProps {
  detail?: CaseDetail;
  isLoading?: boolean;
}

/**
 * The case record.
 *
 * The "opened from" row is the one that matters to anyone reviewing the case
 * later: a case created from a triaged alert inherited that alert's evidence,
 * while a case opened directly began with an investigator's judgement and
 * whatever they attached by hand. Those are different standards of proof, and
 * the difference should not require reading the event history to discover.
 */
export function CaseSummaryPanel({ detail, isLoading }: CaseSummaryPanelProps) {
  const investigation = detail?.case;

  return (
    <Card
      title="Case"
      actions={
        investigation ? (
          <div className="flex items-center gap-1.5">
            <SeverityBadge
              severity={
                (investigation.priority as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL') ?? null
              }
            />
            <StatusPill kind="case" value={investigation.status} />
            {investigation.status === 'CLOSED' ? (
              <StatusPill kind="disposition" value={investigation.disposition ?? null} />
            ) : null}
          </div>
        ) : null
      }
      caveats={detail?.caveats}
    >
      {isLoading ? (
        <p className="text-xs text-ink-500 dark:text-ink-400">Loading…</p>
      ) : !investigation ? null : (
        <>
          {investigation.description ? (
            <p className="mb-4 whitespace-pre-line text-xs leading-relaxed text-ink-800 dark:text-ink-100">
              {investigation.description}
            </p>
          ) : (
            <p className="mb-4 text-xs text-ink-500 dark:text-ink-400">
              No description was recorded when this case was opened.
            </p>
          )}

          <KeyValueList
            columns={3}
            entries={[
              {
                label: 'Case id',
                value: (
                  <span className="flex items-center gap-1">
                    <span className="font-mono text-2xs">{truncateId(investigation.id, 10)}</span>
                    <CopyButton value={investigation.id} label="Copy case id" />
                  </span>
                ),
              },
              {
                label: 'Opened from',
                value: investigation.alert_id ? (
                  <Link
                    to={paths.alert(investigation.alert_id)}
                    className="font-mono text-accent-700 hover:underline dark:text-accent-300"
                  >
                    alert {truncateId(investigation.alert_id, 8)}
                  </Link>
                ) : (
                  <Badge
                    tone="neutral"
                    title="No originating alert. The case began from an investigator's own judgement, so its evidence was attached by hand."
                  >
                    Opened directly
                  </Badge>
                ),
                help: 'A case from an alert inherits that alert’s evidence; one opened directly starts empty.',
              },
              {
                label: 'Account',
                value: investigation.account_id ? (
                  <Link
                    to={paths.account(investigation.account_id)}
                    className="font-mono text-accent-700 hover:underline dark:text-accent-300"
                  >
                    {truncateId(investigation.account_id, 8)}
                  </Link>
                ) : (
                  '—'
                ),
              },
              {
                label: 'Assignee',
                value:
                  investigation.assignee_username ??
                  (investigation.assignee_id ? truncateId(investigation.assignee_id, 8) : null) ?? (
                    <Badge tone="warning" title="Nobody is working this case.">
                      Unassigned
                    </Badge>
                  ),
              },
              {
                label: 'Opened by',
                value:
                  investigation.creator_username ??
                  (investigation.creator_id ? truncateId(investigation.creator_id, 8) : '—'),
              },
              {
                label: 'Opened',
                value: formatDateTime(investigation.created_at),
              },
              {
                label: 'Last activity',
                value: investigation.updated_at
                  ? `${formatRelative(investigation.updated_at)} (${formatDateTime(investigation.updated_at)})`
                  : '—',
              },
              {
                label: 'Closed',
                value: investigation.closed_at ? formatDateTime(investigation.closed_at) : '—',
              },
              {
                label: 'Evidence attached',
                value: detail ? String(detail.evidence_total) : '—',
                help: 'Active and removed items both counted. Removed items are retained so earlier reports stay reconstructible.',
              },
            ]}
          />
        </>
      )}
    </Card>
  );
}
