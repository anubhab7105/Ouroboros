import { Link, useNavigate } from 'react-router-dom';

import { CaseStatusChart } from '@/components/charts/CaseStatusChart';
import { Badge } from '@/components/common/Badge';
import { Card } from '@/components/common/Card';
import { EmptyState } from '@/components/common/EmptyState';
import { SeverityBadge } from '@/components/common/SeverityBadge';
import { formatCount } from '@/lib/amounts';
import { formatDuration } from '@/lib/dates';
import type { FriendlyError } from '@/lib/errorMapper';
import { truncateText } from '@/lib/formatters';
import { paths } from '@/routes/paths';
import type { CaseStatus } from '@/types/case';
import type { DashboardCaseBreakdown, DashboardQueueSection } from '@/types/dashboard';

export interface OpenCasesPanelProps {
  cases?: DashboardCaseBreakdown;
  /** The escalated queue, which is the one worth listing by name. */
  escalated?: DashboardQueueSection;
  isLoading?: boolean;
  error?: FriendlyError | null;
  onRetry?: () => void;
}

/**
 * Open cases by status, with the escalated ones named.
 *
 * Escalation is a request for someone senior to look, so an escalated case
 * sitting in a queue is the failure mode this panel exists to prevent. Age is
 * shown per case and comes from the server's `age_seconds`, so every row
 * agrees on what "now" means — a client-side clock would disagree with the
 * ordering the server used.
 */
export function OpenCasesPanel({
  cases,
  escalated,
  isLoading,
  error,
  onRetry,
}: OpenCasesPanelProps) {
  const navigate = useNavigate();

  const counts = (cases?.open_by_status ?? {}) as Partial<Record<CaseStatus, number>>;
  const items = escalated?.items ?? [];

  return (
    <Card
      title="Cases"
      description="Open investigations by status. Escalated cases are listed because an escalation that nobody picks up is the one that goes stale."
      actions={
        <Link
          to={`${paths.cases}?open_only=true`}
          className="text-2xs font-medium text-accent-700 hover:underline dark:text-accent-300"
        >
          All open cases
        </Link>
      }
    >
      <CaseStatusChart
        counts={counts}
        isLoading={isLoading}
        error={error}
        onRetry={onRetry}
        onSelectStatus={(status) => navigate(`${paths.cases}?status=${status}`)}
      />

      <div className="mt-4 border-t border-ink-200 pt-3 dark:border-ink-700">
        <div className="mb-2 flex items-center justify-between gap-2">
          <p className="text-2xs font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
            Escalated
          </p>
          {escalated && escalated.total > items.length ? (
            <Badge tone="neutral" title="More escalated cases exist than are listed here.">
              {formatCount(items.length)} of {formatCount(escalated.total)}
            </Badge>
          ) : null}
        </div>

        {items.length === 0 ? (
          <EmptyState title="Nothing escalated" compact />
        ) : (
          <ul className="divide-y divide-ink-200 dark:divide-ink-700">
            {items.map((item) => (
              <li key={item.id} className="flex items-start justify-between gap-3 py-1.5">
                <div className="min-w-0">
                  <Link
                    to={paths.case(item.id)}
                    className="block truncate text-xs font-medium text-accent-700 hover:underline dark:text-accent-300"
                    title={item.title ?? item.id}
                  >
                    {truncateText(item.title ?? item.id, 56)}
                  </Link>
                  <p className="mt-0.5 text-2xs text-ink-500 dark:text-ink-400">
                    {item.assignee_id ? `Assigned` : 'Unassigned'}
                    {item.age_seconds !== null && item.age_seconds !== undefined
                      ? ` · open ${formatDuration(item.age_seconds)}`
                      : ''}
                  </p>
                </div>
                <SeverityBadge
                  severity={
                    (item.priority as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | undefined) ?? null
                  }
                />
              </li>
            ))}
          </ul>
        )}
      </div>
    </Card>
  );
}
