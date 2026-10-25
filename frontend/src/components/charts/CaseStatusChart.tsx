import { formatCount, formatPercent } from '@/lib/amounts';
import { CASE_STATUS_TOKENS } from '@/lib/constants';
import type { FriendlyError } from '@/lib/errorMapper';
import type { CaseStatus } from '@/types/case';

import { ChartFrame } from './ChartFrame';

export interface CaseStatusChartProps {
  counts: Partial<Record<CaseStatus, number>>;
  isLoading?: boolean;
  error?: FriendlyError | null;
  onRetry?: () => void;
  onSelectStatus?: (status: CaseStatus) => void;
  className?: string;
}

/** Workflow order, so the bar reads left to right as a case progresses. */
const ORDER: CaseStatus[] = ['NEW', 'TRIAGED', 'UNDER_INVESTIGATION', 'ESCALATED', 'CLOSED'];

/**
 * Case status as a single proportional bar.
 *
 * Not a chart library at all: with five ordered categories summing to a
 * meaningful whole, one stacked bar plus a labelled legend is more readable
 * than a donut and survives being 180 pixels wide. Each segment is a button,
 * so the bar is also the filter.
 *
 * Segments below a visible width are still rendered at a minimum size, because
 * "two escalated cases" disappearing entirely is the opposite of what an
 * escalation should do.
 */
export function CaseStatusChart({
  counts,
  isLoading = false,
  error = null,
  onRetry,
  onSelectStatus,
  className,
}: CaseStatusChartProps) {
  const rows = ORDER.map((status) => ({
    status,
    label: CASE_STATUS_TOKENS[status]?.label ?? status,
    hex: CASE_STATUS_TOKENS[status]?.hex ?? '#6b7a8f',
    count: counts[status] ?? 0,
  })).filter((row) => row.count > 0);

  const total = rows.reduce((sum, row) => sum + row.count, 0);

  const summary =
    total === 0
      ? 'Case status chart: no cases.'
      : `Case status across ${formatCount(total)} cases: ` +
        rows
          .map((row) => `${row.label} ${formatCount(row.count)} (${formatPercent(row.count / total)})`)
          .join(', ') +
        '.';

  return (
    <ChartFrame
      height={96}
      isLoading={isLoading}
      error={error}
      onRetry={onRetry}
      isEmpty={total === 0}
      emptyTitle="No cases yet"
      emptyMessage="Cases are created from an alert during triage."
      summary={summary}
      className={className}
    >
      <div className="flex h-full flex-col justify-center gap-3">
        <div
          className="flex h-6 w-full overflow-hidden rounded-md"
          role="presentation"
        >
          {rows.map((row) => {
            const share = row.count / total;

            return (
              <button
                key={row.status}
                type="button"
                disabled={!onSelectStatus}
                onClick={() => onSelectStatus?.(row.status)}
                title={`${row.label}: ${formatCount(row.count)} (${formatPercent(share)})`}
                aria-label={`${row.label}: ${formatCount(row.count)} cases, ${formatPercent(share)}`}
                style={{
                  backgroundColor: row.hex,
                  // A floor of 3% keeps a one-case segment visible and clickable.
                  flexBasis: `${Math.max(share * 100, 3)}%`,
                }}
                className="group relative min-w-0 border-r border-white/40 last:border-r-0 enabled:cursor-pointer dark:border-ink-900/40"
              >
                <span className="mg-visually-hidden">{row.label}</span>
              </button>
            );
          })}
        </div>

        <ul className="flex flex-wrap gap-x-4 gap-y-1">
          {rows.map((row) => (
            <li key={row.status} className="flex items-center gap-1.5 text-2xs">
              <span
                aria-hidden="true"
                className="h-2 w-2 shrink-0 rounded-sm"
                style={{ backgroundColor: row.hex }}
              />
              <span className="text-ink-700 dark:text-ink-200">{row.label}</span>
              <span className="tabular font-semibold text-ink-900 dark:text-ink-50">
                {formatCount(row.count)}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </ChartFrame>
  );
}
