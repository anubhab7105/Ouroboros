import clsx from 'clsx';
import type { ReactNode } from 'react';

import { EmptyState } from '@/components/common/EmptyState';
import { ErrorState } from '@/components/common/ErrorState';
import { LoadingOverlay } from '@/components/common/LoadingOverlay';
import type { FriendlyError } from '@/lib/errorMapper';

export interface ChartFrameProps {
  children: ReactNode;
  /** Fixed height. Charts need one: a percentage height inside auto-height
   *  parents collapses to zero and the chart silently does not render. */
  height?: number;
  isLoading?: boolean;
  error?: FriendlyError | null;
  onRetry?: () => void;
  isEmpty?: boolean;
  emptyTitle?: string;
  emptyMessage?: string;
  /** A plain-text equivalent of the chart, for screen readers. */
  summary?: string;
  className?: string;
}

/**
 * The shell every chart sits in: a fixed height, the four states, and a text
 * summary for anyone who cannot see the picture.
 *
 * The summary is not decoration. A bar chart conveys nothing to a screen
 * reader, and in an investigation tool "nothing" is the wrong answer, so each
 * chart passes a sentence stating what it shows and the headline numbers.
 */
export function ChartFrame({
  children,
  height = 240,
  isLoading = false,
  error = null,
  onRetry,
  isEmpty = false,
  emptyTitle = 'No data for this window',
  emptyMessage,
  summary,
  className,
}: ChartFrameProps) {
  if (error) {
    return <ErrorState error={error} onRetry={onRetry} compact className={className} />;
  }

  if (!isLoading && isEmpty) {
    return <EmptyState title={emptyTitle} message={emptyMessage} compact className={className} />;
  }

  return (
    <div className={clsx('relative', className)} style={{ height }}>
      {isLoading ? <LoadingOverlay message="Loading chart" /> : null}

      {summary ? (
        <p className="mg-visually-hidden" role="img" aria-label={summary}>
          {summary}
        </p>
      ) : null}

      <div aria-hidden={summary ? true : undefined} className="h-full w-full">
        {children}
      </div>
    </div>
  );
}

/** Shared axis and grid styling, so every chart looks like the same chart. */
export const AXIS_PROPS = {
  stroke: 'currentColor',
  tick: { fontSize: 10, fill: 'currentColor' },
  tickLine: false,
  axisLine: false,
} as const;

export const GRID_PROPS = {
  stroke: 'currentColor',
  strokeOpacity: 0.12,
  strokeDasharray: '2 4',
  vertical: false,
} as const;

/**
 * Tooltip styling.
 *
 * Recharts renders tooltips with inline styles, so these cannot be Tailwind
 * classes; the values match the `--mg-surface` tokens closely enough that the
 * tooltip does not look foreign in either theme.
 */
export const TOOLTIP_PROPS = {
  contentStyle: {
    fontSize: 11,
    borderRadius: 6,
    border: '1px solid rgb(148 163 184 / 0.4)',
    background: 'rgb(255 255 255 / 0.98)',
    color: '#111620',
    padding: '6px 8px',
    boxShadow: '0 4px 12px rgb(15 23 42 / 0.12)',
  },
  labelStyle: { fontWeight: 600, marginBottom: 2 },
  itemStyle: { padding: 0 },
} as const;
