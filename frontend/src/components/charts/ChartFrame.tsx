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


