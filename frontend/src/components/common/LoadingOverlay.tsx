import clsx from 'clsx';

import { LoadingSpinner } from './LoadingSpinner';

export interface LoadingOverlayProps {
  message?: string;
  className?: string;
  /** Dim the content behind instead of hiding it. */
  translucent?: boolean;
}

/**
 * An overlay for a region that is refetching.
 *
 * Translucent by default so the previous data stays readable underneath. In a
 * queue the analyst was mid-way through reading, blanking the panel on every
 * refetch loses their place; dimming it signals the update without doing that.
 */
export function LoadingOverlay({
  message = 'Loading',
  className,
  translucent = true,
}: LoadingOverlayProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      className={clsx(
        'absolute inset-0 z-10 flex flex-col items-center justify-center gap-2',
        translucent ? 'bg-white/70 dark:bg-ink-900/70' : 'bg-white dark:bg-ink-900',
        className,
      )}
    >
      <LoadingSpinner size="md" label={null} />
      <p className="text-xs font-medium text-ink-600 dark:text-ink-300">{message}</p>
    </div>
  );
}
