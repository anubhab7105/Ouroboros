import clsx from 'clsx';
import type { ReactNode } from 'react';

export interface EmptyStateProps {
  title: string;
  /** Why it is empty and what to do, not just "no data". */
  message?: string;
  action?: ReactNode;
  icon?: ReactNode;
  className?: string;
  compact?: boolean;
}

/**
 * The empty state for a list or panel.
 *
 * `message` matters more than it looks. "No results" leaves an analyst unsure
 * whether the filter is too narrow, the analysis has not run, or the data was
 * never imported — three very different next steps. Callers pass the specific
 * reason.
 */
export function EmptyState({
  title,
  message,
  action,
  icon,
  className,
  compact = false,
}: EmptyStateProps) {
  return (
    <div
      className={clsx(
        'flex flex-col items-center justify-center text-center',
        compact ? 'gap-1.5 py-6' : 'gap-2 py-12',
        className,
      )}
    >
      {icon ? <div className="text-ink-300 dark:text-ink-600">{icon}</div> : null}
      <p className="text-sm font-semibold text-ink-700 dark:text-ink-200">{title}</p>
      {message ? (
        <p className="max-w-md text-xs leading-relaxed text-ink-500 dark:text-ink-400">{message}</p>
      ) : null}
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  );
}
