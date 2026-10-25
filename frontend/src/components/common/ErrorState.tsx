import clsx from 'clsx';

import type { FriendlyError } from '@/lib/errorMapper';

import { Button } from './Button';

export interface ErrorStateProps {
  error: FriendlyError | null;
  onRetry?: () => void;
  className?: string;
  compact?: boolean;
}

/**
 * A failed request.
 *
 * Shows three things: what happened, what to do about it, and the request id.
 * The request id is the part that makes a support conversation possible, so it
 * is rendered selectably rather than buried in a console log.
 *
 * Retry is only offered when retrying can actually help — a 403 will answer
 * the same way however many times it is asked.
 */
export function ErrorState({ error, onRetry, className, compact = false }: ErrorStateProps) {
  if (!error) return null;

  return (
    <div
      role="alert"
      className={clsx(
        'rounded-card border border-state-danger/30 bg-red-50 dark:bg-red-950/25',
        compact ? 'p-3' : 'p-5',
        className,
      )}
    >
      <p className="text-sm font-semibold text-red-900 dark:text-red-200">{error.title}</p>
      <p className="mt-1 text-xs leading-relaxed text-red-900/90 dark:text-red-200/90">
        {error.message}
      </p>

      {error.action ? (
        <p className="mt-2 text-xs font-medium text-red-900 dark:text-red-200">{error.action}</p>
      ) : null}

      {Object.keys(error.fieldErrors).length > 0 ? (
        <ul className="mt-2 space-y-0.5">
          {Object.entries(error.fieldErrors)
            .slice(0, 6)
            .map(([field, message]) => (
              <li key={field} className="text-2xs text-red-900/80 dark:text-red-200/80">
                <span className="font-mono">{field}: </span>
                {message}
              </li>
            ))}
        </ul>
      ) : null}

      {error.requestId ? (
        <p className="mt-2 font-mono text-2xs text-red-900/70 dark:text-red-200/70">
          Request {error.requestId}
        </p>
      ) : null}

      <div className="mt-3 flex items-center gap-3">
        {error.isRetryable && onRetry ? (
          <Button size="sm" variant="secondary" onClick={onRetry}>
            Retry
          </Button>
        ) : null}

        {error.requestId ? (
          <span className="text-2xs text-red-900/70 dark:text-red-200/70">
            Request id <span className="mg-id select-all">{error.requestId}</span>
          </span>
        ) : null}
      </div>
    </div>
  );
}
