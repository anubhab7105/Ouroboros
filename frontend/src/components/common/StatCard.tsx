import clsx from 'clsx';
import type { ReactNode } from 'react';

import { Tooltip } from './Tooltip';

export interface StatCardProps {
  label: string;
  value: ReactNode;
  /** Secondary line: a comparison, a share, a unit. */
  detail?: ReactNode;
  /** Explains what the number counts. Shown as a tooltip on the label. */
  help?: string;
  tone?: 'neutral' | 'attention' | 'critical';
  onClick?: () => void;
  className?: string;
}

const TONES = {
  neutral: 'border-ink-200 dark:border-ink-700',
  // Amber left rule: something needs looking at.
  attention: 'border-ink-200 border-l-4 border-l-risk-medium dark:border-ink-700',
  critical: 'border-ink-200 border-l-4 border-l-risk-critical dark:border-ink-700',
} as const;

/**
 * A single KPI tile.
 *
 * `help` is where the definition goes. "High risk accounts: 42" invites the
 * reader to assume a cumulative total, when it actually counts accounts whose
 * *latest assessment in the window* was HIGH or CRITICAL. Putting the
 * definition one hover away is what stops that number being quoted wrongly.
 */
export function StatCard({
  label,
  value,
  detail,
  help,
  tone = 'neutral',
  onClick,
  className,
}: StatCardProps) {
  const body = (
    <>
      <div className="flex items-center gap-1">
        <p className="text-2xs font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
          {label}
        </p>
        {help ? (
          <Tooltip content={help}>
            <span
              className="cursor-help text-2xs text-ink-400 dark:text-ink-500"
              aria-label={`What ${label} means`}
              tabIndex={0}
            >
              ⓘ
            </span>
          </Tooltip>
        ) : null}
      </div>

      <p className="mt-1.5 text-2xl font-semibold tabular leading-none text-ink-900 dark:text-ink-50">
        {value}
      </p>

      {detail ? (
        <p className="mt-1.5 text-2xs text-ink-500 dark:text-ink-400">{detail}</p>
      ) : null}
    </>
  );

  if (onClick) {
    return (
      <button
        type="button"
        onClick={onClick}
        className={clsx(
          'rounded-card border bg-white p-3 text-left shadow-card transition-colors duration-fast',
          'hover:border-accent-300 hover:bg-accent-50/40 dark:bg-ink-900 dark:hover:border-accent-700 dark:hover:bg-ink-800',
          TONES[tone],
          className,
        )}
      >
        {body}
      </button>
    );
  }

  return (
    <div
      className={clsx('rounded-card border bg-white p-3 shadow-card dark:bg-ink-900', TONES[tone], className)}
    >
      {body}
    </div>
  );
}
