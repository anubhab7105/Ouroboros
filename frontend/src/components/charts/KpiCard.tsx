import clsx from 'clsx';
import type { ReactNode } from 'react';

import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { Tooltip } from '@/components/common/Tooltip';
import { formatCount } from '@/lib/amounts';

export interface KpiCardProps {
  label: string;
  value: number | string | null | undefined;
  /** What the number counts, exactly. Shown on hover and to screen readers. */
  definition: string;
  detail?: ReactNode;
  /** A left rule for a number that should pull the eye. Never colour alone. */
  emphasis?: 'none' | 'attention' | 'critical';
  isLoading?: boolean;
  onClick?: () => void;
  /** Label for the action, when the card is clickable. */
  actionLabel?: string;
  className?: string;
}

const EMPHASIS_CLASSES = {
  none: 'border-l-transparent',
  attention: 'border-l-risk-medium',
  critical: 'border-l-risk-critical',
} as const;

/**
 * A single headline number.
 *
 * Every KPI carries its definition. "Open alerts: 412" is ambiguous — does it
 * include acknowledged ones, or alerts on closed cases? An investigator acting
 * on the wrong reading wastes a shift, so the definition travels with the
 * number rather than living in a wiki.
 *
 * A value of `null` renders as an em dash, never as 0: "we could not compute
 * this" and "there are none" lead to opposite decisions.
 */
export function KpiCard({
  label,
  value,
  definition,
  detail,
  emphasis = 'none',
  isLoading = false,
  onClick,
  actionLabel,
  className,
}: KpiCardProps) {
  const display =
    isLoading
      ? null
      : typeof value === 'number'
        ? formatCount(value)
        : typeof value === 'string' && value.length > 0
          ? value
          : '—';

  const body = (
    <>
      <div className="flex items-center gap-1">
        <span className="text-2xs font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
          {label}
        </span>
        <Tooltip content={definition}>
          <span
            aria-hidden="true"
            className="flex h-3.5 w-3.5 cursor-help items-center justify-center rounded-full border border-ink-300 text-[8px] font-bold text-ink-500 dark:border-ink-600 dark:text-ink-400"
          >
            i
          </span>
        </Tooltip>
      </div>

      <p className="mt-1.5 text-2xl font-semibold tabular tracking-tight text-ink-900 dark:text-ink-50">
        {isLoading ? <LoadingSpinner size="sm" label="Loading" /> : display}
      </p>

      {detail ? (
        <p className="mt-0.5 text-2xs text-ink-500 dark:text-ink-400">{detail}</p>
      ) : null}

      <span className="mg-visually-hidden">{definition}</span>
    </>
  );

  const shell = clsx(
    'rounded-card border border-l-4 bg-white p-3.5 dark:bg-ink-900',
    'border-ink-200 dark:border-ink-700',
    EMPHASIS_CLASSES[emphasis],
    className,
  );

  if (!onClick) return <div className={shell}>{body}</div>;

  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={actionLabel ?? `${label}: open the matching list`}
      className={clsx(
        shell,
        'text-left transition-colors duration-fast hover:border-accent-400 hover:bg-ink-50 dark:hover:bg-ink-800',
      )}
    >
      {body}
    </button>
  );
}
