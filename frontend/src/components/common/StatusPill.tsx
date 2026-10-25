import clsx from 'clsx';

import {
  ALERT_STATE_TOKENS,
  CASE_STATUS_TOKENS,
  DISPOSITION_TOKENS,
  SCORING_MODE_TOKENS,
  TRANSACTION_STATUS_TOKENS,
  type DisplayToken,
} from '@/lib/constants';
import { humaniseEnum } from '@/lib/formatters';

export type StatusKind =
  | 'alert'
  | 'case'
  | 'disposition'
  | 'scoring-mode'
  | 'transaction';

const REGISTRIES: Record<StatusKind, Record<string, DisplayToken>> = {
  alert: ALERT_STATE_TOKENS,
  case: CASE_STATUS_TOKENS,
  disposition: DISPOSITION_TOKENS,
  'scoring-mode': SCORING_MODE_TOKENS,
  transaction: TRANSACTION_STATUS_TOKENS,
};

export interface StatusPillProps {
  kind: StatusKind;
  value: string | null | undefined;
  className?: string;
  /** Show the token's explanation as a tooltip. On by default. */
  describe?: boolean;
}

/**
 * A workflow status, rendered from the shared token registry.
 *
 * One component for every status enum means a new state added on the backend
 * shows up with a sensible fallback label rather than an empty cell, and the
 * colour choices stay consistent across pages.
 */
export function StatusPill({ kind, value, className, describe = true }: StatusPillProps) {
  if (!value) {
    return <span className={clsx('text-xs text-ink-400', className)}>—</span>;
  }

  const token = REGISTRIES[kind][value];

  if (!token) {
    // Unknown value: show it humanised rather than blank, so a newly added
    // backend state is visible instead of silently disappearing.
    return (
      <span className={clsx('mg-badge bg-ink-100 text-ink-600 dark:bg-ink-800 dark:text-ink-300', className)}>
        {humaniseEnum(value)}
      </span>
    );
  }

  return (
    <span
      className={clsx('mg-badge', token.className, className)}
      title={describe ? token.description : undefined}
    >
      {token.label}
    </span>
  );
}
