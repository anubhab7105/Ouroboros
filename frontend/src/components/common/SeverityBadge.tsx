import clsx from 'clsx';

import { humaniseEnum } from '@/lib/formatters';
import { SEVERITY_TOKENS } from '@/lib/constants';
import type { Severity } from '@/types/common';

export interface SeverityBadgeProps {
  /** As the API sends it: a plain string, even though an enum backs it. */
  severity: Severity | string | null | undefined;
  className?: string;
}

/** A severity, with its text label. Same reasoning as RiskBadge. */
export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  if (!severity) {
    return <span className={clsx('text-xs text-ink-400', className)}>—</span>;
  }

  const token = SEVERITY_TOKENS[severity as Severity];

  if (!token) {
    // A severity this build does not know: humanise rather than drop it.
    return (
      <span className={clsx('mg-badge bg-ink-100 text-ink-700 dark:bg-ink-800 dark:text-ink-300', className)}>
        {humaniseEnum(severity)}
      </span>
    );
  }

  return (
    <span
      className={clsx('mg-badge border-l-2', token.className, className)}
      style={{ borderLeftColor: token.hex }}
    >
      {token.label}
    </span>
  );
}
