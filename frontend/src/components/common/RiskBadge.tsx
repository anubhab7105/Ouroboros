import clsx from 'clsx';

import { RISK_BAND_TOKENS } from '@/lib/constants';
import { formatScore } from '@/lib/amounts';
import { humaniseEnum } from '@/lib/formatters';
import type { RiskBand } from '@/types/common';

export interface RiskBadgeProps {
  /**
   * The band as the API sends it, which is a plain string: the response
   * models type it as `str` even though an enum backs it. A value this build
   * does not know is rendered as itself rather than dropped.
   */
  band: RiskBand | string | null | undefined;
  score?: number | null;
  showScore?: boolean;
  className?: string;
}

/**
 * A risk band, always with its text label.
 *
 * The colour ramp is deliberately not a traffic light: LOW is slate rather
 * than green, because a low score means "not prioritised", not "cleared" — the
 * detector only finds typologies it already knows about. Rendering LOW in
 * green would tell an analyst the opposite of what the score means.
 *
 * The label is always present, so the badge still reads correctly for anyone
 * who cannot distinguish the colours.
 */
export function RiskBadge({ band, score, showScore = true, className }: RiskBadgeProps) {
  if (!band) {
    return (
      <span
        className={clsx('mg-badge bg-ink-100 text-ink-500 dark:bg-ink-800 dark:text-ink-400', className)}
        title="This account has not been assessed yet."
      >
        Not assessed
      </span>
    );
  }

  const token = RISK_BAND_TOKENS[band as RiskBand];

  if (!token) {
    // A band added on the backend: show it rather than rendering nothing.
    return (
      <span
        className={clsx('mg-badge bg-ink-100 text-ink-700 dark:bg-ink-800 dark:text-ink-300', className)}
        title="This risk band is not one this build recognises."
      >
        {humaniseEnum(band)}
        {showScore && score !== null && score !== undefined ? (
          <span className="font-mono font-normal tabular">{formatScore(score)}</span>
        ) : null}
      </span>
    );
  }

  return (
    <span
      className={clsx('mg-badge border-l-2', token.className, className)}
      style={{ borderLeftColor: token.hex }}
      title={token.description}
    >
      {token.label}
      {showScore && score !== null && score !== undefined ? (
        <span className="font-mono font-normal tabular">{formatScore(score)}</span>
      ) : null}
    </span>
  );
}
