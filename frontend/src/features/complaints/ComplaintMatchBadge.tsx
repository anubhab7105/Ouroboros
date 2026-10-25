import { Badge } from '@/components/common/Badge';
import { Tooltip } from '@/components/common/Tooltip';
import { formatConfidence } from '@/lib/amounts';
import { MATCH_METHOD_LABELS, MATCH_TIER_TOKENS } from '@/lib/constants';
import { humaniseEnum } from '@/lib/formatters';

export interface ComplaintMatchBadgeProps {
  tier: number;
  method: string;
  deterministic: boolean;
  confidence?: number | null;
  /** Show the method alongside the tier. */
  verbose?: boolean;
}

/**
 * How a complaint was linked to a record, in one control.
 *
 * The distinction this badge exists to protect is between an identity and an
 * inference:
 *
 * - **Tiers 1-2** are identities. The complaint named a transaction reference
 *   or an account id, and that record exists. There is no confidence value,
 *   and the badge says "identity" where a number would otherwise go. Printing
 *   1.000 there would imply a measurement nobody made.
 *
 * - **Tiers 3-5** are inferences — a shared entity within the complaint's
 *   window, proximity in amount and time, or a reference pulled out of
 *   narrative text. Each carries a confidence, and tier 5 in particular is
 *   text extraction and the weakest signal the platform produces.
 *
 * Both the tier number and a text label are always present, so the badge does
 * not rely on its colour to carry the distinction.
 */
export function ComplaintMatchBadge({
  tier,
  method,
  deterministic,
  confidence,
  verbose = false,
}: ComplaintMatchBadgeProps) {
  const token = MATCH_TIER_TOKENS[tier];
  const methodLabel = MATCH_METHOD_LABELS[method] ?? humaniseEnum(method);

  const explanation = [
    token?.description ?? `Tier ${tier} correlation.`,
    `Matched by ${methodLabel.toLowerCase()}.`,
    deterministic
      ? 'This is an identity match: the complaint named a reference that exists, so no confidence value applies.'
      : confidence !== null && confidence !== undefined
        ? `Inferred, with confidence ${formatConfidence(confidence)}. A lead until a reviewer accepts it.`
        : 'Inferred. No confidence was recorded.',
  ].join(' ');

  return (
    <Tooltip content={explanation}>
      <span className="inline-flex items-center gap-1">
        <Badge accentColor={token?.hex}>
          Tier {tier}
          <span className="font-normal text-ink-600 dark:text-ink-300">
            {deterministic ? 'identity' : 'inferred'}
          </span>
        </Badge>

        {verbose ? (
          <span className="text-2xs text-ink-600 dark:text-ink-300">{methodLabel}</span>
        ) : null}

        {!deterministic && confidence !== null && confidence !== undefined ? (
          <span className="font-mono text-2xs tabular text-ink-600 dark:text-ink-300">
            {formatConfidence(confidence)}
          </span>
        ) : null}
      </span>
    </Tooltip>
  );
}
