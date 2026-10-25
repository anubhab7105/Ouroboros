import { Badge } from '@/components/common/Badge';
import { Card } from '@/components/common/Card';
import { SCORE_SEMANTICS } from '@/lib/constants';
import { humaniseField } from '@/lib/formatters';
import type { ModelLimitations } from '@/types/model';

export interface LimitationsPanelProps {
  limitations?: ModelLimitations;
  isLoading?: boolean;
}

/**
 * What may and may not be claimed about the scores.
 *
 * These are machine-readable guard rails the server publishes, not a
 * disclaimer somebody wrote once. `probability_claim_allowed` false means the
 * score must never be described as a likelihood of fraud;
 * `calibration_claim_allowed` false means it must not be called calibrated.
 *
 * Rendering them as a yes/no list rather than prose is deliberate: an analyst
 * writing a case note or a reviewer reading a report needs to be able to check
 * at a glance whether the sentence they are about to write is one this
 * platform supports.
 */
export function LimitationsPanel({ limitations, isLoading }: LimitationsPanelProps) {
  const claims = limitations
    ? [
        {
          key: 'probability_claim_allowed',
          allowed: limitations.probability_claim_allowed,
          allowedText: 'Scores may be described as probabilities.',
          deniedText:
            'Scores must NOT be described as probabilities or likelihoods of fraud. They rank accounts for attention; nothing more.',
        },
        {
          key: 'calibration_claim_allowed',
          allowed: limitations.calibration_claim_allowed,
          allowedText: 'Scores may be described as calibrated.',
          deniedText:
            'Scores must NOT be described as calibrated. A score of 80 does not mean twice the risk of 40.',
        },
        {
          key: 'synthetic_only',
          allowed: !limitations.synthetic_only,
          allowedText: 'This deployment is configured for real data.',
          deniedText:
            'This platform is built and configured for synthetic data. Output is not a finding about any real person or account.',
        },
        {
          key: 'production_ready',
          allowed: limitations.production_ready,
          allowedText: 'This configuration is marked production ready.',
          deniedText:
            'This configuration is NOT production ready. It must not be used to make or support a decision about a real account.',
        },
      ]
    : [];

  return (
    <Card
      title="What may be claimed"
      description="Published by the server, so the interface, the reports and any downstream use agree on the limits."
      caveats={limitations?.caveats}
    >
      <p className="rounded-md border border-ink-200 bg-ink-50 p-3 text-xs leading-relaxed text-ink-800 dark:border-ink-700 dark:bg-ink-800/60 dark:text-ink-100">
        {SCORE_SEMANTICS}
      </p>

      {isLoading ? (
        <p className="mt-3 text-xs text-ink-500 dark:text-ink-400">Loading…</p>
      ) : !limitations ? null : (
        <>
          <ul className="mt-4 space-y-2.5">
            {claims.map((claim) => (
              <li key={claim.key} className="flex items-start gap-2">
                <Badge
                  tone={claim.allowed ? 'neutral' : 'warning'}
                  title={humaniseField(claim.key)}
                >
                  {claim.allowed ? 'Permitted' : 'Not permitted'}
                </Badge>
                <p className="min-w-0 text-2xs leading-relaxed text-ink-700 dark:text-ink-200">
                  {claim.allowed ? claim.allowedText : claim.deniedText}
                </p>
              </li>
            ))}
          </ul>

          {limitations.limitations_summary ? (
            <p className="mt-4 whitespace-pre-line border-t border-ink-200 pt-3 text-2xs leading-relaxed text-ink-700 dark:border-ink-700 dark:text-ink-200">
              {limitations.limitations_summary}
            </p>
          ) : null}
        </>
      )}
    </Card>
  );
}
