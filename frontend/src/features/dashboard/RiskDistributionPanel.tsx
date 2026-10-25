import { useNavigate } from 'react-router-dom';

import { RiskDistributionChart } from '@/components/charts/RiskDistributionChart';
import { Card } from '@/components/common/Card';
import { StatusPill } from '@/components/common/StatusPill';
import { formatCount, formatPercent } from '@/lib/amounts';
import { SCORE_SEMANTICS } from '@/lib/constants';
import type { FriendlyError } from '@/lib/errorMapper';
import { paths } from '@/routes/paths';
import type { DashboardAssessmentBreakdown } from '@/types/dashboard';

export interface RiskDistributionPanelProps {
  assessments?: DashboardAssessmentBreakdown;
  isLoading?: boolean;
  error?: FriendlyError | null;
  onRetry?: () => void;
}

/**
 * How assessed accounts fell across the risk bands, plus how they were scored.
 *
 * The scoring-mode breakdown is on the same card deliberately. A distribution
 * produced by a trained model and one produced by the heuristic fallback are
 * not comparable, and an analyst reading band counts without knowing which
 * produced them may draw a conclusion the scores do not support. When a
 * window contains both, both are listed.
 */
export function RiskDistributionPanel({
  assessments,
  isLoading,
  error,
  onRetry,
}: RiskDistributionPanelProps) {
  const navigate = useNavigate();

  const modes = Object.entries(assessments?.by_scoring_mode ?? {})
    .filter(([, count]) => count > 0)
    .sort((a, b) => b[1] - a[1]);

  const total = assessments?.total_in_window ?? 0;
  const explained = assessments?.explanation_available ?? 0;

  return (
    <Card
      title="Risk distribution"
      description={SCORE_SEMANTICS}
    >
      <RiskDistributionChart
        counts={assessments?.by_risk_band}
        isLoading={isLoading}
        error={error}
        onRetry={onRetry}
        onSelectBand={(band) => navigate(`${paths.accounts}?risk_band=${band}`)}
      />

      {modes.length > 0 ? (
        <div className="mt-4 border-t border-ink-200 pt-3 dark:border-ink-700">
          <p className="mb-1.5 text-2xs font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
            Scored by
          </p>
          <ul className="flex flex-wrap items-center gap-x-4 gap-y-1.5">
            {modes.map(([mode, count]) => (
              <li key={mode} className="flex items-center gap-1.5">
                <StatusPill kind="scoring-mode" value={mode} />
                <span className="text-2xs tabular text-ink-600 dark:text-ink-300">
                  {formatCount(count)}
                </span>
              </li>
            ))}
          </ul>

          {modes.length > 1 ? (
            <p className="mt-2 text-2xs leading-relaxed text-ink-600 dark:text-ink-300">
              This window mixes scoring modes. Scores from different modes are on the same 0-100
              scale but are not calibrated against each other, so rank accounts within a mode
              rather than across them.
            </p>
          ) : null}

          {total > 0 ? (
            <p className="mt-2 text-2xs text-ink-500 dark:text-ink-400">
              {formatCount(explained)} of {formatCount(total)} assessments (
              {formatPercent(explained / total)}) carry a written explanation.
            </p>
          ) : null}
        </div>
      ) : null}
    </Card>
  );
}
