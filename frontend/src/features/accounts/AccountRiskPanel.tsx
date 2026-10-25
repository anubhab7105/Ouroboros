import { Badge } from '@/components/common/Badge';
import { Card } from '@/components/common/Card';
import { EmptyState } from '@/components/common/EmptyState';
import { KeyValueList } from '@/components/common/KeyValueList';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { RiskBadge } from '@/components/common/RiskBadge';
import { StatusPill } from '@/components/common/StatusPill';
import { RuleHitsTable } from '@/components/tables/RuleHitsTable';
import { formatPercent, formatScore } from '@/lib/amounts';
import { SCORE_SEMANTICS } from '@/lib/constants';
import { formatDateTime } from '@/lib/dates';
import { humaniseField, truncateId } from '@/lib/formatters';
import type { AccountAssessment } from '@/types/account';
import type { RiskBand } from '@/types/common';

export interface AccountRiskPanelProps {
  assessment?: AccountAssessment;
  isLoading?: boolean;
  onSelectEvidence?: (reference: string) => void;
}

/** One row of the component breakdown, read out of `components_json`. */
interface ComponentRow {
  name: string;
  /** Null when the component could not be computed — never a zero. */
  value: number | null;
  weight: number | null;
  available: boolean;
}

/**
 * Read the component breakdown out of the assessment's JSON column.
 *
 * The shape is the scorer's own, and it varies by scoring mode, so this reads
 * defensively: a component with no recognisable value is reported as
 * unavailable rather than as zero. The distinction is the whole point of the
 * panel — a component that could not be computed had its weight redistributed
 * among the others, and treating it as a zero contribution would understate
 * every score it touched.
 */
function readComponents(raw: unknown): ComponentRow[] {
  if (!raw || typeof raw !== 'object') return [];

  const source = (raw as { components?: unknown }).components ?? raw;
  if (!source || typeof source !== 'object') return [];

  const entries: Array<[string, unknown]> = Array.isArray(source)
    ? (source as Array<Record<string, unknown>>).map((item) => [
        String(item.name ?? item.component ?? 'component'),
        item,
      ])
    : Object.entries(source as Record<string, unknown>);

  return entries.map(([name, value]): ComponentRow => {
    if (typeof value === 'number') {
      return { name, value, weight: null, available: Number.isFinite(value) };
    }

    if (value && typeof value === 'object') {
      const record = value as Record<string, unknown>;
      const numeric = [record.normalised_value, record.value, record.score].find(
        (candidate) => typeof candidate === 'number',
      ) as number | undefined;
      const weight = [record.effective_weight, record.weight].find(
        (candidate) => typeof candidate === 'number',
      ) as number | undefined;
      const available =
        record.available === undefined ? numeric !== undefined : record.available === true;

      return { name, value: numeric ?? null, weight: weight ?? null, available };
    }

    return { name, value: null, weight: null, available: false };
  });
}

/**
 * The risk assessment, and why it says what it says.
 *
 * Three things are kept distinct and are easy to conflate:
 *
 * - **`as_of` versus `scored_at`.** The first is the instant assessed; the
 *   features saw only data strictly before it. The second is when the scoring
 *   actually ran. A re-run over last month's data is correct about last month.
 *
 * - **An unavailable component versus a zero one.** When a component has no
 *   data its weight is redistributed across the rest; it is not scored as
 *   zero, and the panel names which ones were missing.
 *
 * - **Scoring mode.** A score from the heuristic fallback and one from a
 *   trained model are on the same 0-100 scale but are not comparable, so the
 *   mode is shown next to the score rather than buried.
 */
export function AccountRiskPanel({
  assessment,
  isLoading,
  onSelectEvidence,
}: AccountRiskPanelProps) {
  if (isLoading) {
    return (
      <Card title="Risk assessment">
        <LoadingSpinner label="Loading assessment" />
      </Card>
    );
  }

  if (!assessment || !assessment.available || !assessment.assessment) {
    return (
      <Card title="Risk assessment">
        <EmptyState
          title="This account has not been assessed"
          message={
            assessment?.message ??
            'No analysis run has produced an assessment for it. That is not a low score — it is the absence of one.'
          }
          compact
        />
      </Card>
    );
  }

  const detail = assessment.assessment;
  const components = readComponents(detail.components_json);
  const unavailable = components.filter((component) => !component.available);

  const explanation =
    detail.explanation_json && typeof detail.explanation_json === 'object'
      ? ((detail.explanation_json as { summary?: unknown }).summary ?? null)
      : null;

  return (
    <Card
      title="Risk assessment"
      description={SCORE_SEMANTICS}
      actions={
        <RiskBadge band={detail.risk_band as RiskBand} score={detail.score} />
      }
    >
      <KeyValueList
        columns={3}
        entries={[
          { label: 'Score', value: formatScore(detail.score), mono: true },
          { label: 'Band', value: humaniseField(detail.risk_band) },
          {
            label: 'Scored by',
            value: <StatusPill kind="scoring-mode" value={detail.scoring_mode} />,
          },
          {
            label: 'Assessed as of',
            value: formatDateTime(detail.as_of),
            help: 'Features saw only data from strictly before this instant.',
          },
          {
            label: 'Scoring ran at',
            value: formatDateTime(detail.scored_at),
            help: 'Usually later than the as-of instant. An assessment can be reproduced for a past date.',
          },
          {
            label: 'Score version',
            value: detail.score_version ?? '—',
            mono: true,
            help: 'The fusion configuration in force. Scores from different versions are not directly comparable.',
          },
          {
            label: 'Model version',
            value: detail.model_version_id ? truncateId(detail.model_version_id, 8) : 'None',
            mono: true,
            help: detail.model_version_id
              ? undefined
              : 'No trained model contributed; the heuristic fallback produced this score.',
          },
          {
            label: 'Dataset fingerprint',
            value: detail.dataset_fingerprint ? truncateId(detail.dataset_fingerprint, 8) : '—',
            mono: true,
            help: 'Identifies the exact data this assessment was computed from.',
          },
          {
            label: 'Feature snapshot',
            value: detail.feature_snapshot_id ? truncateId(detail.feature_snapshot_id, 8) : '—',
            mono: true,
          },
        ]}
      />

      {typeof explanation === 'string' && explanation.length > 0 ? (
        <p className="mt-4 rounded-md border border-ink-200 bg-ink-50 p-3 text-xs leading-relaxed text-ink-800 dark:border-ink-700 dark:bg-ink-800/60 dark:text-ink-100">
          {explanation}
        </p>
      ) : null}

      {components.length > 0 ? (
        <div className="mt-4 border-t border-ink-200 pt-3 dark:border-ink-700">
          <h3 className="mb-2 text-2xs font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
            Score components
          </h3>

          <ul className="space-y-1.5">
            {components.map((component) => (
              <li key={component.name} className="flex items-center gap-2">
                <span className="w-40 shrink-0 text-2xs text-ink-700 dark:text-ink-200">
                  {humaniseField(component.name)}
                </span>

                {component.available && component.value !== null ? (
                  <>
                    <span
                      aria-hidden="true"
                      className="h-1.5 min-w-[2px] rounded-sm bg-accent-500 dark:bg-accent-400"
                      style={{
                        width: `${Math.min(100, Math.max(0, (component.value ?? 0) * 100))}%`,
                      }}
                    />
                    <span className="text-2xs tabular text-ink-600 dark:text-ink-300">
                      {formatPercent(component.value)}
                      {component.weight !== null
                        ? ` · weight ${formatPercent(component.weight)}`
                        : ''}
                    </span>
                  </>
                ) : (
                  <Badge
                    tone="neutral"
                    title="No data for this component. Its weight was redistributed across the others — it was not scored as zero."
                  >
                    Not available
                  </Badge>
                )}
              </li>
            ))}
          </ul>

          {unavailable.length > 0 ? (
            <p className="mt-2 text-2xs leading-relaxed text-ink-600 dark:text-ink-300">
              {unavailable.length} component{unavailable.length === 1 ? '' : 's'} had no data. The
              remaining weights were renormalised, so this score is computed from fewer inputs than
              a complete assessment and is correspondingly less informative.
            </p>
          ) : null}
        </div>
      ) : null}

      {assessment.rule_hits.length > 0 ? (
        <div className="mt-4 border-t border-ink-200 pt-3 dark:border-ink-700">
          <h3 className="mb-2 text-2xs font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
            Rules evaluated
          </h3>
          <RuleHitsTable
            rows={assessment.rule_hits}
            includeNotTriggered
            onSelectEvidence={onSelectEvidence}
          />
        </div>
      ) : null}

      {assessment.indicators.length > 0 ? (
        <div className="mt-4 border-t border-ink-200 pt-3 dark:border-ink-700">
          <h3 className="mb-2 text-2xs font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
            Indicators
          </h3>
          <ul className="space-y-1.5">
            {assessment.indicators.map((indicator) => (
              <li key={indicator.id} className="text-2xs text-ink-700 dark:text-ink-200">
                <span className="font-medium">{indicator.title}</span>
                <span className="text-ink-500 dark:text-ink-400">
                  {' '}
                  · {humaniseField(indicator.indicator_type)} · {humaniseField(indicator.severity)}
                </span>
                {indicator.explanation ? (
                  <span className="block text-ink-600 dark:text-ink-300">
                    {indicator.explanation}
                  </span>
                ) : null}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </Card>
  );
}
