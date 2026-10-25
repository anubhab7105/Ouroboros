import { Badge } from '@/components/common/Badge';
import { Card } from '@/components/common/Card';
import { DataTable, type Column } from '@/components/common/DataTable';
import { EmptyState } from '@/components/common/EmptyState';
import { formatCount, formatRatio } from '@/lib/amounts';
import { formatDateTime } from '@/lib/dates';
import { formatCellValue, humaniseField, truncateId } from '@/lib/formatters';
import type { ModelEvaluation } from '@/types/model';

export interface MetricsSummaryProps {
  evaluations: ModelEvaluation[];
  isLoading?: boolean;
  /** True when no trained model is scoring, which changes how to read these. */
  usingFallback?: boolean;
}

/**
 * Metric names worth explaining, and the trap in each.
 *
 * Fraud detection is extremely imbalanced — a fraction of a percent of
 * accounts are mules — and that makes the obvious metrics misleading in
 * specific, nameable ways. A model that predicts "not a mule" every time
 * scores above 99% accuracy, and precision at the top of a ranked list is
 * what an analyst's working day actually depends on.
 */
const METRIC_NOTES: Record<string, string> = {
  accuracy:
    'Nearly useless here. With under 1% positives, always answering "not a mule" scores above 99%.',
  precision: 'Of the accounts flagged, the share that were mules. Drives wasted analyst time.',
  recall: 'Of the actual mules, the share that were flagged. Drives mules missed.',
  f1: 'The harmonic mean of precision and recall. A single number that hides which of the two is weak.',
  roc_auc:
    'Ranking quality over all thresholds. Looks flattering on imbalanced data; prefer PR-AUC.',
  pr_auc: 'Precision-recall area. The honest summary for data this imbalanced.',
  average_precision: 'Equivalent to PR-AUC. The right headline figure here.',
  brier_score: 'Calibration error, lower better. Only meaningful if calibration is claimed.',
  log_loss: 'Penalises confident wrong answers. Lower is better.',
  precision_at_k:
    'Precision within the top K ranked accounts. The closest metric to how the queue is worked.',
  threshold: 'The decision cut-off these figures were computed at.',
  support: 'How many samples the figure was computed from. A small support is a noisy figure.',
};

/** Pull the numeric metrics out of an evaluation's open metrics map. */
function metricRows(evaluation: ModelEvaluation): Array<{ name: string; value: unknown }> {
  return Object.entries(evaluation.metrics_summary ?? {})
    .filter(([, value]) => value !== null && value !== undefined)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, value]) => ({ name, value }));
}

/**
 * Evaluation metrics for the model versions on record.
 *
 * Two things this panel refuses to do:
 *
 * - **It does not invent a headline number.** The metrics map is open-ended
 *   and varies between versions, so every metric present is shown with its
 *   name rather than one being promoted to "the score".
 *
 * - **It does not let a metric stand without its caveat.** Accuracy above 99%
 *   on this problem is the signature of a model that predicts the majority
 *   class, and a reader who sees the number without the note may conclude the
 *   opposite of the truth.
 *
 * The split strategy is shown per evaluation, because a random split on
 * transaction data leaks the future into the training set and inflates every
 * figure beneath it.
 */
export function MetricsSummary({
  evaluations,
  isLoading,
  usingFallback = false,
}: MetricsSummaryProps) {
  const columns: Array<Column<ModelEvaluation>> = [
    {
      key: 'created_at',
      header: 'Evaluated',
      render: (row) => (
        <span className="whitespace-nowrap text-xs tabular text-ink-700 dark:text-ink-200">
          {formatDateTime(row.created_at)}
        </span>
      ),
      width: '18%',
    },
    {
      key: 'split_strategy',
      header: 'Split',
      render: (row) => (
        <Badge
          tone={row.split_strategy?.toLowerCase().includes('random') ? 'warning' : 'neutral'}
          title={
            row.split_strategy?.toLowerCase().includes('random')
              ? 'A random split on time-ordered transaction data leaks future information into training and inflates every figure here.'
              : 'How the holdout was cut.'
          }
        >
          {humaniseField(row.split_strategy)}
        </Badge>
      ),
      width: '16%',
    },
    {
      key: 'sample_count',
      header: 'Samples',
      numeric: true,
      render: (row) => (
        <span className="text-xs tabular">{formatCount(row.sample_count)}</span>
      ),
      width: '12%',
    },
    {
      key: 'metrics',
      header: 'Metrics',
      render: (row) => {
        const rows = metricRows(row);

        if (rows.length === 0) {
          return (
            <span className="text-2xs text-ink-400 dark:text-ink-500">
              No metrics recorded
            </span>
          );
        }

        return (
          <ul className="space-y-0.5">
            {rows.map((metric) => (
              <li key={metric.name} className="flex flex-wrap items-baseline gap-1.5 text-2xs">
                <span
                  className="font-medium text-ink-700 dark:text-ink-200"
                  title={METRIC_NOTES[metric.name.toLowerCase()]}
                >
                  {humaniseField(metric.name)}
                </span>
                <span className="font-mono tabular text-ink-900 dark:text-ink-50">
                  {typeof metric.value === 'number'
                    ? formatRatio(metric.value, 4)
                    : formatCellValue(metric.value)}
                </span>
                {METRIC_NOTES[metric.name.toLowerCase()] ? (
                  <span className="text-ink-500 dark:text-ink-400">
                    — {METRIC_NOTES[metric.name.toLowerCase()]}
                  </span>
                ) : null}
              </li>
            ))}
          </ul>
        );
      },
      width: '44%',
    },
    {
      key: 'model_version_id',
      header: 'Version',
      render: (row) => (
        <span className="font-mono text-2xs text-ink-600 dark:text-ink-300" title={row.model_version_id}>
          {truncateId(row.model_version_id, 8)}
        </span>
      ),
      hideOnSmall: true,
      width: '10%',
    },
  ];

  return (
    <Card
      title="Evaluation metrics"
      description="Figures recorded against each model version, with the caveat each one carries on an imbalanced problem."
    >
      {usingFallback ? (
        <p className="mb-3 rounded-md border border-ink-200 bg-ink-50 p-3 text-2xs leading-relaxed text-ink-700 dark:border-ink-700 dark:bg-ink-800/60 dark:text-ink-200">
          No trained model is scoring at the moment, so these figures describe models on record
          rather than the scores currently being produced. The heuristic fallback has no evaluation
          metrics: its weights were set by hand, not learned, and there is nothing to measure them
          against.
        </p>
      ) : null}

      {!isLoading && evaluations.length === 0 ? (
        <EmptyState
          title="No evaluations recorded"
          message="No model version in this deployment has an evaluation against it. Scores are still being produced; they simply have no measured performance to quote."
          compact
        />
      ) : (
        <DataTable
          caption="Model evaluations with their metrics"
          columns={columns}
          rows={evaluations}
          rowKey={(row) => row.id}
          isLoading={isLoading}
          emptyTitle="No evaluations recorded"
        />
      )}
    </Card>
  );
}
