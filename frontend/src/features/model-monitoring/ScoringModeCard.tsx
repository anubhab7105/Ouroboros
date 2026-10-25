import { Badge } from '@/components/common/Badge';
import { Card } from '@/components/common/Card';
import { KeyValueList } from '@/components/common/KeyValueList';
import { StatusPill } from '@/components/common/StatusPill';
import { formatDateTime } from '@/lib/dates';
import { humaniseField, truncateId } from '@/lib/formatters';
import type { ModelCurrent, ModelMetricsStatus } from '@/types/model';

export interface ScoringModeCardProps {
  status?: ModelMetricsStatus;
  current?: ModelCurrent;
  isLoading?: boolean;
}

/**
 * What is actually producing scores.
 *
 * This is the most important card in the application, and the reason is
 * uncomfortable: a deployment with no trained model still produces scores, in
 * the same 0-100 range, through a hand-set heuristic. Nothing downstream looks
 * different. An analyst ranking accounts by score, and a reader of a report
 * quoting one, are entitled to know which of the two they are looking at.
 *
 * So the card leads with the mode, names the fallback explicitly when one is
 * in force, and reports whether the model artefact is actually present on
 * disk — a model row with a missing file scores nothing, which is a failure
 * that otherwise looks like success.
 */
export function ScoringModeCard({ status, current, isLoading }: ScoringModeCardProps) {
  const mode = current?.scoring_mode ?? status?.scoring_mode;
  const activeVersion = current?.active_version;
  const usingFallback = mode !== 'TRAINED_MODEL';

  const artifactStatus = status?.artifact_status ?? {};
  const artifactEntries = Object.entries(artifactStatus);

  return (
    <Card
      title="Scoring"
      description="What produced the scores you are seeing elsewhere in the application."
      actions={mode ? <StatusPill kind="scoring-mode" value={mode} /> : null}
      caveats={status?.caveats ?? current?.caveats}
    >
      {isLoading ? (
        <p className="text-xs text-ink-500 dark:text-ink-400">Loading…</p>
      ) : (
        <>
          {usingFallback ? (
            <p
              role="note"
              className="mb-4 rounded-md border border-ink-200 bg-amber-50 p-3 text-xs leading-relaxed text-amber-900 dark:border-ink-700 dark:bg-amber-950/40 dark:text-amber-200"
            >
              No trained model is scoring. Scores are coming from{' '}
              <span className="font-semibold">
                {current?.fallback_label ?? status?.fallback_label ?? 'a fallback scorer'}
              </span>
              , whose weights are hand-set rather than learned. They are on the same 0-100 scale as
              a model's and are <span className="font-semibold">not</span> comparable to one, are
              not calibrated, and are not probabilities. They remain usable for ranking accounts by
              how much they merit a look.
            </p>
          ) : null}

          <KeyValueList
            columns={3}
            entries={[
              {
                label: 'Mode',
                value: mode ? humaniseField(mode) : '—',
              },
              {
                label: 'Active model version',
                value: current?.active_model_version ?? status?.active_model_version ?? 'None',
                mono: true,
              },
              {
                label: 'Feature schema',
                value: current?.feature_schema_version ?? status?.feature_schema_version ?? '—',
                mono: true,
                help: 'Scores computed under different schema versions are not directly comparable.',
              },
              {
                label: 'Trained model required',
                value: (current?.require_trained_model ?? status?.require_trained_model)
                  ? 'Yes'
                  : 'No',
                help: 'When required and absent, analysis refuses to run rather than falling back silently.',
              },
              {
                label: 'Dataset mode',
                value: status?.dataset_mode ? humaniseField(status.dataset_mode) : '—',
                help: 'This platform is built for synthetic data and says so rather than implying otherwise.',
              },
              {
                label: 'Feature schema published',
                value: status?.feature_schema_available ? 'Yes' : 'No',
              },
            ]}
          />

          {activeVersion ? (
            <div className="mt-4 border-t border-ink-200 pt-3 dark:border-ink-700">
              <h3 className="mb-2 flex items-center gap-1.5 text-2xs font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
                Active version
                {!activeVersion.artifact_available ? (
                  <Badge
                    tone="danger"
                    title="The version row exists but its artefact file is missing, so this model cannot score. Nothing downstream will say so."
                  >
                    Artefact missing
                  </Badge>
                ) : null}
              </h3>

              <KeyValueList
                columns={3}
                entries={[
                  { label: 'Version', value: activeVersion.version, mono: true },
                  { label: 'Type', value: humaniseField(activeVersion.model_type) },
                  { label: 'Split strategy', value: humaniseField(activeVersion.split_strategy) },
                  {
                    label: 'Trained',
                    value: activeVersion.training_finished_at
                      ? formatDateTime(activeVersion.training_finished_at)
                      : '—',
                  },
                  {
                    label: 'Training seed',
                    value:
                      activeVersion.training_seed !== null &&
                      activeVersion.training_seed !== undefined
                        ? String(activeVersion.training_seed)
                        : '—',
                    help: 'Recorded so a training run can be reproduced exactly.',
                  },
                  {
                    label: 'Dataset fingerprint',
                    value: activeVersion.dataset_fingerprint
                      ? truncateId(activeVersion.dataset_fingerprint, 10)
                      : '—',
                    mono: true,
                  },
                  {
                    label: 'Artefact checksum',
                    value: activeVersion.artifact_checksum
                      ? `${truncateId(activeVersion.artifact_checksum, 10)} (${activeVersion.checksum_algorithm ?? 'unknown'})`
                      : '—',
                    mono: true,
                    wide: true,
                    help: 'Lets the file in use be shown to be the file that was trained.',
                  },
                ]}
              />

              {activeVersion.notes ? (
                <p className="mt-2 text-2xs leading-relaxed text-ink-600 dark:text-ink-300">
                  {activeVersion.notes}
                </p>
              ) : null}
            </div>
          ) : null}

          {artifactEntries.length > 0 ? (
            <div className="mt-4 border-t border-ink-200 pt-3 dark:border-ink-700">
              <h3 className="mb-1.5 text-2xs font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
                Artefacts on disk
              </h3>
              <dl className="space-y-1">
                {artifactEntries.map(([key, value]) => (
                  <div key={key} className="flex gap-2 text-2xs">
                    <dt className="w-44 shrink-0 font-medium text-ink-600 dark:text-ink-300">
                      {humaniseField(key)}
                    </dt>
                    <dd className="font-mono text-ink-800 dark:text-ink-100">
                      {typeof value === 'boolean' ? (value ? 'present' : 'missing') : String(value)}
                    </dd>
                  </div>
                ))}
              </dl>
            </div>
          ) : null}
        </>
      )}
    </Card>
  );
}
