import { useQuery } from '@tanstack/react-query';

import { Badge } from '@/components/common/Badge';
import { Card } from '@/components/common/Card';
import { DataTable, type Column } from '@/components/common/DataTable';
import { ErrorState } from '@/components/common/ErrorState';
import { Pagination } from '@/components/common/Pagination';
import { PageHeader } from '@/components/layout/PageHeader';
import { useApiError } from '@/hooks/useApiError';
import { usePagination } from '@/hooks/usePagination';
import { formatDateTime } from '@/lib/dates';
import { humaniseField, truncateId } from '@/lib/formatters';
import { queryKeys } from '@/lib/queryKeys';
import { pageInfo } from '@/types/common';
import type { ModelVersion } from '@/types/model';

import { FeatureSchemaTable } from './FeatureSchemaTable';
import { LimitationsPanel } from './LimitationsPanel';
import { MetricsSummary } from './MetricsSummary';
import { ScoringModeCard } from './ScoringModeCard';
import {
  fetchFeatureSchema,
  fetchModelCurrent,
  fetchModelLimitations,
  fetchModelStatus,
  fetchModelVersions,
} from './modelApi';

/**
 * Model monitoring.
 *
 * Ordered by what a reader most needs to know first: what is scoring right
 * now, what may be claimed about those scores, then the measured performance
 * of the versions on record, then the inputs.
 *
 * That order is deliberate. A reader who starts at the metrics table and
 * stops there can walk away believing a model is scoring when the heuristic
 * fallback is, which is the single most consequential misreading this page can
 * cause.
 */
export default function ModelMonitoringPage() {
  const { page, pageSize, setPage, setPageSize } = usePagination(10);

  const statusQuery = useQuery({
    queryKey: queryKeys.model.status(),
    queryFn: fetchModelStatus,
  });

  const currentQuery = useQuery({
    queryKey: queryKeys.model.current(),
    queryFn: fetchModelCurrent,
  });

  const limitationsQuery = useQuery({
    queryKey: queryKeys.model.limitations(),
    queryFn: fetchModelLimitations,
    staleTime: 10 * 60_000,
  });

  const schemaQuery = useQuery({
    queryKey: queryKeys.model.featureSchema(),
    queryFn: fetchFeatureSchema,
    staleTime: 10 * 60_000,
  });

  const versionsQuery = useQuery({
    queryKey: queryKeys.model.versions(page, pageSize),
    queryFn: () =>
      fetchModelVersions({
        page,
        page_size: pageSize,
        sort_by: 'created_at',
        sort_order: 'desc',
      }),
  });

  const statusError = useApiError(statusQuery.error);
  const versionsError = useApiError(versionsQuery.error);

  const usingFallback =
    (currentQuery.data?.scoring_mode ?? statusQuery.data?.scoring_mode) !== 'TRAINED_MODEL';

  const versionColumns: Array<Column<ModelVersion>> = [
    {
      key: 'version',
      header: 'Version',
      render: (row) => (
        <span className="flex items-center gap-1.5">
          <span className="font-mono text-xs text-ink-800 dark:text-ink-100">{row.version}</span>
          {row.is_active ? (
            <Badge tone="accent" title="The version currently selected for scoring.">
              Active
            </Badge>
          ) : null}
          {!row.artifact_available ? (
            <Badge
              tone="danger"
              title="The artefact file is missing on disk, so this version cannot score."
            >
              No artefact
            </Badge>
          ) : null}
        </span>
      ),
      width: '24%',
    },
    {
      key: 'model_type',
      header: 'Type',
      render: (row) => (
        <span className="text-xs text-ink-700 dark:text-ink-200">
          {humaniseField(row.model_type)}
        </span>
      ),
      width: '15%',
    },
    {
      key: 'feature_schema_version',
      header: 'Schema',
      render: (row) => (
        <span className="font-mono text-2xs text-ink-700 dark:text-ink-200">
          {row.feature_schema_version}
        </span>
      ),
      hideOnSmall: true,
      width: '12%',
    },
    {
      key: 'split_strategy',
      header: 'Split',
      render: (row) => (
        <Badge
          tone={row.split_strategy?.toLowerCase().includes('random') ? 'warning' : 'neutral'}
          title={
            row.split_strategy?.toLowerCase().includes('random')
              ? 'A random split on time-ordered data leaks the future into training.'
              : undefined
          }
        >
          {humaniseField(row.split_strategy)}
        </Badge>
      ),
      hideOnSmall: true,
      width: '15%',
    },
    {
      key: 'dataset_fingerprint',
      header: 'Dataset',
      render: (row) => (
        <span
          className="font-mono text-2xs text-ink-600 dark:text-ink-300"
          title={row.dataset_fingerprint ?? undefined}
        >
          {row.dataset_fingerprint ? truncateId(row.dataset_fingerprint, 8) : '—'}
        </span>
      ),
      hideOnSmall: true,
      width: '13%',
    },
    {
      key: 'training_finished_at',
      header: 'Trained',
      render: (row) => (
        <span className="whitespace-nowrap text-2xs tabular text-ink-600 dark:text-ink-300">
          {row.training_finished_at ? formatDateTime(row.training_finished_at) : '—'}
        </span>
      ),
      width: '21%',
    },
  ];

  return (
    <div className="space-y-5">
      <PageHeader
        title="Model monitoring"
        description="What is producing scores, what may be claimed about them, and what the model is built from."
      />

      {statusError ? (
        <ErrorState error={statusError} onRetry={() => void statusQuery.refetch()} />
      ) : null}

      <div className="grid gap-5 xl:grid-cols-3">
        <div className="xl:col-span-2">
          <ScoringModeCard
            status={statusQuery.data}
            current={currentQuery.data}
            isLoading={statusQuery.isLoading || currentQuery.isLoading}
          />
        </div>

        <LimitationsPanel
          limitations={limitationsQuery.data}
          isLoading={limitationsQuery.isLoading}
        />
      </div>

      <MetricsSummary
        evaluations={currentQuery.data?.latest_evaluations ?? []}
        isLoading={currentQuery.isLoading}
        usingFallback={usingFallback}
      />

      <Card
        title="Model versions"
        description="Every version on record, whether or not it is scoring."
        caveats={versionsQuery.data?.caveats}
        flush
      >
        {versionsError ? (
          <div className="p-4">
            <ErrorState
              error={versionsError}
              onRetry={() => void versionsQuery.refetch()}
              compact
            />
          </div>
        ) : null}

        <DataTable
          caption="Model versions with their training provenance"
          columns={versionColumns}
          rows={versionsQuery.data?.items ?? []}
          rowKey={(row) => row.id}
          isLoading={versionsQuery.isLoading}
          emptyTitle="No model version on record"
          emptyMessage="Nothing has been trained in this deployment. Scores come from the heuristic fallback."
        />

        {versionsQuery.data ? (
          <Pagination
            meta={pageInfo(versionsQuery.data)!}
            onPageChange={setPage}
            onPageSizeChange={setPageSize}
            requestedPageSize={pageSize}
          />
        ) : null}
      </Card>

      <FeatureSchemaTable schema={schemaQuery.data} isLoading={schemaQuery.isLoading} />
    </div>
  );
}
