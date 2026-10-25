import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link } from 'react-router-dom';

import { Badge } from '@/components/common/Badge';
import { Button } from '@/components/common/Button';
import { Card } from '@/components/common/Card';
import { DataTable, type Column } from '@/components/common/DataTable';
import { ErrorState } from '@/components/common/ErrorState';
import { KeyValueList } from '@/components/common/KeyValueList';
import { Pagination } from '@/components/common/Pagination';
import { StatusPill } from '@/components/common/StatusPill';
import { Tabs } from '@/components/common/Tabs';
import { PageHeader } from '@/components/layout/PageHeader';
import { RoleGate } from '@/components/layout/RoleGate';
import { useApiError } from '@/hooks/useApiError';
import { usePagination } from '@/hooks/usePagination';
import { useQueryParams } from '@/hooks/useQueryParams';
import { formatCount } from '@/lib/amounts';
import { formatDateTime, formatDuration, formatRelative } from '@/lib/dates';
import { humaniseField, truncateId } from '@/lib/formatters';
import { PERMISSIONS } from '@/lib/permissions';
import { queryKeys } from '@/lib/queryKeys';
import { paths } from '@/routes/paths';
import type { AnalysisRun } from '@/types/api';
import { pageInfo } from '@/types/common';

import { GenerateDataForm } from './GenerateDataForm';
import { ImportJsonForm } from './ImportJsonForm';
import {
  cancelAnalysisRun,
  fetchAnalysisRuns,
  fetchAnalysisStatus,
  isRunInFlight,
  startAnalysisRun,
} from './analysisApi';
import { fetchIngestionStatus } from './ingestionApi';

/**
 * Data and analysis.
 *
 * The two halves belong together because they are one workflow: data is
 * loaded, then analysed, and neither is useful alone. Loading data produces no
 * alerts until a run happens, and a run over an empty database produces
 * nothing — which is the most common reason a new deployment looks broken.
 *
 * The run panel reports what analysis *can* do here before offering the
 * button. `service_available` false means starting a run returns 503, and
 * `require_trained_model` with no active model means the same; both are better
 * said in advance than discovered afterwards.
 */
export default function IngestionPage() {
  const queryClient = useQueryClient();
  const { params, setParams } = useQueryParams();
  const { page, pageSize, setPage, setPageSize } = usePagination(10);

  const tab = params.tab ?? 'analysis';
  const [runOutcome, setRunOutcome] = useState<string | null>(null);

  const ingestionStatusQuery = useQuery({
    queryKey: queryKeys.ingestion.status(),
    queryFn: fetchIngestionStatus,
  });

  const analysisStatusQuery = useQuery({
    queryKey: queryKeys.analysis.status(),
    queryFn: fetchAnalysisStatus,
  });

  const runsQuery = useQuery({
    queryKey: queryKeys.analysis.runs(page, pageSize),
    queryFn: () =>
      fetchAnalysisRuns({
        page,
        page_size: pageSize,
        sort_by: 'created_at',
        sort_order: 'desc',
      }),
    // A queued or running job finishes while this page is open.
    refetchInterval: 15_000,
  });

  const startRun = useMutation({
    mutationFn: () => startAnalysisRun({}),
    onSuccess: (run) => {
      setRunOutcome(
        `Run ${truncateId(run.id, 8)} is ${humaniseField(run.status).toLowerCase()}. ` +
          'Alerts appear as it completes.',
      );
      void queryClient.invalidateQueries({ queryKey: queryKeys.analysis.all });
    },
  });

  const cancelRun = useMutation({
    mutationFn: (id: string) => cancelAnalysisRun(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.analysis.all });
    },
  });

  const ingestionError = useApiError(ingestionStatusQuery.error);
  const analysisError = useApiError(analysisStatusQuery.error ?? startRun.error ?? cancelRun.error);

  const ingestion = ingestionStatusQuery.data;
  const analysis = analysisStatusQuery.data;

  const canRun = Boolean(analysis?.enabled && analysis?.service_available);
  const blockedReason = !analysis
    ? null
    : !analysis.enabled
      ? 'Analysis is switched off in this deployment.'
      : !analysis.service_available
        ? 'The analytical service is not available, so starting a run would return 503.'
        : analysis.require_trained_model && !analysis.model_version_id
          ? 'A trained model is required here and none is active, so a run would be refused rather than falling back.'
          : null;

  const runColumns: Array<Column<AnalysisRun>> = [
    {
      key: 'status',
      header: 'Status',
      render: (row) => (
        <div className="flex flex-col gap-1">
          <Badge
            tone={
              row.status === 'SUCCEEDED'
                ? 'neutral'
                : row.status === 'FAILED'
                  ? 'danger'
                  : row.status === 'PARTIAL'
                    ? 'warning'
                    : 'accent'
            }
            title={
              row.status === 'PARTIAL'
                ? 'Usable output with some per-account failures. Conclusions drawn from it rest on fewer accounts than were requested.'
                : undefined
            }
          >
            {humaniseField(row.status)}
          </Badge>
          <StatusPill kind="scoring-mode" value={row.scoring_mode} />
        </div>
      ),
      width: '16%',
    },
    {
      key: 'created_at',
      header: 'Started',
      render: (row) => (
        <span
          className="whitespace-nowrap text-xs text-ink-700 dark:text-ink-200"
          title={formatDateTime(row.started_at ?? row.created_at)}
        >
          {formatRelative(row.started_at ?? row.created_at)}
        </span>
      ),
      width: '14%',
    },
    {
      key: 'counts',
      header: 'Produced',
      render: (row) => (
        <span className="text-2xs text-ink-700 dark:text-ink-200">
          {formatCount(row.assessment_count)} assessments
          <span className="block text-ink-500 dark:text-ink-400">
            {formatCount(row.alert_count)} alerts over {formatCount(row.account_count)} accounts
          </span>
        </span>
      ),
      width: '22%',
    },
    {
      key: 'duration_seconds',
      header: 'Took',
      numeric: true,
      render: (row) => (
        <span className="text-xs tabular">{formatDuration(row.duration_seconds)}</span>
      ),
      hideOnSmall: true,
      width: '10%',
    },
    {
      key: 'requested_by',
      header: 'By',
      render: (row) => (
        <span className="text-2xs text-ink-700 dark:text-ink-200">
          {row.requested_by_username ??
            (row.requested_by ? truncateId(row.requested_by, 6) : 'System')}
        </span>
      ),
      hideOnSmall: true,
      width: '12%',
    },
    {
      key: 'error',
      header: 'Problem',
      render: (row) =>
        row.error_code || row.error_message ? (
          <span className="text-2xs text-ink-800 dark:text-ink-100" title={row.error_message ?? undefined}>
            <span className="font-mono">{row.error_code ?? 'error'}</span>
            {row.error_message ? (
              <span className="block text-ink-600 dark:text-ink-300">{row.error_message}</span>
            ) : null}
          </span>
        ) : (
          <span className="text-2xs text-ink-400 dark:text-ink-500">—</span>
        ),
      width: '18%',
    },
    {
      key: 'actions',
      header: <span className="mg-visually-hidden">Actions</span>,
      render: (row) =>
        isRunInFlight(row) ? (
          <RoleGate permissions={[PERMISSIONS.runAnalysis]} silent>
            <Button
              size="sm"
              variant="ghost"
              isLoading={cancelRun.isPending && cancelRun.variables === row.id}
              onClick={() => cancelRun.mutate(row.id)}
            >
              Cancel
            </Button>
          </RoleGate>
        ) : null,
      width: '8%',
    },
  ];

  return (
    <div className="space-y-5">
      <PageHeader
        title="Data"
        description="Load records and run analysis. Loading data produces no alerts on its own; a run over an empty database produces nothing — which is the usual reason a fresh deployment looks broken."
      />

      {ingestion && ingestion.require_synthetic ? (
        <p
          role="note"
          className="rounded-card border border-ink-200 bg-ink-50 p-3 text-xs leading-relaxed text-ink-700 dark:border-ink-700 dark:bg-ink-800/60 dark:text-ink-200"
        >
          This deployment is configured for synthetic data (
          <span className="font-mono">{humaniseField(ingestion.dataset_mode)}</span>). Output here
          is not a finding about any real person or account.
        </p>
      ) : null}

      <Tabs
        activeId={tab}
        onChange={(id) => setParams({ tab: id }, { resetPage: false })}
        items={[
          {
            id: 'analysis',
            label: 'Analysis runs',
            content: (
              <div className="space-y-5">
                <Card
                  title="Run analysis"
                  description="Computes features, evaluates the rule pack, scores, correlates complaints, builds neighbourhoods and raises alerts."
                  caveats={analysis?.caveats}
                  actions={
                    <RoleGate permissions={[PERMISSIONS.runAnalysis]} silent>
                      <Button
                        variant="primary"
                        size="sm"
                        isLoading={startRun.isPending}
                        disabled={!canRun}
                        onClick={() => {
                          setRunOutcome(null);
                          startRun.mutate();
                        }}
                      >
                        Start a run
                      </Button>
                    </RoleGate>
                  }
                >
                  {analysisError ? <ErrorState error={analysisError} compact className="mb-3" /> : null}

                  {blockedReason ? (
                    <p
                      role="status"
                      className="mb-3 rounded-md border border-ink-200 bg-amber-50 p-3 text-xs leading-relaxed text-amber-900 dark:border-ink-700 dark:bg-amber-950/40 dark:text-amber-200"
                    >
                      {blockedReason}
                    </p>
                  ) : null}

                  {runOutcome ? (
                    <p role="status" className="mb-3 text-xs text-ink-700 dark:text-ink-200">
                      {runOutcome}
                    </p>
                  ) : null}

                  {analysis ? (
                    <KeyValueList
                      columns={3}
                      entries={[
                        {
                          label: 'Scoring mode',
                          value: <StatusPill kind="scoring-mode" value={analysis.scoring_mode} />,
                        },
                        {
                          label: 'Active model',
                          value: analysis.model_version ?? 'None',
                          mono: true,
                          help: analysis.model_version
                            ? undefined
                            : 'Scores will come from the heuristic fallback, whose weights are hand-set rather than learned.',
                        },
                        {
                          label: 'Accounts per run',
                          value: `up to ${formatCount(analysis.max_accounts)}`,
                          help: 'A run with no explicit account list is capped at this.',
                        },
                        {
                          label: 'All accounts allowed',
                          value: analysis.allow_all_accounts ? 'Yes' : 'No',
                        },
                        {
                          label: 'As-of policy',
                          value: humaniseField(analysis.default_as_of_policy),
                          help: 'Where the run takes its point-in-time cutoff from when none is given. Features see only data strictly before it.',
                        },
                        {
                          label: 'Dataset mode',
                          value: humaniseField(analysis.dataset_mode),
                        },
                      ]}
                    />
                  ) : null}

                  <p className="mt-3 text-2xs leading-relaxed text-ink-500 dark:text-ink-400">
                    A run with no parameters assesses up to the cap above, as of now. Model
                    monitoring shows what is producing the scores and what may be claimed about
                    them — worth reading before acting on a first batch of alerts.
                    {' '}
                    <Link
                      to={paths.modelMonitoring}
                      className="font-medium text-accent-700 hover:underline dark:text-accent-300"
                    >
                      Model monitoring
                    </Link>
                  </p>
                </Card>

                <Card title="Runs" caveats={runsQuery.data?.caveats} flush>
                  <DataTable
                    caption="Analysis runs, newest first"
                    columns={runColumns}
                    rows={runsQuery.data?.items ?? []}
                    rowKey={(row) => row.id}
                    isLoading={runsQuery.isLoading}
                    isRefetching={runsQuery.isRefetching}
                    emptyTitle="No analysis has run"
                    emptyMessage="Until one does, there are no assessments and no alerts. An empty alert queue means nothing has been looked at, not that nothing was found."
                  />

                  {runsQuery.data ? (
                    <Pagination
                      meta={pageInfo(runsQuery.data)!}
                      onPageChange={setPage}
                      onPageSizeChange={setPageSize}
                      requestedPageSize={pageSize}
                    />
                  ) : null}
                </Card>
              </div>
            ),
          },
          {
            id: 'generate',
            label: 'Generate data',
            content: (
              <RoleGate
                permissions={[PERMISSIONS.runIngestion]}
                action="load data into this deployment"
              >
                <GenerateDataForm />
              </RoleGate>
            ),
          },
          {
            id: 'import',
            label: 'Import JSON',
            content: (
              <RoleGate
                permissions={[PERMISSIONS.runIngestion]}
                action="load data into this deployment"
              >
                <div className="space-y-5">
                  {ingestionError ? <ErrorState error={ingestionError} /> : null}

                  {ingestion ? (
                    <Card title="What ingestion accepts here" caveats={ingestion.caveats}>
                      <KeyValueList
                        columns={3}
                        entries={[
                          {
                            label: 'Rows per batch',
                            value: `${formatCount(ingestion.max_batch_size)} (hard cap ${formatCount(ingestion.hard_max_batch_size)})`,
                          },
                          {
                            label: 'Errors returned',
                            value: formatCount(ingestion.max_errors_returned),
                            help: 'A batch with more rejections than this returns the first few only.',
                          },
                          {
                            label: 'Partial rows by default',
                            value: ingestion.default_allow_partial ? 'Accepted' : 'All or nothing',
                          },
                          {
                            label: 'On duplicate',
                            value: humaniseField(ingestion.default_duplicate_strategy),
                          },
                          {
                            label: 'Future tolerance',
                            value: `${ingestion.future_tolerance_minutes} minutes`,
                            help: 'An occurred-at further ahead than this is rejected rather than stored.',
                          },
                          {
                            label: 'Synthetic required',
                            value: ingestion.require_synthetic ? 'Yes' : 'No',
                          },
                        ]}
                      />
                    </Card>
                  ) : null}

                  <ImportJsonForm maxBatchSize={ingestion?.max_batch_size} />
                </div>
              </RoleGate>
            ),
          },
        ]}
      />
    </div>
  );
}
