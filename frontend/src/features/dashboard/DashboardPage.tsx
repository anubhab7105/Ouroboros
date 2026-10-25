import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';

import { TransactionsActivityChart } from '@/components/charts/TransactionsActivityChart';
import { Button } from '@/components/common/Button';
import { Card } from '@/components/common/Card';
import { ErrorState } from '@/components/common/ErrorState';
import { KeyValueList } from '@/components/common/KeyValueList';
import { Select } from '@/components/common/Select';
import { PageHeader } from '@/components/layout/PageHeader';
import { useApiError } from '@/hooks/useApiError';
import { useAuth } from '@/hooks/useAuth';
import { useQueryParams } from '@/hooks/useQueryParams';
import { formatCount, formatRatio } from '@/lib/amounts';
import {
  DEFAULT_DASHBOARD_WINDOW_DAYS,
  MAX_DASHBOARD_WINDOW_DAYS,
  WINDOW_DAY_OPTIONS,
} from '@/lib/constants';
import { formatDateTime } from '@/lib/dates';
import { humaniseField } from '@/lib/formatters';
import { queryKeys } from '@/lib/queryKeys';

import { ActivityFeed } from './ActivityFeed';
import { AlertsTrendPanel } from './AlertsTrendPanel';
import { ComplaintSummaryPanel } from './ComplaintSummaryPanel';
import { OpenCasesPanel } from './OpenCasesPanel';
import { RiskDistributionPanel } from './RiskDistributionPanel';
import { SummaryCards } from './SummaryCards';
import { fetchMetrics, fetchOverview, fetchQueues, fetchTrends, windowFromDays } from './dashboardApi';

/**
 * The investigation dashboard.
 *
 * Four independent queries rather than one. Each panel then shows its own
 * loading and error state, and a slow trend query does not hold up the queue
 * list an analyst actually came for. It also means a single failing endpoint
 * degrades one card instead of blanking the page.
 *
 * The window lives in the URL, so "the last 7 days" is a link a colleague can
 * open and see the same figures.
 */
export default function DashboardPage() {
  const { user } = useAuth();
  const { getNumber, setParams } = useQueryParams();

  const requestedWindowDays =
    getNumber('window_days', DEFAULT_DASHBOARD_WINDOW_DAYS) ?? DEFAULT_DASHBOARD_WINDOW_DAYS;
  const windowDays = Math.max(1, Math.min(requestedWindowDays, MAX_DASHBOARD_WINDOW_DAYS));

  // Recomputed per window change rather than per render: a fresh `new Date()`
  // on every render would change the query key continuously and refetch
  // forever.
  const range = useMemo(() => windowFromDays(windowDays), [windowDays]);

  const overviewQuery = useQuery({
    queryKey: queryKeys.dashboard.overview(windowDays),
    queryFn: () => fetchOverview(range),
  });

  const trendsQuery = useQuery({
    queryKey: queryKeys.dashboard.trends(windowDays),
    queryFn: () => fetchTrends(range),
  });

  const queuesQuery = useQuery({
    queryKey: queryKeys.dashboard.queues(user?.id),
    queryFn: () => fetchQueues(),
    // The queues are the actionable part of the page, so they refresh on their
    // own. Everything else is a window aggregate that does not move minute to
    // minute.
    refetchInterval: 60_000,
  });

  const metricsQuery = useQuery({
    queryKey: queryKeys.dashboard.metrics(windowDays),
    queryFn: () => fetchMetrics(range),
  });

  const overviewError = useApiError(overviewQuery.error);
  const trendsError = useApiError(trendsQuery.error);
  const metricsError = useApiError(metricsQuery.error);

  const overview = overviewQuery.data;

  const activityBuckets = useMemo(
    () =>
      (trendsQuery.data?.points ?? []).map((point) => ({
        bucket: point.date,
        count: point.transactions,
        value: null,
      })),
    [trendsQuery.data],
  );

  const rateRows = useMemo(() => {
    const rates = metricsQuery.data?.rates_per_day ?? {};

    return Object.entries(rates)
      .filter(([, value]) => Number.isFinite(value))
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([name, value]) => ({
        label: humaniseField(name),
        value: `${formatRatio(value)} / day`,
      }));
  }, [metricsQuery.data]);

  const serverWindow = overview?.window ?? trendsQuery.data?.period;

  return (
    <div className="space-y-5">
      <PageHeader
        title="Dashboard"
        description="Queue sizes, risk distribution and activity over the selected window. Every figure here is an investigative signal, not a finding."
        actions={
          <div className="flex items-center gap-2">
            <label htmlFor="mg-window" className="text-2xs font-medium text-ink-600 dark:text-ink-300">
              Window
            </label>
            <Select
              id="mg-window"
              value={String(windowDays)}
              onChange={(event) => setParams({ window_days: event.target.value })}
              className="w-28"
              options={WINDOW_DAY_OPTIONS.map((days) => ({
                value: String(days),
                label: `${days} days`,
              }))}
            />
            <Button
              size="sm"
              variant="secondary"
              isLoading={
                overviewQuery.isFetching || trendsQuery.isFetching || queuesQuery.isFetching
              }
              onClick={() => {
                void overviewQuery.refetch();
                void trendsQuery.refetch();
                void queuesQuery.refetch();
                void metricsQuery.refetch();
              }}
            >
              Refresh
            </Button>
          </div>
        }
      >
        {serverWindow ? (
          <p className="text-2xs text-ink-500 dark:text-ink-400">
            Window applied by the server: {formatDateTime(serverWindow.date_from)} to{' '}
            {formatDateTime(serverWindow.date_to)}
            {serverWindow.defaulted
              ? ` — the default ${serverWindow.default_window_days} days, because no range was sent`
              : ''}
            . Maximum span {formatCount(serverWindow.max_span_days)} days.
          </p>
        ) : null}
      </PageHeader>

      {overviewError ? (
        <ErrorState error={overviewError} onRetry={() => void overviewQuery.refetch()} />
      ) : null}

      <SummaryCards overview={overview} isLoading={overviewQuery.isLoading} />

      {overview?.caveats && overview.caveats.length > 0 ? (
        <ul className="space-y-1 rounded-card border border-ink-200 bg-ink-50 p-3 dark:border-ink-700 dark:bg-ink-800/60">
          {overview.caveats.map((caveat) => (
            <li key={caveat} className="text-2xs leading-relaxed text-ink-700 dark:text-ink-200">
              — {caveat}
            </li>
          ))}
        </ul>
      ) : null}

      <div className="grid gap-5 xl:grid-cols-3">
        <div className="space-y-5 xl:col-span-2">
          <AlertsTrendPanel
            trends={trendsQuery.data}
            isLoading={trendsQuery.isLoading}
            error={trendsError}
            onRetry={() => void trendsQuery.refetch()}
          />

          <div className="grid gap-5 lg:grid-cols-2">
            <RiskDistributionPanel
              assessments={overview?.assessments}
              isLoading={overviewQuery.isLoading}
              error={overviewError}
              onRetry={() => void overviewQuery.refetch()}
            />

            <OpenCasesPanel
              cases={overview?.cases}
              escalated={queuesQuery.data?.escalated_cases}
              isLoading={overviewQuery.isLoading || queuesQuery.isLoading}
              error={overviewError}
              onRetry={() => void overviewQuery.refetch()}
            />
          </div>

          <Card
            title="Transaction volume"
            description="All transactions per day, including those that are not fund movement. Only completed transfers count towards the aggregates elsewhere."
            caveats={trendsQuery.data?.caveats}
          >
            <TransactionsActivityChart
              buckets={activityBuckets}
              granularity={(trendsQuery.data?.bucket_size as 'day') ?? 'day'}
              isLoading={trendsQuery.isLoading}
              error={trendsError}
              onRetry={() => void trendsQuery.refetch()}
            />

            {overview?.transactions ? (
              <div className="mt-4 border-t border-ink-200 pt-3 dark:border-ink-700">
                <KeyValueList
                  columns={3}
                  entries={[
                    {
                      label: 'In window',
                      value: formatCount(overview.transactions.total_in_window),
                    },
                    {
                      label: 'Completed',
                      value: formatCount(overview.transactions.completed),
                      help: 'The only status that counts as fund movement.',
                    },
                    {
                      label: 'Pending',
                      value: formatCount(overview.transactions.pending),
                    },
                    {
                      label: 'Failed',
                      value: formatCount(overview.transactions.failed),
                    },
                    {
                      label: 'Reversed',
                      value: formatCount(overview.transactions.reversed),
                      help: 'Excluded from every total, like failed transfers.',
                    },
                  ]}
                />
              </div>
            ) : null}
          </Card>

          {rateRows.length > 0 ? (
            <Card
              title="Rates"
              description={`Per-day averages over ${formatRatio(metricsQuery.data?.days ?? windowDays)} days. Operational signals only — they are not statistically calibrated and must not be read as predictions.`}
              caveats={metricsQuery.data?.caveats}
            >
              {metricsError ? (
                <ErrorState
                  error={metricsError}
                  onRetry={() => void metricsQuery.refetch()}
                  compact
                />
              ) : (
                <KeyValueList columns={3} entries={rateRows} />
              )}
            </Card>
          ) : null}
        </div>

        <div className="space-y-5">
          <ActivityFeed
            queues={queuesQuery.data}
            isLoading={queuesQuery.isLoading}
            username={user?.username}
          />

          <ComplaintSummaryPanel
            complaints={overview?.complaints}
            isLoading={overviewQuery.isLoading}
            error={overviewError}
            onRetry={() => void overviewQuery.refetch()}
          />
        </div>
      </div>
    </div>
  );
}
