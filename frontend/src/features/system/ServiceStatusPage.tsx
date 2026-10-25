import { useQuery } from '@tanstack/react-query';

import { Badge } from '@/components/common/Badge';
import { Button } from '@/components/common/Button';
import { Card } from '@/components/common/Card';
import { ErrorState } from '@/components/common/ErrorState';
import { KeyValueList } from '@/components/common/KeyValueList';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { PageHeader } from '@/components/layout/PageHeader';
import { useApiError } from '@/hooks/useApiError';
import { APP_VERSION, ENVIRONMENT_LABEL } from '@/lib/environment';
import { humaniseField } from '@/lib/formatters';
import { queryKeys } from '@/lib/queryKeys';

import { fetchLimitations, fetchStatus } from './systemApi';

/**
 * Service status.
 *
 * This page exists because the analytical core is optional in parts. A
 * deployment with no trained model still produces scores, from the heuristic
 * fallback; one with the graph component disabled still raises alerts, with
 * one fewer input. Both are legitimate configurations and both change how the
 * output should be read — so rather than hiding degradation behind a working
 * dashboard, every component states its own availability here.
 *
 * It requires no permission, and it does not retry: this is the page a user
 * opens when something is already broken.
 */
export default function ServiceStatusPage() {
  const statusQuery = useQuery({
    queryKey: queryKeys.system.status(),
    queryFn: fetchStatus,
    retry: false,
    refetchInterval: 30_000,
  });

  const limitationsQuery = useQuery({
    queryKey: queryKeys.system.limitations(),
    queryFn: fetchLimitations,
    retry: false,
    staleTime: 10 * 60_000,
  });

  const statusError = useApiError(statusQuery.error);
  const status = statusQuery.data;

  const components = (status?.components ?? {}) as Record<string, unknown>;
  const componentRows = Object.entries(components);

  const describeComponent = (value: unknown): { available: boolean; detail: string } => {
    if (typeof value === 'boolean') {
      return { available: value, detail: value ? 'Available' : 'Unavailable' };
    }

    if (value && typeof value === 'object') {
      const record = value as Record<string, unknown>;
      const available =
        record.available === true || record.status === 'ok' || record.status === 'available';
      const detail =
        typeof record.detail === 'string'
          ? record.detail
          : typeof record.reason === 'string'
            ? record.reason
            : typeof record.status === 'string'
              ? record.status
              : available
                ? 'Available'
                : 'Unavailable';

      return { available, detail };
    }

    return { available: false, detail: String(value ?? 'Unknown') };
  };

  return (
    <div className="space-y-5">
      <PageHeader
        title="Service status"
        description="Which analytical components this deployment has available, and what their absence means for the output you see elsewhere."
        actions={
          <Button
            variant="secondary"
            size="sm"
            onClick={() => {
              void statusQuery.refetch();
              void limitationsQuery.refetch();
            }}
            isLoading={statusQuery.isFetching}
          >
            Refresh
          </Button>
        }
      />

      {statusError ? (
        <ErrorState
          error={statusError}
          onRetry={() => void statusQuery.refetch()}
        />
      ) : null}

      <Card title="Deployment">
        <KeyValueList
          columns={3}
          entries={[
            {
              label: 'API status',
              value: statusQuery.isLoading ? (
                <LoadingSpinner size="sm" />
              ) : status?.status ? (
                <Badge
                  tone={status.status === 'ok' ? 'neutral' : 'warning'}
                  title={
                    status.status === 'ok'
                      ? 'All required components answered.'
                      : 'The API is serving requests with at least one component degraded.'
                  }
                >
                  {humaniseField(status.status)}
                </Badge>
              ) : (
                <Badge tone="danger">Unreachable</Badge>
              ),
            },
            { label: 'API version', value: status?.version ?? '—', mono: true },
            {
              label: 'Backend environment',
              value: status?.environment ?? '—',
              help: 'As the server reports it. If this disagrees with the banner, the frontend is pointed at a different backend than you expect.',
            },
            { label: 'Frontend version', value: APP_VERSION, mono: true },
            { label: 'Frontend environment', value: ENVIRONMENT_LABEL },
          ]}
        />

        {status?.degraded_reasons && status.degraded_reasons.length > 0 ? (
          <ul className="mt-4 space-y-1 border-t border-ink-200 pt-3 dark:border-ink-700">
            {status.degraded_reasons.map((reason) => (
              <li key={reason} className="text-2xs text-ink-700 dark:text-ink-200">
                — {reason}
              </li>
            ))}
          </ul>
        ) : null}
      </Card>

      <Card
        title="Components"
        description="A missing component does not stop analysis. It removes one input from the fused score, and the remaining weights are renormalised rather than the missing one being counted as zero."
      >
        {statusQuery.isLoading ? (
          <LoadingSpinner label="Loading component status" />
        ) : componentRows.length === 0 ? (
          <p className="text-xs text-ink-500 dark:text-ink-400">
            The status endpoint reported no component detail.
          </p>
        ) : (
          <ul className="divide-y divide-ink-200 dark:divide-ink-700">
            {componentRows.map(([name, value]) => {
              const { available, detail } = describeComponent(value);

              return (
                <li key={name} className="flex items-start justify-between gap-4 py-2">
                  <div className="min-w-0">
                    <p className="text-xs font-medium text-ink-800 dark:text-ink-100">
                      {humaniseField(name)}
                    </p>
                    <p className="mt-0.5 text-2xs text-ink-600 dark:text-ink-300">{detail}</p>
                  </div>
                  <Badge tone={available ? 'neutral' : 'warning'}>
                    {available ? 'Available' : 'Unavailable'}
                  </Badge>
                </li>
              );
            })}
          </ul>
        )}
      </Card>

      {limitationsQuery.data ? (
        <Card
          title="Stated limitations"
          description="The same disclaimer and limitations text that is printed in every generated report, so the screen and the PDF cannot drift apart."
          caveats={limitationsQuery.data.caveats}
        >
          {limitationsQuery.data.disclaimer ? (
            <p className="rounded-md border border-ink-200 bg-ink-50 p-3 text-xs leading-relaxed text-ink-800 dark:border-ink-700 dark:bg-ink-800/60 dark:text-ink-100">
              {limitationsQuery.data.disclaimer}
            </p>
          ) : null}

          {limitationsQuery.data.limitations ? (
            <p className="mt-3 whitespace-pre-line text-xs leading-relaxed text-ink-700 dark:text-ink-200">
              {limitationsQuery.data.limitations}
            </p>
          ) : null}

          {limitationsQuery.data.footer ? (
            <p className="mt-3 border-t border-ink-200 pt-2 text-2xs text-ink-500 dark:border-ink-700 dark:text-ink-400">
              {limitationsQuery.data.footer}
            </p>
          ) : null}

          {!limitationsQuery.data.disclaimer && !limitationsQuery.data.limitations ? (
            <p className="text-xs text-ink-500 dark:text-ink-400">
              This deployment has disclaimer and limitations text switched off, so generated
              reports carry none. Anything taken out of this platform then travels without its
              own caveats.
            </p>
          ) : null}
        </Card>
      ) : null}
    </div>
  );
}
