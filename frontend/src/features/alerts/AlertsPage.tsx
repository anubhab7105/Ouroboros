import { useQuery } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';

import { Card } from '@/components/common/Card';
import { ErrorState } from '@/components/common/ErrorState';
import { Pagination } from '@/components/common/Pagination';
import { AlertsTable } from '@/components/tables/AlertsTable';
import { PageHeader } from '@/components/layout/PageHeader';
import { useApiError } from '@/hooks/useApiError';
import { useDebounce } from '@/hooks/useDebounce';
import { usePagination } from '@/hooks/usePagination';
import { useQueryParams } from '@/hooks/useQueryParams';
import { queryKeys } from '@/lib/queryKeys';
import { paths } from '@/routes/paths';
import type { AlertFilters as Filters } from '@/types/alert';
import { pageInfo } from '@/types/common';

import { AlertDetailDrawer } from './AlertDetailDrawer';
import { AlertFilters } from './AlertFilters';
import { fetchAlerts } from './alertsApi';

/** Repeated query parameters arrive from the URL comma-joined. */
function splitList(value: string | undefined): string[] | undefined {
  if (!value) return undefined;
  const parts = value.split(',').map((part) => part.trim()).filter(Boolean);
  return parts.length > 0 ? parts : undefined;
}

/**
 * The triage queue.
 *
 * One page serves both `/alerts` and `/alerts/:alertId`: a single alert is the
 * queue with its drawer open. Closing the drawer returns the analyst to the
 * list they were working through with their filters and scroll position
 * intact, which paging to a separate detail route would lose.
 *
 * Multi-valued state and priority filters live in the URL comma-joined and go
 * to the API as repeated parameters, which is the form it declares.
 */
export default function AlertsPage() {
  const { alertId } = useParams();
  const navigate = useNavigate();
  const { params, setParams, clearParams, activeFilterCount } = useQueryParams<
    Record<string, string>
  >();
  const { page, pageSize, setPage, setPageSize } = usePagination();

  const [selectedId, setSelectedId] = useState<string | null>(alertId ?? null);

  // Keep the drawer and the URL in step when the route parameter changes.
  useEffect(() => {
    setSelectedId(alertId ?? null);
  }, [alertId]);

  const search = useDebounce(params.q ?? '', 350);

  const filters: Filters = {
    account_id: params.account_id,
    states: splitList(params.states),
    priorities: splitList(params.priorities),
    scoring_mode: params.scoring_mode,
    assigned_to: params.assigned_to,
    acknowledged_by: params.acknowledged_by,
    min_score: params.min_score ? Number(params.min_score) : undefined,
    max_score: params.max_score ? Number(params.max_score) : undefined,
    first_seen_from: params.first_seen_from,
    first_seen_to: params.first_seen_to,
    q: search || undefined,
  };

  const sortBy = params.sort_by ?? 'first_seen_at';
  const sortOrder = (params.sort_order as 'asc' | 'desc') ?? 'desc';

  const query = useQuery({
    queryKey: queryKeys.alerts.list(page, pageSize, filters, `${sortBy}:${sortOrder}`),
    queryFn: () =>
      fetchAlerts({
        page,
        page_size: pageSize,
        sort_by: sortBy,
        sort_order: sortOrder,
        filters,
      }),
    // The queue moves while it is being worked, so it refreshes on its own.
    refetchInterval: 90_000,
  });

  const error = useApiError(query.error);

  const openAlert = (id: string) => {
    setSelectedId(id);
    // Push the URL so the alert is linkable and the back button closes it.
    navigate(paths.alert(id) + window.location.search, { replace: false });
  };

  const closeAlert = () => {
    setSelectedId(null);
    navigate(paths.alerts + window.location.search, { replace: false });
  };

  return (
    <div>
      <PageHeader
        title="Alerts"
        description="Risk findings awaiting triage. Age is measured from when a signature was first seen, not from the last analysis run — deduplication updates an existing alert rather than raising a new one."
      >
        <AlertFilters
          values={params}
          onChange={setParams}
          onClear={() => clearParams()}
          activeCount={activeFilterCount}
        />
      </PageHeader>

      {error ? (
        <ErrorState error={error} onRetry={() => void query.refetch()} className="mb-4" />
      ) : null}

      <Card flush caveats={query.data?.caveats}>
        <AlertsTable
          rows={query.data?.items ?? []}
          isLoading={query.isLoading}
          isRefetching={query.isRefetching}
          sortBy={sortBy}
          sortOrder={sortOrder}
          onSortChange={(key, order) => setParams({ sort_by: key, sort_order: order })}
          onRowClick={(row) => openAlert(row.id)}
          selectedId={selectedId}
        />

        {query.data ? (
          <Pagination
            meta={pageInfo(query.data)!}
            onPageChange={setPage}
            onPageSizeChange={setPageSize}
            requestedPageSize={pageSize}
            orderingIsVolatile={sortBy === 'score' || sortBy === 'last_seen_at'}
          />
        ) : null}
      </Card>

      <AlertDetailDrawer alertId={selectedId} onClose={closeAlert} />
    </div>
  );
}
