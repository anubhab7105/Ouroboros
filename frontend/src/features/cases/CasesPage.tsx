import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';

import { Button } from '@/components/common/Button';
import { Card } from '@/components/common/Card';
import { ErrorState } from '@/components/common/ErrorState';
import { Pagination } from '@/components/common/Pagination';
import { CasesTable } from '@/components/tables/CasesTable';
import { PageHeader } from '@/components/layout/PageHeader';
import { RoleGate } from '@/components/layout/RoleGate';
import { useApiError } from '@/hooks/useApiError';
import { useDebounce } from '@/hooks/useDebounce';
import { usePagination } from '@/hooks/usePagination';
import { useQueryParams } from '@/hooks/useQueryParams';
import { PERMISSIONS } from '@/lib/permissions';
import { queryKeys } from '@/lib/queryKeys';
import type { CaseFilters as Filters } from '@/types/case';
import { pageInfo } from '@/types/common';

import { CaseFilters } from './CaseFilters';
import { CreateCaseModal } from './CreateCaseModal';
import { fetchCases } from './casesApi';

/** Investigations. */
export default function CasesPage() {
  const { params, setParams, clearParams, activeFilterCount } = useQueryParams<
    Filters & Record<string, string>
  >();
  const { page, pageSize, setPage, setPageSize } = usePagination();
  const [creating, setCreating] = useState(false);

  const search = useDebounce(params.q ?? '', 350);

  const filters: Filters = {
    status: params.status,
    priority: params.priority,
    disposition: params.disposition,
    assignee_id: params.assignee_id,
    creator_id: params.creator_id,
    account_id: params.account_id,
    alert_id: params.alert_id,
    date_from: params.date_from,
    date_to: params.date_to,
    closed_from: params.closed_from,
    closed_to: params.closed_to,
    include_account: true,
    q: search || undefined,
  };

  const sortBy = params.sort_by ?? 'updated_at';
  const sortOrder = (params.sort_order as 'asc' | 'desc') ?? 'desc';

  const query = useQuery({
    queryKey: queryKeys.cases.list(page, pageSize, filters),
    queryFn: () =>
      fetchCases({
        page,
        page_size: pageSize,
        sort_by: sortBy,
        sort_order: sortOrder,
        filters,
      }),
  });

  const error = useApiError(query.error);

  return (
    <div>
      <PageHeader
        title="Cases"
        description="Investigations, with the outcome recorded on each. A closed case shows its disposition, because closed as fraud and closed as a false positive are opposite results."
        actions={
          <RoleGate permissions={[PERMISSIONS.createCase]} silent>
            <Button variant="primary" size="sm" onClick={() => setCreating(true)}>
              Open a case
            </Button>
          </RoleGate>
        }
      >
        <CaseFilters
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
        <CasesTable
          rows={query.data?.items ?? []}
          isLoading={query.isLoading}
          isRefetching={query.isRefetching}
          sortBy={sortBy}
          sortOrder={sortOrder}
          onSortChange={(key, order) => setParams({ sort_by: key, sort_order: order })}
        />

        {query.data ? (
          <Pagination
            meta={pageInfo(query.data)!}
            onPageChange={setPage}
            onPageSizeChange={setPageSize}
            requestedPageSize={pageSize}
            orderingIsVolatile={sortBy === 'updated_at'}
          />
        ) : null}
      </Card>

      <CreateCaseModal
        open={creating}
        onClose={() => setCreating(false)}
        accountId={params.account_id}
      />
    </div>
  );
}
