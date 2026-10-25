import { useQuery } from '@tanstack/react-query';

import { Card } from '@/components/common/Card';
import { ErrorState } from '@/components/common/ErrorState';
import { Pagination } from '@/components/common/Pagination';
import { AccountsTable } from '@/components/tables/AccountsTable';
import { PageHeader } from '@/components/layout/PageHeader';
import { useApiError } from '@/hooks/useApiError';
import { useDebounce } from '@/hooks/useDebounce';
import { usePagination } from '@/hooks/usePagination';
import { useQueryParams } from '@/hooks/useQueryParams';
import { SCORE_SEMANTICS } from '@/lib/constants';
import { queryKeys } from '@/lib/queryKeys';
import type { AccountFilters as Filters } from '@/types/account';
import { pageInfo } from '@/types/common';

import { AccountFilters } from './AccountFilters';
import { fetchAccounts } from './accountsApi';

/**
 * The account list.
 *
 * The score semantics sit in the page description rather than in a tooltip,
 * because this is the first screen on which an analyst meets a ranked list of
 * accounts and the ranking is the thing most easily misread. It is an
 * investigative priority, not a probability of guilt.
 */
export default function AccountsPage() {
  const { params, setParams, clearParams, activeFilterCount } = useQueryParams<
    Filters & Record<string, string>
  >();
  const { page, pageSize, setPage, setPageSize } = usePagination();

  const search = useDebounce(params.q ?? '', 350);

  const filters: Filters = {
    account_type: params.account_type,
    status: params.status,
    created_from: params.created_from,
    created_to: params.created_to,
    q: search || undefined,
  };

  const sortBy = params.sort_by ?? 'created_at';
  const sortOrder = (params.sort_order as 'asc' | 'desc') ?? 'desc';

  const query = useQuery({
    queryKey: queryKeys.accounts.list(page, pageSize, filters, `${sortBy}:${sortOrder}`),
    queryFn: () =>
      fetchAccounts({
        page,
        page_size: pageSize,
        sort_by: sortBy,
        sort_order: sortOrder,
        filters,
      }),
  });

  const error = useApiError(query.error);

  // Score-ordered pages genuinely re-rank as new assessments land, so the
  // pager warns that rows can move between pages.
  const volatileOrdering = sortBy.includes('score') || sortBy.includes('risk');

  return (
    <div>
      <PageHeader title="Accounts" description={SCORE_SEMANTICS}>
        <AccountFilters
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
        <AccountsTable
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
            orderingIsVolatile={volatileOrdering}
          />
        ) : null}
      </Card>
    </div>
  );
}
