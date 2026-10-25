import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';

import { Card } from '@/components/common/Card';
import { ErrorState } from '@/components/common/ErrorState';
import { Pagination } from '@/components/common/Pagination';
import { PageHeader } from '@/components/layout/PageHeader';
import { TransactionsTable } from '@/components/tables/TransactionsTable';
import { useApiError } from '@/hooks/useApiError';
import { useDebounce } from '@/hooks/useDebounce';
import { usePagination } from '@/hooks/usePagination';
import { useQueryParams } from '@/hooks/useQueryParams';
import { queryKeys } from '@/lib/queryKeys';
import { pageInfo } from '@/types/common';
import type { TransactionFilters as Filters } from '@/types/transaction';

import { TransactionDetailDrawer } from './TransactionDetailDrawer';
import { TransactionFilters } from './TransactionFilters';
import { fetchTransactions } from './transactionsApi';

/**
 * The transaction ledger.
 *
 * Sorting and filtering are server-side, and the filter state lives in the
 * URL. Both matter here more than elsewhere: this list runs to millions of
 * rows, so client-side sorting would order one page and look like it ordered
 * everything, and a filtered ledger view is the thing analysts paste to each
 * other most often.
 */
export default function TransactionsPage() {
  const { params, setParams, clearParams, activeFilterCount } = useQueryParams<
    Filters & Record<string, string>
  >();
  const { page, pageSize, setPage, setPageSize } = usePagination();
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const search = useDebounce(params.q ?? '', 350);

  const filters: Filters = {
    account_id: params.account_id,
    sender_account_id: params.sender_account_id,
    receiver_account_id: params.receiver_account_id,
    status: params.status,
    channel: params.channel,
    currency: params.currency,
    reference: params.reference,
    date_from: params.date_from,
    date_to: params.date_to,
    min_amount: params.min_amount ? Number(params.min_amount) : undefined,
    max_amount: params.max_amount ? Number(params.max_amount) : undefined,
    q: search || undefined,
  };

  const sortBy = params.sort_by ?? 'occurred_at';
  const sortOrder = (params.sort_order as 'asc' | 'desc') ?? 'desc';

  const query = useQuery({
    queryKey: queryKeys.transactions.list(page, pageSize, filters, `${sortBy}:${sortOrder}`),
    queryFn: () =>
      fetchTransactions({
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
        title="Transactions"
        description="The transaction ledger. Only completed transfers count as fund movement; the rest are shown but excluded from every aggregate in the platform."
      >
        <TransactionFilters
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
        <TransactionsTable
          rows={query.data?.items ?? []}
          isLoading={query.isLoading}
          isRefetching={query.isRefetching}
          sortBy={sortBy}
          sortOrder={sortOrder}
          onSortChange={(key, order) => setParams({ sort_by: key, sort_order: order })}
          onRowClick={(row) => setSelectedId(row.id)}
          selectedId={selectedId}
          perspectiveAccountId={params.account_id ?? null}
        />

        {query.data ? (
          <Pagination
            meta={pageInfo(query.data)!}
            onPageChange={setPage}
            onPageSizeChange={setPageSize}
            requestedPageSize={pageSize}
          />
        ) : null}
      </Card>

      <TransactionDetailDrawer
        transactionId={selectedId}
        onClose={() => setSelectedId(null)}
      />
    </div>
  );
}
