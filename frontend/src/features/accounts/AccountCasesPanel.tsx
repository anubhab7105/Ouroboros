import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';

import { Card } from '@/components/common/Card';
import { ErrorState } from '@/components/common/ErrorState';
import { CasesTable } from '@/components/tables/CasesTable';
import { useApiError } from '@/hooks/useApiError';
import { formatCount } from '@/lib/amounts';
import { queryKeys } from '@/lib/queryKeys';
import { paths } from '@/routes/paths';

import { fetchCases } from '@/features/cases/casesApi';

export interface AccountCasesPanelProps {
  accountId: string;
}

/**
 * Investigations touching this account.
 *
 * The case list endpoint takes an `account_id` filter, so this is the same
 * list the Cases page shows, scoped. Reusing the table rather than writing a
 * reduced one keeps the disposition column — which is the thing worth seeing
 * here, because a previous investigation that closed as a false positive is
 * context an analyst needs before opening another.
 */
export function AccountCasesPanel({ accountId }: AccountCasesPanelProps) {
  const query = useQuery({
    queryKey: queryKeys.cases.list(1, 10, { account_id: accountId }),
    queryFn: () =>
      fetchCases({
        page: 1,
        page_size: 10,
        sort_by: 'updated_at',
        sort_order: 'desc',
        filters: { account_id: accountId },
      }),
  });

  const error = useApiError(query.error);
  const total = query.data?.total ?? 0;
  const shown = query.data?.items.length ?? 0;

  return (
    <Card
      title="Cases"
      description={
        total > shown
          ? `Showing ${formatCount(shown)} of ${formatCount(total)}.`
          : 'Investigations that reference this account.'
      }
      actions={
        total > 0 ? (
          <Link
            to={`${paths.cases}?account_id=${encodeURIComponent(accountId)}`}
            className="text-2xs font-medium text-accent-700 hover:underline dark:text-accent-300"
          >
            All cases
          </Link>
        ) : null
      }
      caveats={query.data?.caveats}
      flush
    >
      {error ? (
        <div className="p-4">
          <ErrorState error={error} onRetry={() => void query.refetch()} compact />
        </div>
      ) : (
        <CasesTable
          rows={query.data?.items ?? []}
          isLoading={query.isLoading}
          emptyMessage="No investigation references this account."
        />
      )}
    </Card>
  );
}
