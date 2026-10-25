import { useQuery } from '@tanstack/react-query';

import { Card } from '@/components/common/Card';
import { ErrorState } from '@/components/common/ErrorState';
import { AlertsTable } from '@/components/tables/AlertsTable';
import { useApiError } from '@/hooks/useApiError';
import { formatCount } from '@/lib/amounts';
import { queryKeys } from '@/lib/queryKeys';

import { fetchAccountAlerts } from './accountsApi';

export interface AccountAlertsPanelProps {
  accountId: string;
  onSelect?: (alertId: string) => void;
}

/**
 * Alerts raised on this account.
 *
 * Bounded to the first page: an account with a long alert history is read
 * through the alert queue with a filter, not by paging a panel inside another
 * page. The count and a link make that route obvious.
 */
export function AccountAlertsPanel({ accountId, onSelect }: AccountAlertsPanelProps) {
  const query = useQuery({
    queryKey: queryKeys.accounts.alerts(accountId),
    queryFn: () =>
      fetchAccountAlerts(accountId, {
        page: 1,
        page_size: 10,
        sort_by: 'first_seen_at',
        sort_order: 'desc',
      }),
  });

  const error = useApiError(query.error);
  const total = query.data?.total ?? 0;
  const shown = query.data?.items.length ?? 0;

  return (
    <Card
      title="Alerts"
      description={
        total > shown
          ? `Showing the ${formatCount(shown)} most recent of ${formatCount(total)}.`
          : undefined
      }
      caveats={query.data?.caveats}
      flush
    >
      {error ? (
        <div className="p-4">
          <ErrorState error={error} onRetry={() => void query.refetch()} compact />
        </div>
      ) : (
        <AlertsTable
          rows={query.data?.items ?? []}
          isLoading={query.isLoading}
          onRowClick={onSelect ? (row) => onSelect(row.id) : undefined}
          emptyMessage="No alert has been raised on this account. If nothing has analysed it, that is the absence of a finding rather than a clean result."
        />
      )}
    </Card>
  );
}
