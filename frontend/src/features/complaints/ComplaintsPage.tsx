import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';

import { ComplaintsByCategoryChart } from '@/components/charts/ComplaintsByCategoryChart';
import { KpiCard } from '@/components/charts/KpiCard';
import { Card } from '@/components/common/Card';
import { ErrorState } from '@/components/common/ErrorState';
import { Pagination } from '@/components/common/Pagination';
import { ComplaintsTable } from '@/components/tables/ComplaintsTable';
import { PageHeader } from '@/components/layout/PageHeader';
import { useApiError } from '@/hooks/useApiError';
import { useDebounce } from '@/hooks/useDebounce';
import { usePagination } from '@/hooks/usePagination';
import { useQueryParams } from '@/hooks/useQueryParams';
import { formatCount, formatPercent } from '@/lib/amounts';
import { queryKeys } from '@/lib/queryKeys';
import { pageInfo } from '@/types/common';
import { toCategoryCounts } from '@/types/dashboard';
import type { ComplaintFilters as Filters } from '@/types/complaint';

import { ComplaintDetailDrawer } from './ComplaintDetailDrawer';
import { ComplaintFilters } from './ComplaintFilters';
import { fetchComplaints, fetchComplaintStats } from './complaintsApi';

/**
 * Cybercrime complaints.
 *
 * The three figures across the top are the ones that decide how much weight
 * the complaint side of the platform can bear: how many complaints are held,
 * how many correlations are identities rather than inferences, and how many
 * inferences nobody has reviewed. An unreviewed backlog means the correlation
 * output is unverified, which is worth knowing before citing any of it.
 *
 * The complaint being viewed is in the URL, so a particular complaint is a
 * link a colleague can open.
 */
export default function ComplaintsPage() {
  const { params, setParams, clearParams, activeFilterCount } = useQueryParams<
    Filters & Record<string, string>
  >();
  const { page, pageSize, setPage, setPageSize } = usePagination();

  const selectedId = params.complaintId ?? null;
  const search = useDebounce(params.q ?? '', 350);

  const filters: Filters = {
    category: params.category,
    source: params.source,
    victim_account_id: params.victim_account_id,
    suspected_account_id: params.suspected_account_id,
    transaction_reference: params.transaction_reference,
    date_from: params.date_from,
    date_to: params.date_to,
    min_amount: params.min_amount ? Number(params.min_amount) : undefined,
    max_amount: params.max_amount ? Number(params.max_amount) : undefined,
    q: search || undefined,
  };

  const sortBy = params.sort_by ?? 'reported_at';
  const sortOrder = (params.sort_order as 'asc' | 'desc') ?? 'desc';

  const query = useQuery({
    queryKey: queryKeys.complaints.list(page, pageSize, filters, `${sortBy}:${sortOrder}`),
    queryFn: () =>
      fetchComplaints({
        page,
        page_size: pageSize,
        sort_by: sortBy,
        sort_order: sortOrder,
        filters,
      }),
  });

  const statsQuery = useQuery({
    queryKey: queryKeys.complaints.stats(),
    queryFn: () => fetchComplaintStats({ top_limit: 12 }),
    staleTime: 2 * 60_000,
  });

  const error = useApiError(query.error);
  const statsError = useApiError(statsQuery.error);
  const stats = statsQuery.data;

  const unreviewed = stats?.by_review_state?.UNREVIEWED ?? 0;
  const categories = useMemo(() => Object.keys(stats?.by_category ?? {}), [stats]);
  const sources = useMemo(() => Object.keys(stats?.by_source ?? {}), [stats]);

  return (
    <div>
      <PageHeader
        title="Complaints"
        description="Cybercrime complaints and the records they have been correlated to. What a complainant alleged is shown as an allegation, not as a finding."
      >
        <ComplaintFilters
          values={params}
          onChange={setParams}
          onClear={() => clearParams()}
          activeCount={activeFilterCount}
          categories={categories}
          sources={sources}
        />
      </PageHeader>

      <div className="mb-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <KpiCard
          label="Complaints"
          value={stats?.total_complaints ?? null}
          isLoading={statsQuery.isLoading}
          definition="Complaints held in the selected window. The window is the server's default unless a date filter is applied."
        />
        <KpiCard
          label="Identity matches"
          value={stats?.deterministic_count ?? null}
          isLoading={statsQuery.isLoading}
          definition="Tier 1-2 correlations: the complaint named a reference that exists. These carry no confidence value because they are identities, not estimates."
        />
        <KpiCard
          label="Inferred links"
          value={stats?.inferred_count ?? null}
          isLoading={statsQuery.isLoading}
          definition="Tier 3-5 correlations, matched through a shared identifier, the network or narrative text. Each is a lead until a reviewer accepts it."
        />
        <KpiCard
          label="Unreviewed"
          value={unreviewed}
          isLoading={statsQuery.isLoading}
          emphasis={unreviewed > 0 ? 'attention' : 'none'}
          definition="Inferred correlations nobody has accepted or rejected. Until reviewed, none of them should be relied on in a report."
          detail={
            stats && stats.total_correlations > 0
              ? `${formatPercent(unreviewed / stats.total_correlations)} of ${formatCount(stats.total_correlations)} correlations`
              : undefined
          }
        />
      </div>

      <div className="mb-5 grid gap-5 lg:grid-cols-3">
        <Card
          title="By category"
          description="A long tail is folded into one bar rather than dropped."
          className="lg:col-span-2"
          caveats={stats?.caveats}
        >
          <ComplaintsByCategoryChart
            data={toCategoryCounts(stats?.by_category)}
            isLoading={statsQuery.isLoading}
            error={statsError}
            onRetry={() => void statsQuery.refetch()}
            onSelectCategory={(category) => setParams({ category })}
          />
        </Card>

        <Card title="By match tier" description="1 is strongest, 5 is text extraction.">
          {stats && Object.keys(stats.by_match_tier).length > 0 ? (
            <ul className="space-y-2">
              {['1', '2', '3', '4', '5'].map((tier) => {
                const count = stats.by_match_tier[tier] ?? 0;
                const share =
                  stats.total_correlations > 0 ? count / stats.total_correlations : 0;

                return (
                  <li key={tier} className="flex items-center gap-2">
                    <span className="w-12 shrink-0 text-2xs text-ink-700 dark:text-ink-200">
                      Tier {tier}
                    </span>
                    <span
                      aria-hidden="true"
                      className="h-1.5 min-w-[2px] rounded-sm bg-accent-500 dark:bg-accent-400"
                      style={{ width: `${Math.max(share * 100, count > 0 ? 2 : 0)}%` }}
                    />
                    <span className="text-2xs tabular text-ink-600 dark:text-ink-300">
                      {formatCount(count)}
                    </span>
                  </li>
                );
              })}
            </ul>
          ) : (
            <p className="text-xs text-ink-500 dark:text-ink-400">
              No correlations in this window.
            </p>
          )}

          <p className="mt-3 text-2xs leading-relaxed text-ink-600 dark:text-ink-300">
            Tiers 1-2 are identities and need no review. Tiers 3-5 are inferences and each carries
            a confidence; a platform whose correlations are mostly tier 5 is running on text
            extraction, which is the weakest signal here.
          </p>
        </Card>
      </div>

      {error ? (
        <ErrorState error={error} onRetry={() => void query.refetch()} className="mb-4" />
      ) : null}

      <Card flush caveats={query.data?.caveats}>
        <ComplaintsTable
          rows={query.data?.items ?? []}
          isLoading={query.isLoading}
          isRefetching={query.isRefetching}
          sortBy={sortBy}
          sortOrder={sortOrder}
          onSortChange={(key, order) => setParams({ sort_by: key, sort_order: order })}
          onRowClick={(row) => setParams({ complaintId: row.id }, { resetPage: false })}
          selectedId={selectedId}
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

      <ComplaintDetailDrawer
        complaintId={selectedId}
        onClose={() => setParams({ complaintId: undefined }, { resetPage: false })}
      />
    </div>
  );
}
