import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';

import { Badge } from '@/components/common/Badge';
import { Card } from '@/components/common/Card';
import { DataTable, type Column } from '@/components/common/DataTable';
import { ErrorState } from '@/components/common/ErrorState';
import { useApiError } from '@/hooks/useApiError';
import { formatConfidence, formatCount } from '@/lib/amounts';
import { MATCH_METHOD_LABELS, MATCH_TIER_TOKENS } from '@/lib/constants';
import { formatDate } from '@/lib/dates';
import { humaniseEnum, truncateId } from '@/lib/formatters';
import { queryKeys } from '@/lib/queryKeys';
import { paths } from '@/routes/paths';
import type { ComplaintCorrelation } from '@/types/complaint';

import { fetchAccountCorrelations } from './accountsApi';

export interface AccountComplaintsPanelProps {
  accountId: string;
}

/**
 * Complaints correlated to this account.
 *
 * The tier column does the heavy lifting, and the panel is built so the two
 * kinds of correlation cannot be read as one thing:
 *
 * - **Tiers 1-2 are identities.** The complaint names a transaction reference
 *   or an account id that exists. There is no confidence value, and showing a
 *   dash rather than 1.000 is deliberate — a dash says "not applicable", where
 *   a 1.000 would imply a measurement.
 *
 * - **Tiers 3-5 are inferences**, through a shared entity, the network or
 *   narrative text. Each carries a confidence and a review state, and until a
 *   human accepts one it is a lead rather than a finding.
 */
export function AccountComplaintsPanel({ accountId }: AccountComplaintsPanelProps) {
  const query = useQuery({
    queryKey: queryKeys.accounts.complaints(accountId),
    queryFn: () => fetchAccountCorrelations(accountId, { page: 1, page_size: 15 }),
  });

  const error = useApiError(query.error);
  const rows = query.data?.items ?? [];
  const total = query.data?.total ?? 0;

  const deterministicCount = rows.filter((row) => row.deterministic).length;

  const columns: Array<Column<ComplaintCorrelation>> = [
    {
      key: 'match_tier',
      header: 'Tier',
      render: (row) => {
        const token = MATCH_TIER_TOKENS[row.match_tier];

        return (
          <Badge
            accentColor={token?.hex}
            title={token?.description ?? `Tier ${row.match_tier} correlation.`}
          >
            {row.match_tier}
          </Badge>
        );
      },
      width: '8%',
    },
    {
      key: 'complaint_reference',
      header: 'Complaint',
      render: (row) => (
        <Link
          to={paths.complaint(row.complaint_id)}
          className="font-mono text-xs text-accent-700 hover:underline dark:text-accent-300"
          title={row.complaint_reference ?? row.complaint_id}
        >
          {truncateId(row.complaint_reference ?? row.complaint_id, 10)}
        </Link>
      ),
      width: '20%',
    },
    {
      key: 'complaint_category',
      header: 'Category',
      render: (row) => (
        <span className="text-xs text-ink-700 dark:text-ink-200">
          {row.complaint_category ? humaniseEnum(row.complaint_category) : '—'}
        </span>
      ),
      hideOnSmall: true,
      width: '16%',
    },
    {
      key: 'complaint_reported_at',
      header: 'Reported',
      render: (row) => (
        <span className="whitespace-nowrap text-xs tabular text-ink-600 dark:text-ink-300">
          {formatDate(row.complaint_reported_at)}
        </span>
      ),
      width: '12%',
    },
    {
      key: 'match_method',
      header: 'Matched by',
      render: (row) => (
        <span className="text-2xs text-ink-700 dark:text-ink-200">
          {MATCH_METHOD_LABELS[row.match_method] ?? humaniseEnum(row.match_method)}
        </span>
      ),
      width: '19%',
    },
    {
      key: 'confidence',
      header: 'Confidence',
      numeric: true,
      render: (row) =>
        row.deterministic ? (
          <span
            className="text-2xs text-ink-500 dark:text-ink-400"
            title="An identity match. No confidence value applies — showing 1.000 would imply a measurement that was never made."
          >
            identity
          </span>
        ) : (
          <span className="text-xs tabular">{formatConfidence(row.confidence)}</span>
        ),
      width: '13%',
    },
    {
      key: 'review_state',
      header: 'Review',
      render: (row) =>
        row.deterministic ? (
          <span className="text-2xs text-ink-400 dark:text-ink-500">—</span>
        ) : (
          <Badge
            tone={row.review_state === 'UNREVIEWED' ? 'warning' : 'neutral'}
            title={
              row.review_state === 'UNREVIEWED'
                ? 'Nobody has accepted or rejected this inference yet, so it is a lead.'
                : undefined
            }
          >
            {humaniseEnum(row.review_state)}
          </Badge>
        ),
      hideOnSmall: true,
      width: '12%',
    },
  ];

  return (
    <Card
      title="Complaint correlations"
      description={
        rows.length > 0
          ? `${formatCount(deterministicCount)} identity match${deterministicCount === 1 ? '' : 'es'} and ${formatCount(rows.length - deterministicCount)} inferred, of ${formatCount(total)} in total.`
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
        <DataTable
          caption="Complaints correlated to this account, by match tier"
          columns={columns}
          rows={rows}
          rowKey={(row) => row.id}
          isLoading={query.isLoading}
          emptyTitle="No complaint correlates to this account"
          emptyMessage="Correlation runs as part of an analysis run. An absence here is not evidence that no complaint concerns this account."
        />
      )}
    </Card>
  );
}
