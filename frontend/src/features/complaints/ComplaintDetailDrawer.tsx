import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';

import { Badge } from '@/components/common/Badge';
import { CopyButton } from '@/components/common/CopyButton';
import { Drawer } from '@/components/common/Drawer';
import { ErrorState } from '@/components/common/ErrorState';
import { KeyValueList } from '@/components/common/KeyValueList';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { Tabs } from '@/components/common/Tabs';
import { useApiError } from '@/hooks/useApiError';
import { useQueryParams } from '@/hooks/useQueryParams';
import { formatAmount, formatCount } from '@/lib/amounts';
import { formatDate, formatDateTime } from '@/lib/dates';
import { humaniseEnum, truncateId } from '@/lib/formatters';
import { queryKeys } from '@/lib/queryKeys';
import { paths } from '@/routes/paths';

import { ComplaintCorrelationTable } from './ComplaintCorrelationTable';
import {
  fetchComplaint,
  fetchComplaintCorrelations,
  fetchComplaintEntities,
  fetchComplaintTransactions,
} from './complaintsApi';

export interface ComplaintDetailDrawerProps {
  complaintId: string | null;
  onClose: () => void;
}

/**
 * One complaint, in a side panel.
 *
 * The narrative is *not* here. The API returns `narrative_available` and no
 * text: reading it needs the `read_complaint_narrative` capability, and this
 * drawer says so rather than showing an empty box. That is the right default
 * — the narrative is a victim's account of what happened to them, not
 * reference data every analyst needs open on screen.
 *
 * Everything the complainant alleged is labelled as an allegation. A victim
 * who mistyped a UPI handle names an innocent account, and the interface
 * should not quietly promote that to a finding.
 */
export function ComplaintDetailDrawer({ complaintId, onClose }: ComplaintDetailDrawerProps) {
  const { params, setParams } = useQueryParams();
  const tab = params.tab ?? 'correlations';

  const query = useQuery({
    queryKey: queryKeys.complaints.detail(complaintId ?? ''),
    queryFn: () => fetchComplaint(complaintId!),
    enabled: Boolean(complaintId),
  });

  const correlationsQuery = useQuery({
    queryKey: queryKeys.complaints.correlations(complaintId ?? ''),
    queryFn: () => fetchComplaintCorrelations(complaintId!, { page: 1, page_size: 50 }),
    enabled: Boolean(complaintId),
  });

  const transactionsQuery = useQuery({
    queryKey: [...queryKeys.complaints.all, 'transactions', complaintId ?? ''],
    queryFn: () => fetchComplaintTransactions(complaintId!, { page: 1, page_size: 25 }),
    enabled: Boolean(complaintId) && tab === 'transactions',
  });

  const entitiesQuery = useQuery({
    queryKey: [...queryKeys.complaints.all, 'entities', complaintId ?? ''],
    queryFn: () => fetchComplaintEntities(complaintId!, { page: 1, page_size: 25 }),
    enabled: Boolean(complaintId) && tab === 'identifiers',
  });

  const error = useApiError(query.error);
  const complaint = query.data;

  const correlations = correlationsQuery.data?.items ?? [];
  const deterministic = correlations.filter((item) => item.deterministic).length;

  return (
    <Drawer open={Boolean(complaintId)} onClose={onClose} title="Complaint" width="xl">
      {query.isLoading ? (
        <LoadingSpinner label="Loading complaint" />
      ) : error ? (
        <ErrorState error={error} onRetry={() => void query.refetch()} />
      ) : !complaint ? null : (
        <div className="space-y-5">
          <div>
            <div className="mb-1 flex flex-wrap items-center gap-1.5">
              <Badge tone="neutral">{humaniseEnum(complaint.category)}</Badge>
              {complaint.source ? (
                <Badge tone="neutral" title="Where the complaint came from.">
                  {complaint.source}
                </Badge>
              ) : null}
            </div>

            <h2 className="flex items-center gap-1 font-mono text-sm font-semibold text-ink-900 dark:text-ink-50">
              {complaint.reference}
              <CopyButton value={complaint.reference} label="Copy complaint reference" />
            </h2>

            <p className="mt-0.5 text-2xs text-ink-500 dark:text-ink-400">
              Reported {formatDate(complaint.reported_at)}
              {complaint.created_at ? ` · loaded ${formatDateTime(complaint.created_at)}` : ''}
            </p>
          </div>

          <KeyValueList
            columns={2}
            entries={[
              {
                label: 'Reported loss',
                value: formatAmount(complaint.amount, complaint.currency),
                mono: true,
                help: 'The amount stated in the complaint. Not independently verified against the ledger.',
              },
              {
                label: 'Correlations',
                value:
                  complaint.correlation_count !== null && complaint.correlation_count !== undefined
                    ? formatCount(complaint.correlation_count)
                    : '—',
              },
              {
                label: 'Transaction named',
                value: complaint.transaction_reference ? (
                  <Link
                    to={`${paths.transactions}?reference=${encodeURIComponent(complaint.transaction_reference)}`}
                    className="font-mono text-accent-700 hover:underline dark:text-accent-300"
                  >
                    {complaint.transaction_reference}
                  </Link>
                ) : (
                  'None given'
                ),
                help: 'As given by the complainant. A tier 1 correlation is this reference matching a transaction that exists.',
              },
              {
                label: 'Account named as suspect',
                value: complaint.suspected_account_id ? (
                  <Link
                    to={paths.account(complaint.suspected_account_id)}
                    className="font-mono text-accent-700 hover:underline dark:text-accent-300"
                  >
                    {truncateId(complaint.suspected_account_id, 10)}
                  </Link>
                ) : (
                  'None named'
                ),
                help: 'The complainant’s allegation, carried through from the filing. It is not a MuleGuard finding.',
              },
              {
                label: 'Victim account',
                value: complaint.victim_account_id ? (
                  <Link
                    to={paths.account(complaint.victim_account_id)}
                    className="font-mono text-accent-700 hover:underline dark:text-accent-300"
                  >
                    {truncateId(complaint.victim_account_id, 10)}
                  </Link>
                ) : (
                  '—'
                ),
              },
              {
                label: 'Narrative',
                value: complaint.narrative_available ? (
                  <Badge
                    tone="neutral"
                    title="The complaint has a narrative. Reading it requires the complaint-narrative permission; it is the victim's own account of events, not reference data."
                  >
                    On file, not shown here
                  </Badge>
                ) : (
                  'None'
                ),
                help: 'Tiers 4 and 5 correlation read this text. The text itself is not served to this view.',
              },
              {
                label: 'Evidence reference',
                value: (
                  <span className="flex items-center gap-1">
                    <span className="font-mono text-2xs">COMPLAINT:{complaint.id}</span>
                    <CopyButton value={`COMPLAINT:${complaint.id}`} label="Copy evidence reference" />
                  </span>
                ),
                wide: true,
              },
            ]}
          />

          <Tabs
            activeId={tab}
            onChange={(id) => setParams({ tab: id }, { resetPage: false })}
            items={[
              {
                id: 'correlations',
                label: 'Correlations',
                badge: correlationsQuery.data?.total,
                content: (
                  <div>
                    {correlations.length > 0 ? (
                      <p className="mb-2 text-2xs text-ink-600 dark:text-ink-300">
                        {formatCount(deterministic)} identity match
                        {deterministic === 1 ? '' : 'es'} and{' '}
                        {formatCount(correlations.length - deterministic)} inferred. Only the
                        inferred ones are reviewable, because an identity either holds or does not.
                      </p>
                    ) : null}

                    <ComplaintCorrelationTable
                      complaintId={complaint.id}
                      rows={correlations}
                      isLoading={correlationsQuery.isLoading}
                    />
                  </div>
                ),
              },
              {
                id: 'transactions',
                label: 'Transactions',
                content: transactionsQuery.isLoading ? (
                  <LoadingSpinner label="Loading transactions" />
                ) : (transactionsQuery.data?.items.length ?? 0) === 0 ? (
                  <p className="text-xs text-ink-500 dark:text-ink-400">
                    No transaction has been correlated to this complaint.
                  </p>
                ) : (
                  <ul className="space-y-1.5">
                    {(transactionsQuery.data?.items ?? []).map((item) => (
                      <li key={item.correlation_id} className="flex flex-wrap items-center gap-2 text-2xs">
                        <span className="font-mono">{item.reference}</span>
                        <span className="tabular">{formatAmount(item.amount, item.currency)}</span>
                        <span className="text-ink-500 dark:text-ink-400">
                          {formatDateTime(item.occurred_at)}
                        </span>
                        <Badge tone="neutral">{humaniseEnum(item.status)}</Badge>
                        <span className="text-ink-500 dark:text-ink-400">
                          tier {item.match_tier}
                        </span>
                      </li>
                    ))}
                  </ul>
                ),
              },
              {
                id: 'identifiers',
                label: 'Identifiers',
                content: entitiesQuery.isLoading ? (
                  <LoadingSpinner label="Loading identifiers" />
                ) : (entitiesQuery.data?.items.length ?? 0) === 0 ? (
                  <p className="text-xs text-ink-500 dark:text-ink-400">
                    No shared identifier has been correlated to this complaint.
                  </p>
                ) : (
                  <div>
                    <p className="mb-2 text-2xs leading-relaxed text-ink-600 dark:text-ink-300">
                      Identifiers are stored hashed. Sharing one suggests a connection between
                      accounts; it does not establish common control.
                    </p>
                    <ul className="space-y-1.5">
                      {(entitiesQuery.data?.items ?? []).map((item) => (
                        <li key={item.correlation_id} className="flex flex-wrap items-center gap-2 text-2xs">
                          <Badge tone="neutral">{humaniseEnum(item.entity_type)}</Badge>
                          <span className="font-mono">
                            {item.identifier_display ?? truncateId(item.id, 10)}
                          </span>
                          <span className="text-ink-500 dark:text-ink-400">
                            tier {item.match_tier} · {humaniseEnum(item.review_state)}
                          </span>
                        </li>
                      ))}
                    </ul>
                  </div>
                ),
              },
            ]}
          />
        </div>
      )}
    </Drawer>
  );
}
