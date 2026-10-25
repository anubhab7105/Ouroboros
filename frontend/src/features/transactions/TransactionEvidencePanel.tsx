import { useQuery } from '@tanstack/react-query';

import { Badge } from '@/components/common/Badge';
import { CopyButton } from '@/components/common/CopyButton';
import { EmptyState } from '@/components/common/EmptyState';
import { KeyValueList } from '@/components/common/KeyValueList';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { formatAmount } from '@/lib/amounts';
import { CHANNEL_LABELS } from '@/lib/constants';
import { formatDateTime } from '@/lib/dates';
import { humaniseEnum } from '@/lib/formatters';
import { queryKeys } from '@/lib/queryKeys';
import { isFundMovement } from '@/types/transaction';

import { fetchTransactionCorrelations } from './transactionsApi';

export interface TransactionEvidencePanelProps {
  transactionId: string;
  /** Present when the caller already loaded the transaction. */
  transaction?: {
    id: string;
    reference: string;
    amount: number;
    currency: string;
    occurred_at: string;
    status: string;
    channel: string;
    sender_account_id: string;
    receiver_account_id: string;
  };
}

/**
 * What can be said about one transaction, as evidence.
 *
 * This panel is the thing an analyst reads before attaching a transaction to a
 * case, so it states the evidential position rather than only the figures:
 * the reference an investigator would quote, whether the transfer counts as
 * fund movement, and which complaints have been correlated to it — with the
 * deterministic ones distinguished from the inferred ones, because only the
 * first are identities.
 */
export function TransactionEvidencePanel({
  transactionId,
  transaction,
}: TransactionEvidencePanelProps) {
  const correlationsQuery = useQuery({
    queryKey: queryKeys.transactions.correlations(transactionId),
    queryFn: () => fetchTransactionCorrelations(transactionId, { page: 1, page_size: 25 }),
  });

  const correlations = correlationsQuery.data?.items ?? [];
  const deterministic = correlations.filter((item) => item.deterministic);
  const inferred = correlations.filter((item) => !item.deterministic);

  return (
    <div className="space-y-4">
      {transaction ? (
        <KeyValueList
          columns={2}
          entries={[
            {
              label: 'Reference',
              value: (
                <span className="flex items-center gap-1">
                  <span className="font-mono">{transaction.reference}</span>
                  <CopyButton
                    value={transaction.reference}
                    label={`Copy reference ${transaction.reference}`}
                  />
                </span>
              ),
              help: 'The identifier a complainant would quote, and what a tier 1 correlation matches on.',
            },
            {
              label: 'Amount',
              value: formatAmount(transaction.amount, transaction.currency),
              mono: true,
            },
            { label: 'Occurred', value: formatDateTime(transaction.occurred_at) },
            {
              label: 'Channel',
              value: CHANNEL_LABELS[transaction.channel] ?? transaction.channel,
            },
            {
              label: 'Counts as fund movement',
              value: isFundMovement(transaction) ? 'Yes' : 'No',
              help: 'Only completed transfers do. Everything else is excluded from every aggregate in the platform.',
            },
            {
              label: 'Status',
              value: humaniseEnum(transaction.status),
            },
            {
              label: 'Evidence reference',
              value: (
                <span className="flex items-center gap-1">
                  <span className="font-mono text-2xs">TRANSACTION:{transaction.id}</span>
                  <CopyButton
                    value={`TRANSACTION:${transaction.id}`}
                    label="Copy evidence reference"
                  />
                </span>
              ),
              wide: true,
              help: 'The form used when this transaction is cited in a case or a report.',
            },
          ]}
        />
      ) : null}

      <div className="border-t border-ink-200 pt-3 dark:border-ink-700">
        <h3 className="mb-1.5 text-2xs font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
          Complaint correlations
        </h3>

        {correlationsQuery.isLoading ? (
          <LoadingSpinner label="Loading correlations" />
        ) : correlations.length === 0 ? (
          <EmptyState
            title="No complaint links this transaction"
            message="Correlation runs as part of an analysis run. An absence here is not evidence that no complaint concerns it."
            compact
          />
        ) : (
          <div className="space-y-3">
            {deterministic.length > 0 ? (
              <div>
                <p className="mb-1 flex items-center gap-1.5 text-2xs text-ink-600 dark:text-ink-300">
                  <Badge tone="neutral" title="Tier 1-2: the complaint names a reference that exists.">
                    Identity match
                  </Badge>
                  {deterministic.length}
                </p>
                <ul className="space-y-1">
                  {deterministic.map((item) => (
                    <li key={item.id} className="text-2xs text-ink-700 dark:text-ink-200">
                      <span className="font-mono">{item.complaint_reference ?? item.complaint_id}</span>
                      {item.complaint_category ? ` · ${humaniseEnum(item.complaint_category)}` : ''}
                      {' · tier '}
                      {item.match_tier}
                      {' · '}
                      {humaniseEnum(item.match_method)}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}

            {inferred.length > 0 ? (
              <div>
                <p className="mb-1 flex items-center gap-1.5 text-2xs text-ink-600 dark:text-ink-300">
                  <Badge
                    tone="warning"
                    title="Tier 3-5: matched through an entity, the network or narrative text. A lead until a human accepts it."
                  >
                    Inferred
                  </Badge>
                  {inferred.length}
                </p>
                <ul className="space-y-1">
                  {inferred.map((item) => (
                    <li key={item.id} className="text-2xs text-ink-700 dark:text-ink-200">
                      <span className="font-mono">{item.complaint_reference ?? item.complaint_id}</span>
                      {' · tier '}
                      {item.match_tier}
                      {' · '}
                      {humaniseEnum(item.match_method)}
                      {item.confidence !== null && item.confidence !== undefined
                        ? ` · confidence ${item.confidence.toFixed(3)}`
                        : ''}
                      {' · '}
                      {humaniseEnum(item.review_state)}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </div>
        )}
      </div>
    </div>
  );
}
