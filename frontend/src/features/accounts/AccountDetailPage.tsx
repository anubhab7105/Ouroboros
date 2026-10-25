import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';

import { Button } from '@/components/common/Button';
import { Card } from '@/components/common/Card';
import { ErrorState } from '@/components/common/ErrorState';
import { KeyValueList } from '@/components/common/KeyValueList';
import { Tabs } from '@/components/common/Tabs';
import { PageHeader } from '@/components/layout/PageHeader';
import { useApiError } from '@/hooks/useApiError';
import { usePagination } from '@/hooks/usePagination';
import { useQueryParams } from '@/hooks/useQueryParams';
import { formatAmount, formatCount } from '@/lib/amounts';
import { formatDateTime } from '@/lib/dates';
import { queryKeys } from '@/lib/queryKeys';
import { paths } from '@/routes/paths';

import { TransactionDetailDrawer } from '@/features/transactions/TransactionDetailDrawer';

import { AccountAlertsPanel } from './AccountAlertsPanel';
import { AccountCasesPanel } from './AccountCasesPanel';
import { AccountComplaintsPanel } from './AccountComplaintsPanel';
import { AccountFeaturePanel } from './AccountFeaturePanel';
import { AccountOverviewPanel } from './AccountOverviewPanel';
import { AccountRiskPanel } from './AccountRiskPanel';
import { AccountTimelinePanel } from './AccountTimelinePanel';
import { fetchAccount, fetchAccountAssessment, fetchAccountSummary } from './accountsApi';

/**
 * One account, in full.
 *
 * Tabs rather than one long page, because the sections answer different
 * questions and an investigator arrives with one of them in mind. The tab is
 * in the URL, so a colleague can be sent straight to the risk breakdown
 * rather than to the top of the page.
 *
 * The windowed summary sits above the tabs: inbound and outbound totals,
 * counterparty counts and the non-completed counts that explain the gap
 * between the ledger and the totals. Those are the figures every tab is read
 * against.
 */
export default function AccountDetailPage() {
  const { accountId = '' } = useParams();
  const { params, setParams } = useQueryParams();
  const { page, pageSize, setPage, setPageSize } = usePagination(25);
  const [selectedTransaction, setSelectedTransaction] = useState<string | null>(null);

  const activeTab = params.tab ?? 'activity';

  const accountQuery = useQuery({
    queryKey: queryKeys.accounts.detail(accountId),
    queryFn: () => fetchAccount(accountId),
    enabled: Boolean(accountId),
  });

  const summaryQuery = useQuery({
    queryKey: queryKeys.accounts.summary(accountId),
    queryFn: () => fetchAccountSummary(accountId),
    enabled: Boolean(accountId),
  });

  const assessmentQuery = useQuery({
    queryKey: queryKeys.accounts.assessment(accountId),
    queryFn: () => fetchAccountAssessment(accountId),
    enabled: Boolean(accountId),
  });

  const accountError = useApiError(accountQuery.error);
  const summary = summaryQuery.data;

  return (
    <div>
      <PageHeader
        title={
          <span className="font-mono text-base">{accountId}</span>
        }
        description="One account: its ledger, its risk assessment and the investigations and complaints that reference it."
        actions={
          <div className="flex items-center gap-2">
            <Link to={paths.graphForAccount(accountId)}>
              <Button size="sm" variant="secondary">
                Open in network view
              </Button>
            </Link>
            <Link to={`${paths.transactions}?account_id=${encodeURIComponent(accountId)}`}>
              <Button size="sm" variant="ghost">
                Full ledger
              </Button>
            </Link>
          </div>
        }
      />

      {accountError ? (
        <ErrorState
          error={accountError}
          onRetry={() => void accountQuery.refetch()}
          className="mb-4"
        />
      ) : null}

      {summary ? (
        <Card
          className="mb-5"
          title="Activity in window"
          description={
            summary.window
              ? `Window as applied by the server. Monetary figures count completed transfers only, in ${summary.currency}.`
              : undefined
          }
          caveats={summary.caveats}
        >
          <KeyValueList
            columns={3}
            entries={[
              {
                label: 'Inbound',
                value: `${formatAmount(summary.incoming_completed_amount, summary.currency)} over ${formatCount(summary.incoming_completed_count)}`,
              },
              {
                label: 'Outbound',
                value: `${formatAmount(summary.outgoing_completed_amount, summary.currency)} over ${formatCount(summary.outgoing_completed_count)}`,
              },
              {
                label: 'Net',
                value: formatAmount(summary.net_completed_amount, summary.currency),
                help: 'Inbound minus outbound over completed transfers. A near-zero net with high volume is the pass-through shape.',
              },
              {
                label: 'Distinct senders',
                value: formatCount(summary.distinct_incoming_counterparties),
                help: 'Many senders into one account is the fan-in shape a collection account produces.',
              },
              {
                label: 'Distinct recipients',
                value: formatCount(summary.distinct_outgoing_recipients),
                help: 'Many recipients out of one account is the fan-out shape of a distribution account.',
              },
              {
                label: 'Self transfers',
                value: formatCount(summary.self_transfer_count),
                help: 'Transfers where this account is both sender and receiver. Excluded from counterparty counts.',
              },
              {
                label: 'Not counted',
                value: `${formatCount(summary.pending_count)} pending, ${formatCount(summary.failed_count)} failed, ${formatCount(summary.reversed_count)} reversed`,
                help: 'These appear in the ledger and in no total. They are the difference between the ledger and the figures above.',
                wide: true,
              },
              {
                label: 'Open alerts',
                value: formatCount(summary.open_alert_count),
              },
              {
                label: 'Complaint links',
                value: formatCount(summary.complaint_correlation_count),
              },
              {
                label: 'Active shared identifiers',
                value: formatCount(summary.active_entity_link_count),
                help: 'Entity links valid now. Sharing an identifier suggests a connection; it does not prove common control.',
              },
            ]}
          />

          {summary.latest_assessment ? (
            <p className="mt-3 border-t border-ink-200 pt-2 text-2xs text-ink-500 dark:border-ink-700 dark:text-ink-400">
              Latest assessment as of {formatDateTime(summary.latest_assessment.as_of)}, scored{' '}
              {formatDateTime(summary.latest_assessment.scored_at)}.
            </p>
          ) : null}
        </Card>
      ) : null}

      <Tabs
        activeId={activeTab}
        onChange={(id) => setParams({ tab: id }, { resetPage: false })}
        items={[
          {
            id: 'activity',
            label: 'Activity',
            content: (
              <AccountTimelinePanel
                accountId={accountId}
                page={page}
                pageSize={pageSize}
                onPageChange={setPage}
                onPageSizeChange={setPageSize}
                onSelect={setSelectedTransaction}
              />
            ),
          },
          {
            id: 'risk',
            label: 'Risk',
            content: (
              <div className="space-y-5">
                <AccountRiskPanel
                  assessment={assessmentQuery.data}
                  isLoading={assessmentQuery.isLoading}
                />
                <AccountFeaturePanel
                  featureSnapshotId={assessmentQuery.data?.assessment?.feature_snapshot_id}
                />
              </div>
            ),
          },
          {
            id: 'alerts',
            label: 'Alerts',
            content: (
              <div className="space-y-5">
                <AccountAlertsPanel accountId={accountId} />
                <AccountCasesPanel accountId={accountId} />
              </div>
            ),
          },
          {
            id: 'complaints',
            label: 'Complaints',
            content: <AccountComplaintsPanel accountId={accountId} />,
          },
          {
            id: 'record',
            label: 'Record',
            content: (
              <AccountOverviewPanel
                account={accountQuery.data}
                isLoading={accountQuery.isLoading}
              />
            ),
          },
        ]}
      />

      <TransactionDetailDrawer
        transactionId={selectedTransaction}
        onClose={() => setSelectedTransaction(null)}
      />
    </div>
  );
}
