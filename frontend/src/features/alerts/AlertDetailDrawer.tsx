import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';

import { Badge } from '@/components/common/Badge';
import { CopyButton } from '@/components/common/CopyButton';
import { Drawer } from '@/components/common/Drawer';
import { ErrorState } from '@/components/common/ErrorState';
import { KeyValueList } from '@/components/common/KeyValueList';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { SeverityBadge } from '@/components/common/SeverityBadge';
import { StatusPill } from '@/components/common/StatusPill';
import { Tabs } from '@/components/common/Tabs';
import { useApiError } from '@/hooks/useApiError';
import { formatScore } from '@/lib/amounts';
import { SCORE_SEMANTICS } from '@/lib/constants';
import { formatDateTime, formatRelative } from '@/lib/dates';
import { formatCellValue, humaniseField, truncateId } from '@/lib/formatters';
import { queryKeys } from '@/lib/queryKeys';
import { paths } from '@/routes/paths';
import { useQueryParams } from '@/hooks/useQueryParams';

import { AlertEvidencePanel } from './AlertEvidencePanel';
import { AlertTriageActions } from './AlertTriageActions';
import { CreateCaseFromAlertButton } from './CreateCaseFromAlertButton';
import { fetchAlert, fetchAlertHistory } from './alertsApi';

export interface AlertDetailDrawerProps {
  alertId: string | null;
  onClose: () => void;
}

/**
 * One alert, in a side panel.
 *
 * The header pairs the score with the scoring mode, because the two are read
 * together or not at all: 84 from a trained model and 84 from the heuristic
 * fallback are the same number with different meanings, and neither is a
 * probability of guilt.
 *
 * The age line shows both instants. Deduplication updates an existing alert
 * rather than raising a new one, so "first seen" is the queue age and "last
 * seen" is how recently the pattern re-fired — an alert first seen a fortnight
 * ago and last seen this morning is a persistent pattern, not a stale row.
 */
export function AlertDetailDrawer({ alertId, onClose }: AlertDetailDrawerProps) {
  const { params, setParams } = useQueryParams();
  const tab = params.alert_tab ?? 'evidence';

  const query = useQuery({
    queryKey: queryKeys.alerts.detail(alertId ?? ''),
    queryFn: () => fetchAlert(alertId!),
    enabled: Boolean(alertId),
  });

  const historyQuery = useQuery({
    queryKey: queryKeys.alerts.history(alertId ?? ''),
    queryFn: () => fetchAlertHistory(alertId!, { page: 1, page_size: 25 }),
    enabled: Boolean(alertId) && tab === 'history',
  });

  const error = useApiError(query.error);
  const detail = query.data;
  const alert = detail?.alert;

  return (
    <Drawer open={Boolean(alertId)} onClose={onClose} title="Alert" width="xl">
      {query.isLoading ? (
        <LoadingSpinner label="Loading alert" />
      ) : error ? (
        <ErrorState error={error} onRetry={() => void query.refetch()} />
      ) : !alert ? null : (
        <div className="space-y-5">
          <div>
            <div className="mb-1.5 flex flex-wrap items-center gap-1.5">
              <SeverityBadge
                severity={(alert.priority as 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL') ?? null}
              />
              <StatusPill kind="alert" value={alert.state} />
              <StatusPill kind="scoring-mode" value={alert.scoring_mode} />
            </div>

            <h2 className="text-sm font-semibold text-ink-900 dark:text-ink-50">{alert.title}</h2>

            {alert.summary ? (
              <p className="mt-1 text-xs leading-relaxed text-ink-700 dark:text-ink-200">
                {alert.summary}
              </p>
            ) : null}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <AlertTriageActions alert={alert} />
            <CreateCaseFromAlertButton alert={alert} />
          </div>

          <KeyValueList
            columns={2}
            entries={[
              {
                label: 'Score',
                value: formatScore(alert.score),
                mono: true,
                help: SCORE_SEMANTICS,
              },
              {
                label: 'Account',
                value: (
                  <Link
                    to={paths.account(alert.account_id)}
                    className="font-mono text-accent-700 hover:underline dark:text-accent-300"
                  >
                    {truncateId(alert.account_id, 10)}
                  </Link>
                ),
              },
              {
                label: 'First seen',
                value: `${formatRelative(alert.first_seen_at)} (${formatDateTime(alert.first_seen_at)})`,
                help: 'Queue age is measured from here. Deduplication updates an existing alert rather than raising a new one.',
              },
              {
                label: 'Last re-observed',
                value: `${formatRelative(alert.last_seen_at)} (${formatDateTime(alert.last_seen_at)})`,
                help: 'The most recent run that saw this same signature.',
              },
              {
                label: 'Owner',
                value: alert.assigned_to ?? (
                  <Badge tone="warning" title="Nobody owns this alert.">
                    Unassigned
                  </Badge>
                ),
              },
              {
                label: 'Acknowledged',
                value: alert.acknowledged_at
                  ? `${formatDateTime(alert.acknowledged_at)}${alert.acknowledged_by ? ` by ${alert.acknowledged_by}` : ''}`
                  : 'Not yet',
              },
              {
                label: 'Rules fired',
                value:
                  alert.rule_codes.length > 0 ? (
                    <span className="flex flex-wrap gap-1">
                      {alert.rule_codes.map((code) => (
                        <Badge key={code} tone="neutral">
                          <span className="font-mono text-2xs">{code}</span>
                        </Badge>
                      ))}
                    </span>
                  ) : (
                    'None — this came from the model or anomaly components'
                  ),
                wide: true,
              },
              {
                label: 'Assessment',
                value: alert.assessment_id ? truncateId(alert.assessment_id, 10) : '—',
                mono: true,
              },
              {
                label: 'Score version',
                value: alert.score_version ?? '—',
                mono: true,
              },
              {
                label: 'Evidence reference',
                value: (
                  <span className="flex items-center gap-1">
                    <span className="font-mono text-2xs">ALERT:{alert.id}</span>
                    <CopyButton value={`ALERT:${alert.id}`} label="Copy evidence reference" />
                  </span>
                ),
                wide: true,
              },
            ]}
          />

          <Tabs
            activeId={tab}
            onChange={(id) => setParams({ alert_tab: id }, { resetPage: false })}
            items={[
              {
                id: 'evidence',
                label: 'Evidence',
                badge: detail?.evidences.length,
                content: (
                  <AlertEvidencePanel
                    rows={detail?.evidences ?? []}
                    total={alert.evidence_count ?? detail?.evidences.length}
                    truncated={detail?.evidence_truncated}
                  />
                ),
              },
              {
                id: 'signals',
                label: 'Signals',
                content: alert.signal_summary_json &&
                  Object.keys(alert.signal_summary_json).length > 0 ? (
                  <div>
                    <p className="mb-2 text-2xs leading-relaxed text-ink-600 dark:text-ink-300">
                      The figures the alert was raised on, as recorded at the time. These are the
                      numbers to check against the account's own ledger.
                    </p>
                    <dl className="space-y-1">
                      {Object.entries(alert.signal_summary_json).map(([key, value]) => (
                        <div key={key} className="flex gap-2 text-2xs">
                          <dt className="w-52 shrink-0 font-medium text-ink-600 dark:text-ink-300">
                            {humaniseField(key)}
                          </dt>
                          <dd className="min-w-0 break-words font-mono text-ink-800 dark:text-ink-100">
                            {formatCellValue(value)}
                          </dd>
                        </div>
                      ))}
                    </dl>
                  </div>
                ) : (
                  <p className="text-xs text-ink-500 dark:text-ink-400">
                    No signal summary was recorded on this alert.
                  </p>
                ),
              },
              {
                id: 'cases',
                label: 'Cases',
                badge: detail?.cases.length,
                content:
                  detail && detail.cases.length > 0 ? (
                    <ul className="space-y-1.5">
                      {detail.cases.map((item) => (
                        <li key={item.id} className="flex flex-wrap items-center gap-2 text-2xs">
                          <Link
                            to={paths.case(item.id)}
                            className="font-medium text-accent-700 hover:underline dark:text-accent-300"
                          >
                            {item.title}
                          </Link>
                          <StatusPill kind="case" value={item.status} />
                          <span className="text-ink-500 dark:text-ink-400">
                            {formatDateTime(item.created_at)}
                          </span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p className="text-xs text-ink-500 dark:text-ink-400">
                      No case has been opened from this alert.
                    </p>
                  ),
              },
              {
                id: 'history',
                label: 'History',
                content: historyQuery.isLoading ? (
                  <LoadingSpinner label="Loading history" />
                ) : (historyQuery.data?.items.length ?? 0) === 0 ? (
                  <p className="text-xs text-ink-500 dark:text-ink-400">
                    No recorded actions on this alert yet.
                  </p>
                ) : (
                  <ol className="space-y-2">
                    {(historyQuery.data?.items ?? []).map((event) => (
                      <li key={event.id} className="flex items-start gap-2">
                        <Badge
                          tone={
                            event.outcome === 'SUCCESS'
                              ? 'neutral'
                              : event.outcome === 'FAILURE'
                                ? 'danger'
                                : 'warning'
                          }
                        >
                          {humaniseField(event.outcome)}
                        </Badge>
                        <div className="min-w-0">
                          <p className="font-mono text-2xs text-ink-800 dark:text-ink-100">
                            {event.action}
                          </p>
                          <p className="text-2xs text-ink-500 dark:text-ink-400">
                            {event.actor_username ?? 'System'}
                            {' · '}
                            {formatDateTime(event.created_at)}
                          </p>
                        </div>
                      </li>
                    ))}
                  </ol>
                ),
              },
            ]}
          />

          {detail?.caveats && detail.caveats.length > 0 ? (
            <ul className="space-y-1 border-t border-ink-200 pt-3 dark:border-ink-700">
              {detail.caveats.map((caveat) => (
                <li key={caveat} className="text-2xs text-ink-600 dark:text-ink-300">
                  — {caveat}
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      )}
    </Drawer>
  );
}
