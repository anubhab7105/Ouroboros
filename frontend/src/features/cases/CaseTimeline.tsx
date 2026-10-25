import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';

import { Badge } from '@/components/common/Badge';
import { Card } from '@/components/common/Card';
import { EmptyState } from '@/components/common/EmptyState';
import { ErrorState } from '@/components/common/ErrorState';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { Pagination } from '@/components/common/Pagination';
import { Tabs } from '@/components/common/Tabs';
import { RoleGate } from '@/components/layout/RoleGate';
import { useApiError } from '@/hooks/useApiError';
import { formatDateTime, formatRelative } from '@/lib/dates';
import { formatCellValue, humaniseField, truncateId } from '@/lib/formatters';
import { PERMISSIONS } from '@/lib/permissions';
import { queryKeys } from '@/lib/queryKeys';
import { pageInfo } from '@/types/common';

import { fetchCaseAudit, fetchCaseEvents } from './casesApi';

export interface CaseTimelineProps {
  caseId: string;
}

/**
 * What happened to this case, and who did it.
 *
 * Two tabs, because they are genuinely different records:
 *
 * - **History** is the case's own event stream — the transitions,
 *   assignments, notes and evidence changes, in order. It is what an
 *   investigator reads to pick up someone else's case.
 *
 * - **Audit** is the platform's audit trail filtered to this case, including
 *   refused attempts. It is what a reviewer reads, and it needs the audit
 *   permission, so the tab explains itself rather than silently vanishing.
 */
export function CaseTimeline({ caseId }: CaseTimelineProps) {
  const [tab, setTab] = useState('history');
  const [eventPage, setEventPage] = useState(1);
  const [auditPage, setAuditPage] = useState(1);

  const eventsQuery = useQuery({
    queryKey: queryKeys.cases.events(caseId, eventPage),
    queryFn: () =>
      fetchCaseEvents(caseId, {
        page: eventPage,
        page_size: 25,
        sort_by: 'created_at',
        sort_order: 'desc',
      }),
  });

  const auditQuery = useQuery({
    queryKey: queryKeys.cases.audit(caseId, auditPage),
    queryFn: () =>
      fetchCaseAudit(caseId, {
        page: auditPage,
        page_size: 25,
        sort_by: 'created_at',
        sort_order: 'desc',
      }),
    enabled: tab === 'audit',
  });

  const eventsError = useApiError(eventsQuery.error);
  const auditError = useApiError(auditQuery.error);

  const events = eventsQuery.data?.items ?? [];
  const auditEvents = auditQuery.data?.items ?? [];

  return (
    <Card title="History" flush>
      <div className="px-4 pt-4">
        <Tabs
          activeId={tab}
          onChange={setTab}
          items={[
            {
              id: 'history',
              label: 'Case events',
              badge: eventsQuery.data?.total,
              content: (
                <div>
                  {eventsError ? (
                    <ErrorState
                      error={eventsError}
                      onRetry={() => void eventsQuery.refetch()}
                      compact
                    />
                  ) : eventsQuery.isLoading ? (
                    <LoadingSpinner label="Loading history" />
                  ) : events.length === 0 ? (
                    <EmptyState title="No events recorded" compact />
                  ) : (
                    <ol className="space-y-2">
                      {events.map((event) => (
                        <li key={event.id} className="flex gap-3">
                          <span
                            aria-hidden="true"
                            className="mt-1 h-1.5 w-1.5 shrink-0 rounded-full bg-ink-300 dark:bg-ink-600"
                          />
                          <div className="min-w-0">
                            <p className="text-xs text-ink-800 dark:text-ink-100">
                              <span className="font-medium">{humaniseField(event.action)}</span>
                              {event.summary ? (
                                <span className="text-ink-700 dark:text-ink-200">
                                  {' — '}
                                  {event.summary}
                                </span>
                              ) : null}
                            </p>
                            <p className="mt-0.5 text-2xs text-ink-500 dark:text-ink-400">
                              {event.actor_username ??
                                (event.actor_id ? truncateId(event.actor_id, 6) : 'System')}
                              {' · '}
                              <span title={formatDateTime(event.created_at)}>
                                {formatRelative(event.created_at)}
                              </span>
                              {event.resource_type ? (
                                <>
                                  {' · '}
                                  {humaniseField(event.resource_type)}
                                  {event.resource_id ? ` ${truncateId(event.resource_id, 6)}` : ''}
                                </>
                              ) : null}
                            </p>
                          </div>
                        </li>
                      ))}
                    </ol>
                  )}

                  {eventsQuery.data ? (
                    <Pagination
                      meta={pageInfo(eventsQuery.data)!}
                      onPageChange={setEventPage}
                      className="mt-3 border-t-0 px-0"
                    />
                  ) : null}
                </div>
              ),
            },
            {
              id: 'audit',
              label: 'Audit trail',
              content: (
                <RoleGate
                  permissions={[PERMISSIONS.readAudit]}
                  action="see the audit trail for this case"
                >
                  <div>
                    <p className="mb-2 text-2xs leading-relaxed text-ink-600 dark:text-ink-300">
                      Every recorded action against this case, including attempts that were
                      refused. Append-only: entries cannot be edited or removed.
                    </p>

                    {auditError ? (
                      <ErrorState
                        error={auditError}
                        onRetry={() => void auditQuery.refetch()}
                        compact
                      />
                    ) : auditQuery.isLoading ? (
                      <LoadingSpinner label="Loading audit trail" />
                    ) : auditEvents.length === 0 ? (
                      <EmptyState title="No audit entries for this case" compact />
                    ) : (
                      <ol className="space-y-2">
                        {auditEvents.map((event) => (
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
                                {event.actor_role ? ` (${humaniseField(event.actor_role)})` : ''}
                                {' · '}
                                {formatDateTime(event.created_at)}
                                {event.request_id ? ` · request ${truncateId(event.request_id, 6)}` : ''}
                              </p>
                              {event.metadata_json &&
                              Object.keys(event.metadata_json).length > 0 ? (
                                <p className="mt-0.5 break-words text-2xs text-ink-600 dark:text-ink-300">
                                  {Object.entries(event.metadata_json)
                                    .slice(0, 4)
                                    .map(([key, value]) => `${humaniseField(key)}: ${formatCellValue(value)}`)
                                    .join(' · ')}
                                </p>
                              ) : null}
                            </div>
                          </li>
                        ))}
                      </ol>
                    )}

                    {auditQuery.data ? (
                      <Pagination
                        meta={pageInfo(auditQuery.data)!}
                        onPageChange={setAuditPage}
                        className="mt-3 border-t-0 px-0"
                      />
                    ) : null}
                  </div>
                </RoleGate>
              ),
            },
          ]}
        />
      </div>
    </Card>
  );
}
