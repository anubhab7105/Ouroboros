import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';

import { Button } from '@/components/common/Button';
import { Card } from '@/components/common/Card';
import { DatePicker } from '@/components/common/DatePicker';
import { Drawer } from '@/components/common/Drawer';
import { ErrorState } from '@/components/common/ErrorState';
import { FormField } from '@/components/common/FormField';
import { KeyValueList } from '@/components/common/KeyValueList';
import { Pagination } from '@/components/common/Pagination';
import { Select } from '@/components/common/Select';
import { TextInput } from '@/components/common/TextInput';
import { AuditTable } from '@/components/tables/AuditTable';
import { PageHeader } from '@/components/layout/PageHeader';
import { useApiError } from '@/hooks/useApiError';
import { useDebounce } from '@/hooks/useDebounce';
import { usePagination } from '@/hooks/usePagination';
import { useQueryParams } from '@/hooks/useQueryParams';
import { endpoints } from '@/lib/api';
import { formatDateTime } from '@/lib/dates';
import { DownloadButton } from '@/components/common/DownloadButton';
import { formatCellValue, humaniseField } from '@/lib/formatters';
import { queryKeys } from '@/lib/queryKeys';
import { pageInfo } from '@/types/common';
import type { AuditEvent, AuditFilters } from '@/types/audit';

import { fetchAuditEvents } from './systemApi';

const OUTCOMES = ['SUCCESS', 'FAILURE', 'DENIED', 'WARNING'];

/**
 * The audit trail.
 *
 * Append-only on the server: there is no edit and no delete, by design, and so
 * this page offers no mutation of any kind. What it does offer is a filter on
 * outcome, because the question an auditor usually arrives with is "show me
 * what was refused", and an export, because audit review happens outside this
 * application as often as inside it.
 */
export default function AuditPage() {
  const { params, setParams, clearParams, activeFilterCount } = useQueryParams<
    AuditFilters & Record<string, string>
  >();
  const { page, pageSize, setPage, setPageSize } = usePagination();
  const [selected, setSelected] = useState<AuditEvent | null>(null);

  const searchTerm = useDebounce(params.q ?? '', 350);

  const filters: AuditFilters = {
    actor_username: params.actor_username,
    action: params.action,
    outcome: params.outcome,
    resource_type: params.resource_type,
    resource_id: params.resource_id,
    date_from: params.date_from,
    date_to: params.date_to,
    q: searchTerm || undefined,
  };

  const query = useQuery({
    queryKey: queryKeys.audit.list(page, pageSize, filters),
    queryFn: () =>
      fetchAuditEvents({
        page,
        page_size: pageSize,
        sort_by: params.sort_by ?? 'created_at',
        sort_order: (params.sort_order as 'asc' | 'desc') ?? 'desc',
        filters,
      }),
  });

  const error = useApiError(query.error);

  return (
    <div>
      <PageHeader
        title="Audit trail"
        description="Every recorded action, including those that were refused. The trail is append-only: entries cannot be edited or deleted from this interface or any other."
        actions={
          <DownloadButton
            url={endpoints.audit.export()}
            filename="muleguard-audit-export.csv"
            params={{ ...filters, format: 'csv' }}
            label="Export filtered"
            size="sm"
          />
        }
      >
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <FormField label="Search">
            {({ id }) => (
              <TextInput
                id={id}
                value={params.q ?? ''}
                onChange={(event) => setParams({ q: event.target.value })}
                placeholder="Action, actor or resource"
              />
            )}
          </FormField>

          <FormField label="Outcome">
            {({ id }) => (
              <Select
                id={id}
                value={params.outcome ?? ''}
                onChange={(event) => setParams({ outcome: event.target.value })}
                placeholder="Any outcome"
                options={OUTCOMES.map((outcome) => ({
                  value: outcome,
                  label: humaniseField(outcome),
                }))}
              />
            )}
          </FormField>

          <FormField label="From">
            {({ id }) => (
              <DatePicker
                id={id}
                noFuture
                value={params.date_from?.slice(0, 10) ?? ''}
                onValueChange={(value) => setParams({ date_from: value || undefined })}
              />
            )}
          </FormField>

          <FormField label="To">
            {({ id }) => (
              <DatePicker
                id={id}
                noFuture
                value={params.date_to?.slice(0, 10) ?? ''}
                onValueChange={(value) => setParams({ date_to: value || undefined })}
              />
            )}
          </FormField>
        </div>

        {activeFilterCount > 0 ? (
          <div className="mt-2">
            <Button size="sm" variant="ghost" onClick={() => clearParams()}>
              Clear {activeFilterCount} filter{activeFilterCount === 1 ? '' : 's'}
            </Button>
          </div>
        ) : null}
      </PageHeader>

      {error ? (
        <ErrorState error={error} onRetry={() => void query.refetch()} className="mb-4" />
      ) : null}

      <Card flush>
        <AuditTable
          rows={query.data?.items ?? []}
          isLoading={query.isLoading}
          isRefetching={query.isRefetching}
          sortBy={params.sort_by ?? 'created_at'}
          sortOrder={(params.sort_order as 'asc' | 'desc') ?? 'desc'}
          onSortChange={(key, order) => setParams({ sort_by: key, sort_order: order })}
          onRowClick={setSelected}
          selectedId={selected?.id ?? null}
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

      <Drawer
        open={Boolean(selected)}
        onClose={() => setSelected(null)}
        title="Audit event"
        width="md"
      >
        {selected ? (
          <div className="space-y-4">
            <KeyValueList
              columns={1}
              entries={[
                { label: 'When', value: formatDateTime(selected.created_at) },
                { label: 'Action', value: selected.action, mono: true },
                { label: 'Outcome', value: humaniseField(selected.outcome) },
                {
                  label: 'Actor',
                  value: selected.actor_username ?? selected.actor_id ?? 'System',
                },
                { label: 'Actor role', value: selected.actor_role ?? '—' },
                {
                  label: 'Resource',
                  value: selected.resource_type
                    ? `${humaniseField(selected.resource_type)} ${selected.resource_id ?? ''}`.trim()
                    : '—',
                },
                { label: 'Request id', value: selected.request_id ?? '—', mono: true },
                {
                  label: 'Correlation id',
                  value: selected.correlation_id ?? '—',
                  mono: true,
                  help: 'Groups the events produced by one logical operation, such as a single analysis run.',
                },
                {
                  label: 'Client fingerprint',
                  value: selected.ip_hash ?? '—',
                  mono: true,
                  help: 'A hash, not an address. It distinguishes sessions without recording where someone was.',
                },
              ]}
            />

            {Object.keys(selected.metadata_json ?? {}).length > 0 ? (
              <div>
                <h3 className="mb-1.5 text-2xs font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
                  Recorded detail
                </h3>
                <dl className="space-y-1">
                  {Object.entries(selected.metadata_json ?? {}).map(([key, value]) => (
                    <div key={key} className="flex gap-2 text-2xs">
                      <dt className="shrink-0 font-medium text-ink-600 dark:text-ink-300">
                        {humaniseField(key)}
                      </dt>
                      <dd className="min-w-0 break-words font-mono text-ink-800 dark:text-ink-100">
                        {formatCellValue(value)}
                      </dd>
                    </div>
                  ))}
                </dl>
              </div>
            ) : null}
          </div>
        ) : null}
      </Drawer>
    </div>
  );
}
