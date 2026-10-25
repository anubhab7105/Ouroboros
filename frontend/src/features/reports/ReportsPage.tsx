import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';

import { Badge } from '@/components/common/Badge';
import { Button } from '@/components/common/Button';
import { Card } from '@/components/common/Card';
import { EmptyState } from '@/components/common/EmptyState';
import { ErrorState } from '@/components/common/ErrorState';
import { KeyValueList } from '@/components/common/KeyValueList';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { Select } from '@/components/common/Select';
import { CasesTable } from '@/components/tables/CasesTable';
import { PageHeader } from '@/components/layout/PageHeader';
import { useApiError } from '@/hooks/useApiError';
import { useQueryParams } from '@/hooks/useQueryParams';
import { formatCount } from '@/lib/amounts';
import { formatDateTime, formatDuration } from '@/lib/dates';
import { queryKeys } from '@/lib/queryKeys';

import { fetchCases } from '@/features/cases/casesApi';

import { ReportDownloadCard } from './ReportDownloadCard';
import { fetchReportLimitations, fetchReportPreview, fetchReportStatus } from './reportsApi';

/**
 * Reports.
 *
 * A report is always *of a case* — there is no standalone report object — so
 * this page is a case picker followed by a preview of what the document would
 * contain. The preview is the honest part: it shows the sections as data,
 * which sections hit the per-section cap, and the evidence index, before
 * anyone commits a PDF to an email.
 *
 * Closed cases are offered first, because a report of an open case states a
 * position nobody has finished forming.
 */
export default function ReportsPage() {
  const { params, setParams } = useQueryParams();
  const selectedCaseId = params.case_id ?? null;
  const [statusFilter, setStatusFilter] = useState('CLOSED');

  const statusQuery = useQuery({
    queryKey: queryKeys.reports.status(),
    queryFn: fetchReportStatus,
    staleTime: 5 * 60_000,
  });

  const limitationsQuery = useQuery({
    queryKey: queryKeys.reports.limitations(),
    queryFn: fetchReportLimitations,
    staleTime: 10 * 60_000,
  });

  const casesQuery = useQuery({
    queryKey: queryKeys.cases.list(1, 25, { status: statusFilter }),
    queryFn: () =>
      fetchCases({
        page: 1,
        page_size: 25,
        sort_by: 'updated_at',
        sort_order: 'desc',
        filters: statusFilter ? { status: statusFilter } : {},
      }),
  });

  const previewQuery = useQuery({
    queryKey: queryKeys.reports.preview(selectedCaseId ?? ''),
    queryFn: () => fetchReportPreview(selectedCaseId!),
    enabled: Boolean(selectedCaseId),
  });

  const previewError = useApiError(previewQuery.error);
  const preview = previewQuery.data;
  const status = statusQuery.data;

  return (
    <div className="space-y-5">
      <PageHeader
        title="Reports"
        description="Case report packs for referral. Each is generated from one case and carries that case's evidence index and this platform's stated limitations."
        actions={
          <Select
            aria-label="Filter cases by status"
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value)}
            className="w-44"
            options={[
              { value: 'CLOSED', label: 'Closed cases' },
              { value: 'ESCALATED', label: 'Escalated cases' },
              { value: 'UNDER_INVESTIGATION', label: 'Under investigation' },
              { value: '', label: 'All cases' },
            ]}
          />
        }
      />

      {status && !status.renderer_available ? (
        <p
          role="status"
          className="rounded-card border border-ink-200 bg-amber-50 p-3 text-xs leading-relaxed text-amber-900 dark:border-ink-700 dark:bg-amber-950/40 dark:text-amber-200"
        >
          The PDF renderer ({status.renderer}) is not available in this deployment, so reports
          cannot be produced here. Previews still show exactly what a document would contain.
        </p>
      ) : null}

      <div className="grid gap-5 xl:grid-cols-3">
        <Card
          title="Choose a case"
          description="A report is always of one case."
          className="xl:col-span-2"
          caveats={casesQuery.data?.caveats}
          flush
        >
          <CasesTable
            rows={casesQuery.data?.items ?? []}
            isLoading={casesQuery.isLoading}
            emptyMessage="No case matches that status."
          />
        </Card>

        <div className="space-y-5">
          {selectedCaseId ? (
            <ReportDownloadCard
              caseId={selectedCaseId}
              caseTitle={preview?.case_title}
            />
          ) : (
            <Card title="Report">
              <EmptyState
                title="Pick a case to preview its report"
                message="Open a case from the list and use its Report control, or paste a case id into the address bar as ?case_id=…"
                compact
              />
            </Card>
          )}

          {limitationsQuery.data?.disclaimer ? (
            <Card title="What every report says">
              <p className="whitespace-pre-line text-2xs leading-relaxed text-ink-700 dark:text-ink-200">
                {limitationsQuery.data.disclaimer}
              </p>
              {limitationsQuery.data.limitations ? (
                <p className="mt-2 whitespace-pre-line text-2xs leading-relaxed text-ink-600 dark:text-ink-300">
                  {limitationsQuery.data.limitations}
                </p>
              ) : null}
            </Card>
          ) : null}
        </div>
      </div>

      {selectedCaseId ? (
        <Card
          title="Preview"
          description="The document's content as data, before it is rendered. Previewing is recorded in the audit trail in most configurations, because it contains the same material as the PDF."
          caveats={preview?.caveats}
          actions={
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setParams({ case_id: undefined })}
            >
              Clear selection
            </Button>
          }
        >
          {previewError ? (
            <ErrorState error={previewError} onRetry={() => void previewQuery.refetch()} />
          ) : previewQuery.isLoading ? (
            <LoadingSpinner label="Loading preview" />
          ) : !preview ? null : (
            <div className="space-y-4">
              <KeyValueList
                columns={3}
                entries={[
                  { label: 'Case', value: preview.case_title, wide: true },
                  { label: 'Generated', value: formatDateTime(preview.generated_at) },
                  { label: 'By', value: preview.generated_by },
                  { label: 'Timezone', value: preview.timezone_label },
                  {
                    label: 'Estimated pages',
                    value: `${formatCount(preview.estimated_pages)} of ${formatCount(preview.page_limit)} allowed`,
                  },
                  {
                    label: 'Evidence items',
                    value: `${formatCount(preview.evidence_index.length)} of ${formatCount(preview.evidence_total)}`,
                    help: preview.evidence_truncated
                      ? 'The index is truncated, so the document will not list everything attached to the case.'
                      : undefined,
                  },
                  { label: 'Took', value: formatDuration(preview.generation_seconds) },
                ]}
              />

              {preview.section_summaries.length > 0 ? (
                <div className="border-t border-ink-200 pt-3 dark:border-ink-700">
                  <h3 className="mb-2 text-2xs font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
                    Sections
                  </h3>
                  <ul className="space-y-1.5">
                    {preview.section_summaries.map((section) => (
                      <li key={section.key} className="flex flex-wrap items-center gap-2 text-2xs">
                        <span className="font-medium text-ink-800 dark:text-ink-100">
                          {section.title}
                        </span>
                        <span className="tabular text-ink-600 dark:text-ink-300">
                          {formatCount(section.item_count)} items
                        </span>
                        {section.truncated ? (
                          <Badge
                            tone="warning"
                            title={
                              section.note ??
                              `Cut at the per-section cap of ${formatCount(status?.max_items_per_section ?? 0)} items.`
                            }
                          >
                            Truncated
                          </Badge>
                        ) : null}
                        {section.evidence_refs.length > 0 ? (
                          <span className="text-ink-500 dark:text-ink-400">
                            {formatCount(section.evidence_refs.length)} evidence refs
                          </span>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}

              {preview.sections.length > 0 ? (
                <div className="border-t border-ink-200 pt-3 dark:border-ink-700">
                  <h3 className="mb-2 text-2xs font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
                    Content
                  </h3>
                  <dl className="space-y-1">
                    {preview.sections.map((row, index) => (
                      <div key={`${row.label}-${index}`} className="flex gap-2 text-2xs">
                        <dt className="w-52 shrink-0 font-medium text-ink-600 dark:text-ink-300">
                          {row.label}
                        </dt>
                        <dd className="min-w-0 break-words text-ink-800 dark:text-ink-100">
                          {row.value}
                          {row.evidence_refs.length > 0 ? (
                            <span className="ml-1 font-mono text-ink-500 dark:text-ink-400">
                              [{row.evidence_refs.join(', ')}]
                            </span>
                          ) : null}
                        </dd>
                      </div>
                    ))}
                  </dl>
                </div>
              ) : null}

              {preview.evidence_index.length > 0 ? (
                <div className="border-t border-ink-200 pt-3 dark:border-ink-700">
                  <h3 className="mb-2 text-2xs font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
                    Evidence index
                  </h3>
                  <ol className="space-y-0.5">
                    {preview.evidence_index.map((row, index) => (
                      <li key={`${row.label}-${index}`} className="text-2xs">
                        <span className="font-mono text-ink-700 dark:text-ink-200">
                          {row.label}
                        </span>
                        <span className="text-ink-600 dark:text-ink-300"> — {row.value}</span>
                      </li>
                    ))}
                  </ol>
                  <p className="mt-2 text-2xs text-ink-500 dark:text-ink-400">
                    Without this index, a reader cannot check a claim in the report against the
                    record it rests on.
                  </p>
                </div>
              ) : null}

              {preview.footer ? (
                <p className="border-t border-ink-200 pt-2 text-2xs text-ink-500 dark:border-ink-700 dark:text-ink-400">
                  {preview.footer}
                </p>
              ) : null}
            </div>
          )}
        </Card>
      ) : null}
    </div>
  );
}
