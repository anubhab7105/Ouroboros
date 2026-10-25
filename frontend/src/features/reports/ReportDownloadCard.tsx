import { useMutation, useQuery } from '@tanstack/react-query';
import { useState } from 'react';

import { Badge } from '@/components/common/Badge';
import { Button } from '@/components/common/Button';
import { Card } from '@/components/common/Card';
import { CopyButton } from '@/components/common/CopyButton';
import { DownloadButton } from '@/components/common/DownloadButton';
import { ErrorState } from '@/components/common/ErrorState';
import { KeyValueList } from '@/components/common/KeyValueList';
import { RoleGate } from '@/components/layout/RoleGate';
import { useApiError } from '@/hooks/useApiError';
import { endpoints } from '@/lib/api';
import { formatCount } from '@/lib/amounts';
import { formatDateTime, formatDuration } from '@/lib/dates';
import { PERMISSIONS } from '@/lib/permissions';
import { queryKeys } from '@/lib/queryKeys';
import type { ReportGenerateResult } from '@/types/model';

import { fetchReportStatus, generateReport } from './reportsApi';

export interface ReportDownloadCardProps {
  caseId: string;
  caseTitle?: string;
}

/** Bytes to a readable size. */
function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/**
 * Generate and download a case report.
 *
 * Generation and download are separate steps because the server separates
 * them, and the separation is useful: generating reports what was actually
 * rendered — how many pages, which sections were truncated at the per-section
 * cap, and a SHA-256 of the file — before anyone sends the document on.
 *
 * The digest is shown with a copy control. A report emailed to another team
 * can then be shown to be the same file that was generated here, which is a
 * question that arises precisely when it matters most.
 *
 * `renderer_available` false means ReportLab is not installed in this
 * deployment: previews work and downloads do not. Saying so before the button
 * is pressed is better than a 503 after a case has been written up.
 */
export function ReportDownloadCard({ caseId, caseTitle }: ReportDownloadCardProps) {
  const [result, setResult] = useState<ReportGenerateResult | null>(null);

  const statusQuery = useQuery({
    queryKey: queryKeys.reports.status(),
    queryFn: fetchReportStatus,
    staleTime: 5 * 60_000,
  });

  const mutation = useMutation({
    mutationFn: () => generateReport(caseId),
    onSuccess: setResult,
  });

  const error = useApiError(mutation.error);
  const status = statusQuery.data;

  const unavailable = status && !status.renderer_available;

  return (
    <Card
      title="Case report"
      description="A PDF pack for referral: the case, its evidence index, and the platform's stated limitations."
      caveats={status?.caveats}
    >
      {unavailable ? (
        <p
          role="status"
          className="mb-3 rounded-md border border-ink-200 bg-amber-50 p-3 text-2xs leading-relaxed text-amber-900 dark:border-ink-700 dark:bg-amber-950/40 dark:text-amber-200"
        >
          This deployment reports its PDF renderer ({status?.renderer}) as unavailable, so a
          report cannot be produced here. The preview below still shows exactly what the document
          would contain.
        </p>
      ) : null}

      {status ? (
        <KeyValueList
          columns={3}
          className="mb-4"
          entries={[
            {
              label: 'Per-section cap',
              value: formatCount(status.max_items_per_section),
              help: 'Sections longer than this are truncated, and the report says which were cut.',
            },
            { label: 'Page limit', value: formatCount(status.max_pages) },
            {
              label: 'Timeout',
              value: `${status.max_generation_seconds}s`,
              help: 'Generation is abandoned past this, rather than holding the request open.',
            },
            {
              label: 'Disclaimer included',
              value: status.include_disclaimer ? 'Yes' : 'No',
              help: status.include_disclaimer
                ? undefined
                : 'Switched off, so the document travels without its own caveats.',
            },
            {
              label: 'Limitations included',
              value: status.include_limitations ? 'Yes' : 'No',
            },
            {
              label: 'Evidence index included',
              value: status.include_evidence_index ? 'Yes' : 'No',
              help: 'Without it, a reader cannot check a claim against the record it rests on.',
            },
          ]}
        />
      ) : null}

      {error ? <ErrorState error={error} compact className="mb-3" /> : null}

      <div className="flex flex-wrap items-center gap-2">
        <RoleGate permissions={[PERMISSIONS.generateReport]} silent>
          <Button
            variant="primary"
            size="sm"
            isLoading={mutation.isPending}
            disabled={unavailable}
            onClick={() => mutation.mutate()}
          >
            Generate report
          </Button>
        </RoleGate>

        <RoleGate permissions={[PERMISSIONS.downloadReport]} silent>
          <DownloadButton
            url={endpoints.reports.caseDownload(caseId)}
            filename={`${status?.filename_prefix ?? 'muleguard'}-case-${caseId}.pdf`}
            label="Download PDF"
            size="sm"
            disabled={unavailable}
          />
        </RoleGate>
      </div>

      {result ? (
        <div className="mt-4 border-t border-ink-200 pt-3 dark:border-ink-700">
          <h3 className="mb-2 text-2xs font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
            Rendered
          </h3>

          <KeyValueList
            columns={2}
            entries={[
              { label: 'Filename', value: result.filename, mono: true, wide: true },
              { label: 'Size', value: formatBytes(result.size_bytes) },
              { label: 'Pages', value: formatCount(result.estimated_pages) },
              { label: 'Generated', value: formatDateTime(result.generated_at) },
              { label: 'By', value: result.generated_by },
              { label: 'Took', value: formatDuration(result.generation_seconds) },
              {
                label: 'SHA-256',
                value: (
                  <span className="flex items-center gap-1">
                    <span className="break-all font-mono text-2xs">{result.sha256}</span>
                    <CopyButton value={result.sha256} label="Copy report digest" />
                  </span>
                ),
                wide: true,
                help: 'Quote this alongside the document so the copy somebody holds can be shown to be the one generated here.',
              },
            ]}
          />

          {result.evidence_truncated ? (
            <p className="mt-2 text-2xs text-ink-700 dark:text-ink-200">
              The evidence index was truncated at {formatCount(result.evidence_total)} items, so the
              document does not list everything attached to this case.
            </p>
          ) : null}

          {result.sections.some((section) => section.truncated) ? (
            <div className="mt-2">
              <p className="text-2xs text-ink-700 dark:text-ink-200">Sections cut at the cap:</p>
              <ul className="mt-1 flex flex-wrap gap-1.5">
                {result.sections
                  .filter((section) => section.truncated)
                  .map((section) => (
                    <li key={section.key}>
                      <Badge tone="warning" title={section.note ?? undefined}>
                        {section.title} ({formatCount(section.item_count)})
                      </Badge>
                    </li>
                  ))}
              </ul>
            </div>
          ) : null}

          {result.caveats.length > 0 ? (
            <ul className="mt-2 space-y-1">
              {result.caveats.map((caveat) => (
                <li key={caveat} className="text-2xs text-ink-600 dark:text-ink-300">
                  — {caveat}
                </li>
              ))}
            </ul>
          ) : null}

          {caseTitle ? (
            <p className="mt-2 text-2xs text-ink-500 dark:text-ink-400">
              Report for “{caseTitle}”.
            </p>
          ) : null}
        </div>
      ) : null}
    </Card>
  );
}
