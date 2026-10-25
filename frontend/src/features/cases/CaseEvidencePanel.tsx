import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';

import { Button } from '@/components/common/Button';
import { Card } from '@/components/common/Card';
import { ConfirmDialog } from '@/components/common/ConfirmDialog';
import { ErrorState } from '@/components/common/ErrorState';
import { Modal } from '@/components/common/Modal';
import { Pagination } from '@/components/common/Pagination';
import { Select } from '@/components/common/Select';
import { EvidenceTable } from '@/components/tables/EvidenceTable';
import { RoleGate } from '@/components/layout/RoleGate';
import { useApiError } from '@/hooks/useApiError';
import { useConfirm } from '@/hooks/useConfirm';
import { formatCellValue, humaniseField } from '@/lib/formatters';
import { PERMISSIONS } from '@/lib/permissions';
import { queryKeys } from '@/lib/queryKeys';
import type { CaseEvidence } from '@/types/case';
import { pageInfo } from '@/types/common';
import { EVIDENCE_TYPE_LABELS } from '@/types/evidence';

import { AddEvidenceModal } from './AddEvidenceModal';
import { fetchCaseEvidence, removeCaseEvidence } from './casesApi';

export interface CaseEvidencePanelProps {
  caseId: string;
}

const TYPE_OPTIONS = Object.entries(EVIDENCE_TYPE_LABELS).map(([value, label]) => ({
  value,
  label,
}));

/**
 * The case's evidence, with add and remove.
 *
 * "Show removed" defaults to on. Removed evidence is retained precisely so
 * that a report generated earlier remains reconstructible, and hiding it by
 * default would mean the panel shows a different set of items from the report
 * somebody is holding.
 *
 * Removal asks for confirmation that says what removal does — soft, retained,
 * audited — rather than a generic "are you sure".
 */
export function CaseEvidencePanel({ caseId }: CaseEvidencePanelProps) {
  const queryClient = useQueryClient();
  const confirm = useConfirm();

  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [typeFilter, setTypeFilter] = useState('');
  const [includeInactive, setIncludeInactive] = useState(true);
  const [adding, setAdding] = useState(false);
  const [inspecting, setInspecting] = useState<CaseEvidence | null>(null);

  const query = useQuery({
    queryKey: queryKeys.cases.evidence(caseId, page, typeFilter, includeInactive),
    queryFn: () =>
      fetchCaseEvidence(caseId, {
        page,
        page_size: pageSize,
        evidence_type: typeFilter || undefined,
        include_inactive: includeInactive,
      }),
  });

  const removal = useMutation({
    mutationFn: (evidenceId: string) => removeCaseEvidence(caseId, evidenceId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.cases.all });
    },
  });

  const error = useApiError(query.error ?? removal.error);

  const handleRemove = async (item: CaseEvidence) => {
    const confirmed = await confirm.confirm({
      title: 'Remove this evidence reference?',
      message:
        'The reference is kept and marked removed rather than deleted, so any report already generated from this case stays reconstructible. The removal is recorded in the audit trail against your name.',
      confirmLabel: 'Remove reference',
      destructive: true,
    });

    if (confirmed) removal.mutate(item.id);
  };

  return (
    <Card
      title="Evidence"
      description="What the conclusion rests on. Each item carries a snapshot of the record as it was when attached."
      actions={
        <div className="flex items-center gap-2">
          <Select
            aria-label="Filter evidence by kind"
            value={typeFilter}
            onChange={(event) => {
              setTypeFilter(event.target.value);
              setPage(1);
            }}
            placeholder="Any kind"
            options={TYPE_OPTIONS}
            className="w-40 py-1 text-xs"
          />

          <label className="flex items-center gap-1.5 text-2xs text-ink-600 dark:text-ink-300">
            <input
              type="checkbox"
              checked={includeInactive}
              onChange={(event) => {
                setIncludeInactive(event.target.checked);
                setPage(1);
              }}
              className="h-3.5 w-3.5"
            />
            Show removed
          </label>

          <RoleGate permissions={[PERMISSIONS.addCaseEvidence]} silent>
            <Button size="sm" variant="secondary" onClick={() => setAdding(true)}>
              Attach
            </Button>
          </RoleGate>
        </div>
      }
      caveats={query.data?.caveats}
      flush
    >
      {error ? (
        <div className="p-4">
          <ErrorState error={error} onRetry={() => void query.refetch()} compact />
        </div>
      ) : null}

      <EvidenceTable
        rows={query.data?.items ?? []}
        isLoading={query.isLoading}
        onRemove={(item) => void handleRemove(item)}
        onInspect={setInspecting}
      />

      {query.data ? (
        <Pagination
          meta={pageInfo(query.data)!}
          onPageChange={setPage}
          onPageSizeChange={setPageSize}
          requestedPageSize={pageSize}
        />
      ) : null}

      <AddEvidenceModal open={adding} onClose={() => setAdding(false)} caseId={caseId} />

      <ConfirmDialog
        open={confirm.isOpen}
        options={confirm.pending}
        onConfirm={confirm.onConfirm}
        onCancel={confirm.onCancel}
        isBusy={removal.isPending}
      />

      <Modal
        open={Boolean(inspecting)}
        onClose={() => setInspecting(null)}
        title="Evidence snapshot"
        size="lg"
      >
        {inspecting ? (
          <div className="space-y-3">
            <p className="text-2xs leading-relaxed text-ink-600 dark:text-ink-300">
              The record as it stood when this item was attached. If the live record has changed
              since, this is what the case and any report built from it actually relied on.
            </p>

            <dl className="space-y-1">
              {Object.entries(inspecting.evidence_snapshot_json ?? {}).map(([key, value]) => (
                <div key={key} className="flex gap-2 text-2xs">
                  <dt className="w-44 shrink-0 font-medium text-ink-600 dark:text-ink-300">
                    {humaniseField(key)}
                  </dt>
                  <dd className="min-w-0 break-words font-mono text-ink-800 dark:text-ink-100">
                    {formatCellValue(value)}
                  </dd>
                </div>
              ))}
            </dl>

            {inspecting.provenance_json ? (
              <div className="border-t border-ink-200 pt-2 dark:border-ink-700">
                <h3 className="mb-1 text-2xs font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
                  Provenance
                </h3>
                <dl className="space-y-1">
                  {Object.entries(inspecting.provenance_json).map(([key, value]) => (
                    <div key={key} className="flex gap-2 text-2xs">
                      <dt className="w-44 shrink-0 font-medium text-ink-600 dark:text-ink-300">
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
      </Modal>
    </Card>
  );
}
