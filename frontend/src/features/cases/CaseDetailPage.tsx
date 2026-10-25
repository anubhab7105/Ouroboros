import { useQuery } from '@tanstack/react-query';
import { useParams } from 'react-router-dom';

import { Card } from '@/components/common/Card';
import { ErrorState } from '@/components/common/ErrorState';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { PageHeader } from '@/components/layout/PageHeader';
import { useApiError } from '@/hooks/useApiError';
import { queryKeys } from '@/lib/queryKeys';

import { CaseAssignmentControl } from './CaseAssignmentControl';
import { CaseEvidencePanel } from './CaseEvidencePanel';
import { CaseNotesPanel } from './CaseNotesPanel';
import { CaseReportButton } from './CaseReportButton';
import { CaseStatusTransitionControl } from './CaseStatusTransitionControl';
import { CaseSummaryPanel } from './CaseSummaryPanel';
import { CaseTimeline } from './CaseTimeline';
import { fetchCase } from './casesApi';

/**
 * One investigation.
 *
 * Laid out as one page rather than tabs, unlike the account view. A case is
 * read end to end — what it is, what it rests on, what was concluded, what
 * happened — and splitting that into tabs would hide the evidence from
 * somebody writing the disposition, which is exactly when they should be
 * looking at it.
 *
 * The status and assignment controls sit in the header, where they are
 * reachable without scrolling past the evidence.
 */
export default function CaseDetailPage() {
  const { caseId = '' } = useParams();

  const query = useQuery({
    queryKey: queryKeys.cases.detail(caseId),
    queryFn: () => fetchCase(caseId),
    enabled: Boolean(caseId),
  });

  const error = useApiError(query.error);
  const detail = query.data;
  const investigation = detail?.case;

  return (
    <div>
      <PageHeader
        title={investigation?.title ?? 'Case'}
        description="An investigation, its evidence and its outcome. Notes and history are append-only."
        actions={
          investigation ? (
            <div className="flex flex-wrap items-center gap-2">
              <CaseAssignmentControl investigation={investigation} />
              <CaseReportButton
                caseId={investigation.id}
                caseTitle={investigation.title}
                caseStatus={investigation.status}
              />
            </div>
          ) : null
        }
      >
        {investigation ? <CaseStatusTransitionControl investigation={investigation} /> : null}
      </PageHeader>

      {error ? (
        <ErrorState error={error} onRetry={() => void query.refetch()} className="mb-4" />
      ) : null}

      {query.isLoading ? (
        <Card>
          <LoadingSpinner label="Loading case" />
        </Card>
      ) : !investigation ? null : (
        <div className="space-y-5">
          <CaseSummaryPanel detail={detail} />

          <div className="grid gap-5 xl:grid-cols-3">
            <div className="space-y-5 xl:col-span-2">
              <CaseEvidencePanel caseId={investigation.id} />
              <CaseNotesPanel caseId={investigation.id} />
            </div>

            <div>
              <CaseTimeline caseId={investigation.id} />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
