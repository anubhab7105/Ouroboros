import { useState } from 'react';

import { Button } from '@/components/common/Button';
import { Modal } from '@/components/common/Modal';
import { ReportDownloadCard } from '@/features/reports/ReportDownloadCard';

export interface CaseReportButtonProps {
  caseId: string;
  caseTitle?: string;
  /** Warn before reporting on a case that is still open. */
  caseStatus?: string;
}

/**
 * Open the report controls for one case.
 *
 * The warning on an open case is deliberate. A report is a document that
 * leaves this platform, and one generated mid-investigation states a position
 * nobody has finished forming. It is not blocked — there are legitimate
 * reasons to produce an interim pack — but it is named.
 */
export function CaseReportButton({ caseId, caseTitle, caseStatus }: CaseReportButtonProps) {
  const [open, setOpen] = useState(false);
  const isOpenCase = caseStatus !== 'CLOSED';

  return (
    <>
      <Button size="sm" variant="secondary" onClick={() => setOpen(true)}>
        Report
      </Button>

      <Modal open={open} onClose={() => setOpen(false)} title="Case report" size="lg">
        {isOpenCase ? (
          <p
            role="note"
            className="mb-3 rounded-md border border-ink-200 bg-ink-50 p-3 text-2xs leading-relaxed text-ink-700 dark:border-ink-700 dark:bg-ink-800/60 dark:text-ink-200"
          >
            This case is not closed. A report generated now records the position as it stands
            today, with no disposition — which is legitimate for an interim pack, but anyone
            reading it will take it as the conclusion unless you say otherwise.
          </p>
        ) : null}

        <ReportDownloadCard caseId={caseId} caseTitle={caseTitle} />
      </Modal>
    </>
  );
}
