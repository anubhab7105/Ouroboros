import { cleanParams, endpoints, pageParams } from '@/lib/api';
import { get, post } from '@/lib/apiClient';
import type { PageQuery } from '@/types/common';
import type {
  ReportEvidenceIndex,
  ReportGenerateResult,
  ReportLimitations,
  ReportPreview,
  ReportStatus,
} from '@/types/model';

/**
 * Report reads and generation.
 *
 * Note the three-step shape, which is the server's and not an invention here:
 * `preview` returns the report's content as data, `generate` renders the PDF
 * and returns its metadata (including a SHA-256 of the file), and the download
 * endpoint streams the bytes. Previewing is audited in most configurations,
 * because the preview contains the same material as the document.
 */

export async function fetchReportStatus(): Promise<ReportStatus> {
  return get<ReportStatus>(endpoints.reports.status());
}

export async function fetchReportLimitations(): Promise<ReportLimitations> {
  return get<ReportLimitations>(endpoints.reports.limitations());
}

export async function fetchReportPreview(caseId: string): Promise<ReportPreview> {
  return get<ReportPreview>(endpoints.reports.casePreview(caseId));
}

export async function fetchReportEvidenceIndex(
  caseId: string,
  page: PageQuery & { evidence_type?: string; include_inactive?: boolean } = {},
): Promise<ReportEvidenceIndex> {
  const { evidence_type, include_inactive, ...rest } = page;

  return get<ReportEvidenceIndex>(endpoints.reports.caseEvidenceIndex(caseId), {
    params: { ...pageParams(rest), ...cleanParams({ evidence_type, include_inactive }) },
  });
}

/**
 * Render the PDF.
 *
 * This does not return the file. It returns what was rendered — page count,
 * byte size, digest, which sections were truncated — so the UI can report the
 * outcome before the user downloads, and so the digest can be quoted
 * alongside a document that has been passed on.
 */
export async function generateReport(caseId: string): Promise<ReportGenerateResult> {
  return post<ReportGenerateResult>(endpoints.reports.caseGenerate(caseId));
}
