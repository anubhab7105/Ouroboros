import { cleanParams, endpoints, pageParams } from '@/lib/api';
import { get, post } from '@/lib/apiClient';
import type { AlertListResponse } from '@/types/alert';
import type { PageQuery } from '@/types/common';
import type {
  Complaint,
  ComplaintCorrelationListResponse,
  ComplaintExportBundle,
  ComplaintFilters,
  ComplaintHistoryListResponse,
  ComplaintLinkedAccountListResponse,
  ComplaintLinkedEntityListResponse,
  ComplaintLinkedTransactionListResponse,
  ComplaintListResponse,
  ComplaintReviewUpdateRequest,
  ComplaintReviewUpdateResult,
  ComplaintStats,
  CorrelationFilters,
} from '@/types/complaint';

/**
 * Complaint reads and correlation review.
 *
 * The raw narrative is not available through any of these: the complaint
 * response carries `narrative_available` and nothing more. Reading the text
 * requires the `read_complaint_narrative` capability and a different surface,
 * which is the right design — it is a victim's own account of what happened to
 * them, not reference data.
 */

export async function fetchComplaints(
  page: PageQuery & { filters: ComplaintFilters },
): Promise<ComplaintListResponse> {
  const { filters, ...rest } = page;

  return get<ComplaintListResponse>(endpoints.complaints.list(), {
    params: {
      ...pageParams(rest),
      ...cleanParams({ include_correlation_count: true, ...filters }),
    },
  });
}

export async function fetchComplaint(id: string): Promise<Complaint> {
  return get<Complaint>(endpoints.complaints.detail(id));
}

export async function fetchComplaintStats(
  options: { date_from?: string; date_to?: string; category?: string; top_limit?: number } = {},
): Promise<ComplaintStats> {
  return get<ComplaintStats>(endpoints.complaints.stats(), { params: cleanParams(options) });
}

export async function fetchComplaintCorrelations(
  id: string,
  page: PageQuery & CorrelationFilters = {},
): Promise<ComplaintCorrelationListResponse> {
  const { page: pageNumber, page_size, sort_by, sort_order, ...filters } = page;

  return get<ComplaintCorrelationListResponse>(endpoints.complaints.correlations(id), {
    params: {
      ...pageParams({ page: pageNumber, page_size, sort_by, sort_order }),
      ...cleanParams(filters),
    },
  });
}

/**
 * Record a reviewer's decision on one correlation.
 *
 * Senior investigators and administrators only, enforced server-side. The
 * decision is what turns an inferred correlation from a lead into something a
 * report may rely on, so it is audited and the response reports whether the
 * state actually changed.
 */
export async function reviewCorrelation(
  complaintId: string,
  correlationId: string,
  body: ComplaintReviewUpdateRequest,
): Promise<ComplaintReviewUpdateResult> {
  return post<ComplaintReviewUpdateResult>(
    endpoints.complaints.reviewCorrelation(complaintId, correlationId),
    body,
  );
}

export async function fetchComplaintAccounts(
  id: string,
  page: PageQuery & CorrelationFilters = {},
): Promise<ComplaintLinkedAccountListResponse> {
  const { page: pageNumber, page_size, ...filters } = page;

  return get<ComplaintLinkedAccountListResponse>(endpoints.complaints.accounts(id), {
    params: { ...pageParams({ page: pageNumber, page_size }), ...cleanParams(filters) },
  });
}

export async function fetchComplaintTransactions(
  id: string,
  page: PageQuery & CorrelationFilters = {},
): Promise<ComplaintLinkedTransactionListResponse> {
  const { page: pageNumber, page_size, ...filters } = page;

  return get<ComplaintLinkedTransactionListResponse>(endpoints.complaints.transactions(id), {
    params: { ...pageParams({ page: pageNumber, page_size }), ...cleanParams(filters) },
  });
}

export async function fetchComplaintEntities(
  id: string,
  page: PageQuery & CorrelationFilters = {},
): Promise<ComplaintLinkedEntityListResponse> {
  const { page: pageNumber, page_size, ...filters } = page;

  return get<ComplaintLinkedEntityListResponse>(endpoints.complaints.entities(id), {
    params: { ...pageParams({ page: pageNumber, page_size }), ...cleanParams(filters) },
  });
}

export async function fetchComplaintAlerts(
  id: string,
  page: PageQuery & { state?: string; priority?: string } = {},
): Promise<AlertListResponse> {
  const { state, priority, ...rest } = page;

  return get<AlertListResponse>(endpoints.complaints.alerts(id), {
    params: { ...pageParams(rest), ...cleanParams({ state, priority }) },
  });
}

export async function fetchComplaintHistory(
  id: string,
  page: PageQuery & { action?: string; outcome?: string } = {},
): Promise<ComplaintHistoryListResponse> {
  const { action, outcome, ...rest } = page;

  return get<ComplaintHistoryListResponse>(endpoints.complaints.history(id), {
    params: { ...pageParams(rest), ...cleanParams({ action, outcome }) },
  });
}

export async function exportComplaint(id: string): Promise<ComplaintExportBundle> {
  return get<ComplaintExportBundle>(endpoints.complaints.export(id));
}
