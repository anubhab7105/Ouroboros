import { cleanParams, endpoints, pageParams } from '@/lib/api';
import { get, post } from '@/lib/apiClient';
import type {
  Alert,
  AlertActionResult,
  AlertAssignRequest,
  AlertAssignResult,
  AlertCloseRequest,
  AlertCreateCaseRequest,
  AlertCreateCaseResult,
  AlertDetail,
  AlertEvidenceCreateRequest,
  AlertEvidenceActionResult,
  AlertFilters,
  AlertHistoryListResponse,
  AlertListResponse,
} from '@/types/alert';
import type { PageQuery, PageResponse } from '@/types/common';
import type { AlertEvidence } from '@/types/alert';

/**
 * Alert reads and triage actions.
 *
 * `states` and `priorities` are repeated query parameters, not comma-joined
 * strings — the endpoint declares them as lists. axios serialises an array to
 * repeated keys, which is what the server parses.
 *
 * Each action returns `changed`, false when it was a no-op. Acknowledging an
 * already-acknowledged alert is not a failure and not a success; the UI says
 * so rather than claiming something happened.
 */

export async function fetchAlerts(
  page: PageQuery & { filters: AlertFilters },
): Promise<AlertListResponse> {
  const { filters, ...rest } = page;

  return get<AlertListResponse>(endpoints.alerts.list(), {
    params: { ...pageParams(rest), ...cleanParams({ include_account: true, ...filters }) },
  });
}

export async function fetchAlert(id: string): Promise<AlertDetail> {
  return get<AlertDetail>(endpoints.alerts.detail(id));
}

export async function fetchAlertEvidence(
  id: string,
  page: PageQuery & { evidence_type?: string } = {},
): Promise<PageResponse<AlertEvidence>> {
  const { evidence_type, ...rest } = page;

  return get<PageResponse<AlertEvidence>>(endpoints.alerts.evidence(id), {
    params: { ...pageParams(rest), ...cleanParams({ evidence_type }) },
  });
}

export async function addAlertEvidence(
  id: string,
  body: AlertEvidenceCreateRequest,
): Promise<AlertEvidenceActionResult> {
  return post<AlertEvidenceActionResult>(endpoints.alerts.evidence(id), body);
}

export async function fetchAlertHistory(
  id: string,
  page: PageQuery & { action?: string; outcome?: string } = {},
): Promise<AlertHistoryListResponse> {
  const { action, outcome, ...rest } = page;

  return get<AlertHistoryListResponse>(endpoints.alerts.history(id), {
    params: { ...pageParams(rest), ...cleanParams({ action, outcome }) },
  });
}

/** Take the alert. No body: the actor is the signed-in user. */
export async function acknowledgeAlert(id: string): Promise<AlertActionResult> {
  return post<AlertActionResult>(endpoints.alerts.acknowledge(id));
}

export async function assignAlert(
  id: string,
  body: AlertAssignRequest,
): Promise<AlertAssignResult> {
  return post<AlertAssignResult>(endpoints.alerts.assign(id), body);
}

export async function escalateAlert(id: string): Promise<AlertActionResult> {
  return post<AlertActionResult>(endpoints.alerts.escalate(id));
}

/** Closing requires a reason. There is no "close without comment". */
export async function closeAlert(
  id: string,
  body: AlertCloseRequest,
): Promise<AlertActionResult> {
  return post<AlertActionResult>(endpoints.alerts.close(id), body);
}

export async function reopenAlert(id: string): Promise<AlertActionResult> {
  return post<AlertActionResult>(endpoints.alerts.reopen(id));
}

/**
 * Open a case from this alert.
 *
 * The response reports how much of the alert's evidence was carried across
 * and whether that was truncated, which the UI surfaces: a case that received
 * 50 of 300 evidence items is not the same as one that received all of them.
 */
export async function createCaseFromAlert(
  id: string,
  body: AlertCreateCaseRequest = {},
): Promise<AlertCreateCaseResult> {
  return post<AlertCreateCaseResult>(endpoints.alerts.createCase(id), body);
}

/** True while an alert still represents work. */
export function isOpenAlert(alert: Alert): boolean {
  return alert.state !== 'CLOSED';
}
