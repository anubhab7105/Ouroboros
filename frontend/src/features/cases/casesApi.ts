import { cleanParams, endpoints, pageParams } from '@/lib/api';
import { get, post, patch } from '@/lib/apiClient';
import type { PageQuery } from '@/types/common';
import type {
  CaseActionResult,
  CaseAssignRequest,
  CaseAssignResult,
  CaseAuditListResponse,
  CaseCloseRequest,
  CaseCreateRequest,
  CaseDetail,
  CaseEventListResponse,
  CaseEvidenceActionResult,
  CaseEvidenceCreateRequest,
  CaseEscalateRequest,
  CaseEvidenceListResponse,
  CaseExportBundle,
  CaseFilters,
  CaseListResponse,
  CaseNoteRequest,
  CaseNoteResult,
  CaseReopenRequest,
  CaseUpdateRequest,
  InvestigationCase,
} from '@/types/case';

/**
 * Case reads and mutations.
 *
 * Every state transition is its own endpoint — `start`, `escalate`, `close`,
 * `reopen`, `assign` — rather than a PATCH of the status field. That is the
 * server enforcing its own state machine, and the client follows it rather
 * than trying to set a status directly, which the API would refuse.
 *
 * Each mutation returns `changed`, which is false when the action was a no-op.
 * Callers report that honestly instead of claiming a success that did not
 * happen.
 */

export async function fetchCases(
  page: PageQuery & { filters: CaseFilters },
): Promise<CaseListResponse> {
  const { filters, ...rest } = page;

  return get<CaseListResponse>(endpoints.cases.list(), {
    params: { ...pageParams(rest), ...cleanParams(filters) },
  });
}

export async function fetchCase(id: string): Promise<CaseDetail> {
  return get<CaseDetail>(endpoints.cases.detail(id));
}

export async function createCase(body: CaseCreateRequest): Promise<InvestigationCase> {
  return post<InvestigationCase>(endpoints.cases.create(), body);
}

export async function updateCase(
  id: string,
  body: CaseUpdateRequest,
): Promise<InvestigationCase> {
  return patch<InvestigationCase>(endpoints.cases.update(id), body);
}

export async function assignCase(
  id: string,
  body: CaseAssignRequest,
): Promise<CaseAssignResult> {
  return post<CaseAssignResult>(endpoints.cases.assign(id), body);
}

/**
 * Move a case into investigation. Takes no body.
 *
 * The case must already have an assignee: the server's `start` transition
 * requires one, so an unassigned case is refused with a 409 rather than
 * entering an in-progress state nobody owns. Assign first.
 */
export async function startCase(id: string): Promise<CaseActionResult> {
  return post<CaseActionResult>(endpoints.cases.start(id));
}

/** Escalating requires a reason: it is what the senior reviewer reads first. */
export async function escalateCase(
  id: string,
  body: CaseEscalateRequest,
): Promise<CaseActionResult> {
  return post<CaseActionResult>(endpoints.cases.escalate(id), body);
}

/** Closing requires both a reason and a disposition. */
export async function closeCase(
  id: string,
  body: CaseCloseRequest,
): Promise<CaseActionResult> {
  return post<CaseActionResult>(endpoints.cases.close(id), body);
}

/** Reopening requires a reason. */
export async function reopenCase(
  id: string,
  body: CaseReopenRequest,
): Promise<CaseActionResult> {
  return post<CaseActionResult>(endpoints.cases.reopen(id), body);
}

export async function fetchCaseNotes(
  id: string,
  page: PageQuery & { actor_id?: string } = {},
): Promise<CaseEventListResponse> {
  const { actor_id, ...rest } = page;

  return get<CaseEventListResponse>(endpoints.cases.notes(id), {
    params: { ...pageParams(rest), ...cleanParams({ actor_id }) },
  });
}

export async function addCaseNote(id: string, body: CaseNoteRequest): Promise<CaseNoteResult> {
  return post<CaseNoteResult>(endpoints.cases.notes(id), body);
}

export async function fetchCaseEvidence(
  id: string,
  page: PageQuery & { evidence_type?: string; include_inactive?: boolean } = {},
): Promise<CaseEvidenceListResponse> {
  const { evidence_type, include_inactive, ...rest } = page;

  return get<CaseEvidenceListResponse>(endpoints.cases.evidence(id), {
    params: { ...pageParams(rest), ...cleanParams({ evidence_type, include_inactive }) },
  });
}

export async function addCaseEvidence(
  id: string,
  body: CaseEvidenceCreateRequest,
): Promise<CaseEvidenceActionResult> {
  return post<CaseEvidenceActionResult>(endpoints.cases.evidence(id), body);
}

/**
 * Remove an evidence reference.
 *
 * A POST to `.../remove` rather than a DELETE, because this is a soft removal:
 * the row is retained so that a report generated earlier stays
 * reconstructible. Nothing is deleted.
 */
export async function removeCaseEvidence(
  caseId: string,
  evidenceId: string,
): Promise<CaseEvidenceActionResult> {
  return post<CaseEvidenceActionResult>(endpoints.cases.removeEvidence(caseId, evidenceId));
}

export async function fetchCaseEvents(
  id: string,
  page: PageQuery & { action?: string; actor_id?: string } = {},
): Promise<CaseEventListResponse> {
  const { action, actor_id, ...rest } = page;

  return get<CaseEventListResponse>(endpoints.cases.events(id), {
    params: { ...pageParams(rest), ...cleanParams({ action, actor_id }) },
  });
}

export async function fetchCaseAudit(
  id: string,
  page: PageQuery & { action?: string; outcome?: string } = {},
): Promise<CaseAuditListResponse> {
  const { action, outcome, ...rest } = page;

  return get<CaseAuditListResponse>(endpoints.cases.audit(id), {
    params: { ...pageParams(rest), ...cleanParams({ action, outcome }) },
  });
}

export async function exportCase(
  id: string,
  includeInactiveEvidence = false,
): Promise<CaseExportBundle> {
  return get<CaseExportBundle>(endpoints.cases.export(id), {
    params: { include_inactive_evidence: includeInactiveEvidence },
  });
}
