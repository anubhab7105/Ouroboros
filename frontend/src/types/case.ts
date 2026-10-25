import type { Iso8601, PageResponse } from './common';

/** Case types, mirroring `app/api/v1/endpoints/cases.py`. */

export type CaseStatus = 'NEW' | 'TRIAGED' | 'UNDER_INVESTIGATION' | 'ESCALATED' | 'CLOSED';
export type Disposition = 'CONFIRMED_FRAUD' | 'FALSE_POSITIVE' | 'INCONCLUSIVE' | 'REFERRED';

export interface CaseAccountSummary {
  id: string;
  account_type: string;
  status: string;
  created_at: Iso8601;
  record_created_at?: Iso8601 | null;
  record_updated_at?: Iso8601 | null;
}

export interface CaseAlertSummary {
  id: string;
  account_id: string;
  title: string;
  priority: string;
  state: string;
  score?: number | null;
  scoring_mode: string;
  first_seen_at?: Iso8601 | null;
  last_seen_at?: Iso8601 | null;
}

export interface InvestigationCase {
  id: string;
  title: string;
  description?: string | null;
  status: string;
  priority: string;
  assignee_id?: string | null;
  assignee_username?: string | null;
  creator_id?: string | null;
  creator_username?: string | null;
  alert_id?: string | null;
  account_id?: string | null;
  /** Free text, capped at 100 characters, entered by the investigator. */
  disposition?: string | null;
  closed_at?: Iso8601 | null;
  created_at?: Iso8601 | null;
  updated_at?: Iso8601 | null;
  metadata_json?: Record<string, unknown> | null;
  /** Present only when the request set `include_account`. */
  account?: CaseAccountSummary | null;
  /** Present only when the request set `include_alert`. */
  alert?: CaseAlertSummary | null;
}

export type CaseListResponse = PageResponse<InvestigationCase>;

/**
 * An entry in a case's history.
 *
 * Notes and events share this shape: a note is an event whose action records
 * that someone wrote something, with the text in `summary`. The history is
 * append-only, so there is no edit and no revision count.
 */
export interface CaseEvent {
  id: string;
  case_id: string;
  action: string;
  actor_id?: string | null;
  actor_username?: string | null;
  resource_type?: string | null;
  resource_id?: string | null;
  summary?: string | null;
  metadata_json?: Record<string, unknown> | null;
  created_at?: Iso8601 | null;
}

export type CaseEventListResponse = PageResponse<CaseEvent>;

export interface CaseEvidence {
  id: string;
  case_id: string;
  evidence_type: string;
  evidence_id: string;
  /**
   * What the record looked like when it was attached. Kept so a report can be
   * reconstructed even after the underlying record changes.
   */
  evidence_snapshot_json?: Record<string, unknown> | null;
  provenance_json?: Record<string, unknown> | null;
  added_by?: string | null;
  added_by_username?: string | null;
  /**
   * False when soft-removed. Removed items are retained rather than deleted,
   * so a previously generated report stays reconstructible.
   */
  is_active?: boolean | null;
  record_created_at?: Iso8601 | null;
  record_updated_at?: Iso8601 | null;
}

export type CaseEvidenceListResponse = PageResponse<CaseEvidence>;

/**
 * A case with its first page of evidence, events and notes.
 *
 * Each collection comes with its own total and a truncation flag, because the
 * detail endpoint returns a bounded slice. A case with 400 evidence items
 * shows the first few here and the rest through the paginated endpoint; the
 * flag is what stops the UI implying it has shown everything.
 */
export interface CaseDetail {
  case: InvestigationCase;
  evidences: CaseEvidence[];
  events: CaseEvent[];
  notes: CaseEvent[];
  evidence_total: number;
  evidence_truncated: boolean;
  event_total: number;
  event_truncated: boolean;
  note_total: number;
  note_truncated: boolean;
  caveats: string[];
}

export interface CaseActionResult {
  case: InvestigationCase;
  /** False when the action was a no-op, e.g. starting a started case. */
  changed: boolean;
  previous_status: string;
  new_status: string;
  audited: boolean;
  caveats: string[];
}

export interface CaseAssignResult {
  case: InvestigationCase;
  changed: boolean;
  previous_assignee_id?: string | null;
  new_assignee_id?: string | null;
  previous_status: string;
  new_status: string;
  audited: boolean;
  caveats: string[];
}

export interface CaseNoteResult {
  note: CaseEvent;
  case: InvestigationCase;
  audited: boolean;
  caveats: string[];
}

export interface CaseEvidenceActionResult {
  evidence: CaseEvidence;
  case: InvestigationCase;
  changed: boolean;
  audited: boolean;
  caveats: string[];
}

export interface CaseAuditEvent {
  id: string;
  action: string;
  outcome: string;
  actor_id?: string | null;
  actor_username?: string | null;
  actor_role?: string | null;
  resource_type?: string | null;
  resource_id?: string | null;
  request_id?: string | null;
  metadata_json?: Record<string, unknown> | null;
  created_at?: Iso8601 | null;
}

export type CaseAuditListResponse = PageResponse<CaseAuditEvent>;

export interface CaseExportBundle {
  case: InvestigationCase;
  evidences: CaseEvidence[];
  events: CaseEvent[];
  notes: CaseEvent[];
  evidence_total: number;
  evidence_truncated: boolean;
  event_total: number;
  event_truncated: boolean;
  note_total: number;
  note_truncated: boolean;
  /** The per-collection cap the bundle was built with. */
  max_items: number;
  caveats: string[];
}

export interface CaseCreateRequest {
  title?: string;
  description?: string;
  account_id?: string;
  alert_id?: string;
  assignee_id?: string;
  priority?: string;
  metadata_json?: Record<string, unknown> | null;
}

export interface CaseUpdateRequest {
  title?: string;
  description?: string;
  priority?: string;
  metadata_json?: Record<string, unknown> | null;
}

export interface CaseAssignRequest {
  assignee_id: string;
  note?: string;
}

export interface CaseCloseRequest {
  /** Required. A case cannot be closed without a stated reason. */
  reason: string;
  /**
   * Required. One of `CONFIRMED_FRAUD`, `FALSE_POSITIVE`, `INCONCLUSIVE`,
   * `REFERRED`.
   *
   * Every later quality measurement reads this field, and it cannot be
   * reconstructed from the reason text afterwards, so the server refuses a
   * closure without it.
   */
  disposition: string;
}

export interface CaseEscalateRequest {
  /** Required. Recorded in case history and read by the senior reviewer. */
  reason: string;
}

export interface CaseReopenRequest {
  /** Required. What new information justifies reopening. */
  reason: string;
}

export interface CaseNoteRequest {
  note: string;
}

export interface CaseEvidenceCreateRequest {
  evidence_type: string;
  evidence_id: string;
  evidence_snapshot_json?: Record<string, unknown> | null;
  provenance_json?: Record<string, unknown> | null;
}

export interface CaseFilters {
  status?: string;
  priority?: string;
  assignee_id?: string;
  creator_id?: string;
  account_id?: string;
  alert_id?: string;
  disposition?: string;
  date_from?: string;
  date_to?: string;
  closed_from?: string;
  closed_to?: string;
  include_account?: boolean;
  include_alert?: boolean;
  q?: string;
}

/** Statuses that still represent work. There is no `open_only` parameter. */
export const OPEN_CASE_STATUSES: CaseStatus[] = [
  'NEW',
  'TRIAGED',
  'UNDER_INVESTIGATION',
  'ESCALATED',
];
