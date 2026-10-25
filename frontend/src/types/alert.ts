import type { Iso8601, PageResponse } from './common';

/** Alert types, mirroring `app/api/v1/endpoints/alerts.py`. */

export type AlertState = 'NEW' | 'ACKNOWLEDGED' | 'UNDER_REVIEW' | 'ESCALATED' | 'CLOSED';

export interface AlertAccountSummary {
  id: string;
  account_type: string;
  status: string;
  created_at: Iso8601;
  record_created_at?: Iso8601 | null;
  record_updated_at?: Iso8601 | null;
}

export interface AlertCaseSummary {
  id: string;
  title: string;
  status: string;
  priority: string;
  assignee_id?: string | null;
  creator_id?: string | null;
  alert_id?: string | null;
  account_id?: string | null;
  created_at?: Iso8601 | null;
  updated_at?: Iso8601 | null;
  metadata_json?: Record<string, unknown> | null;
}

export interface AlertEvidence {
  id: string;
  alert_id: string;
  evidence_type: string;
  evidence_id: string;
  /** What the record looked like when attached, so a later edit is visible. */
  evidence_snapshot_json?: Record<string, unknown> | null;
  provenance_json?: Record<string, unknown> | null;
  created_by?: string | null;
  created_by_username?: string | null;
  record_created_at?: Iso8601 | null;
  record_updated_at?: Iso8601 | null;
}

export interface Alert {
  id: string;
  account_id: string;
  assessment_id?: string | null;
  title: string;
  summary?: string | null;
  priority: string;
  state: string;
  score?: number | null;
  score_version?: string | null;
  scoring_mode: string;
  model_version?: string | null;
  rule_codes: string[];
  signal_summary_json?: Record<string, unknown> | null;
  /**
   * When this signature was first seen. Queue age is measured from here, not
   * from the most recent run: deduplication updates an existing alert rather
   * than raising a new one, so an alert that has re-fired nightly for a
   * fortnight is a fortnight old.
   */
  first_seen_at: Iso8601;
  last_seen_at: Iso8601;
  acknowledged_at?: Iso8601 | null;
  acknowledged_by?: string | null;
  assigned_to?: string | null;
  closed_at?: Iso8601 | null;
  created_by?: string | null;
  updated_by?: string | null;
  record_created_at?: Iso8601 | null;
  record_updated_at?: Iso8601 | null;
  /** Present only when the request set `include_account`. */
  account?: AlertAccountSummary | null;
  /** Counts are optional: absent means "not computed", not zero. */
  evidence_count?: number | null;
  case_count?: number | null;
  active_case_count?: number | null;
  active_case_id?: string | null;
}

export type AlertListResponse = PageResponse<Alert>;

export interface AlertDetail {
  alert: Alert;
  evidences: AlertEvidence[];
  cases: AlertCaseSummary[];
  /** True when more evidence exists than was returned. */
  evidence_truncated: boolean;
  case_truncated: boolean;
  caveats: string[];
}

export interface AlertHistoryEvent {
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
  created_at: Iso8601;
}

export type AlertHistoryListResponse = PageResponse<AlertHistoryEvent>;

/**
 * The result of a triage action.
 *
 * `changed` is false when the action was a no-op — acknowledging an already
 * acknowledged alert, say. The UI reports that rather than claiming success,
 * because a user who clicks twice should not believe two things happened.
 */
export interface AlertActionResult {
  alert: Alert;
  changed: boolean;
  previous_state: string;
  new_state: string;
  audited: boolean;
  caveats: string[];
}

export interface AlertAssignResult {
  alert: Alert;
  changed: boolean;
  previous_assignee_id?: string | null;
  new_assignee_id?: string | null;
  previous_state: string;
  new_state: string;
  audited: boolean;
  caveats: string[];
}

export interface AlertAssignRequest {
  assignee_id: string;
  note?: string;
}

export interface AlertCloseRequest {
  /** Required. Closing without a stated reason is not permitted. */
  reason: string;
}

export interface AlertEvidenceCreateRequest {
  evidence_type: string;
  evidence_id: string;
  evidence_snapshot_json?: Record<string, unknown> | null;
  provenance_json?: Record<string, unknown> | null;
}

export interface AlertEvidenceActionResult {
  evidence: AlertEvidence;
  alert: Alert;
  changed: boolean;
  audited: boolean;
  caveats: string[];
}

export interface AlertCreateCaseRequest {
  title?: string;
  description?: string;
  assignee_id?: string;
  priority?: string;
  metadata_json?: Record<string, unknown> | null;
}

export interface AlertCreateCaseResult {
  case: AlertCaseSummary;
  alert: Alert;
  /** Evidence carried over from the alert onto the new case. */
  copied_evidence_count: number;
  total_evidence_count: number;
  evidence_truncated: boolean;
  audited: boolean;
  caveats: string[];
}

/** Query parameters the alert list accepts. Note the plural state filters. */
export interface AlertFilters {
  account_id?: string;
  states?: string[];
  priorities?: string[];
  scoring_mode?: string;
  assigned_to?: string;
  acknowledged_by?: string;
  min_score?: number;
  max_score?: number;
  created_from?: string;
  created_to?: string;
  first_seen_from?: string;
  first_seen_to?: string;
  last_seen_from?: string;
  last_seen_to?: string;
  include_account?: boolean;
  q?: string;
}

/** States that still represent work. There is no `open_only` parameter. */
export const OPEN_ALERT_STATES: AlertState[] = [
  'NEW',
  'ACKNOWLEDGED',
  'UNDER_REVIEW',
  'ESCALATED',
];
