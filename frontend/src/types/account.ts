import type { Iso8601, PageResponse } from './common';

/**
 * Account types, mirroring `app/api/v1/endpoints/accounts.py`.
 *
 * Note what the account list does *not* contain: open alert and case counts.
 * The list endpoint returns the account record and, optionally, a summary of
 * its latest assessment — nothing more. Counts come from
 * `/accounts/{id}/summary`, one account at a time, so a list view must not
 * promise a column it cannot fill.
 */

export type AccountType = 'INDIVIDUAL' | 'BUSINESS' | 'MERCHANT' | 'OTHER';
export type AccountStatus = 'ACTIVE' | 'DORMANT' | 'CLOSED' | 'REVIEW_REQUIRED';

/**
 * The latest persisted assessment for an account.
 *
 * `as_of` is the instant assessed — features saw only data strictly before
 * it. `scored_at` is when scoring ran, usually later. The two are distinct on
 * purpose: an assessment re-run today over last month's data is correct about
 * last month, and conflating them would misdate the finding.
 */
export interface LatestAssessmentSummary {
  id: string;
  account_id: string;
  as_of: Iso8601;
  scored_at: Iso8601;
  scoring_mode: string;
  score: number;
  score_type: string;
  score_version?: string | null;
  risk_band: string;
  model_version_id?: string | null;
  feature_snapshot_id?: string | null;
  analysis_run_id?: string | null;
  dataset_fingerprint?: string | null;
  /** False when the assessment carries no written explanation. */
  explanation_available: boolean;
  indicator_count?: number | null;
}

export interface Account {
  id: string;
  account_type: string;
  /**
   * Lifecycle status as reported by the source system. Observational only:
   * MuleGuard never sets it and takes no action on it.
   */
  status: string;
  created_at: Iso8601;
  metadata_json?: Record<string, unknown> | null;
  record_created_at?: Iso8601 | null;
  record_updated_at?: Iso8601 | null;
  /** Present only when the request set `include_latest_assessment`. */
  latest_assessment?: LatestAssessmentSummary | null;
}

export type AccountListResponse = PageResponse<Account>;

/**
 * Windowed activity for one account.
 *
 * Every monetary figure counts COMPLETED transfers only, which is why the
 * pending, failed and reversed counts are returned alongside: they are the
 * difference between this view and a naive sum of the ledger.
 */
export interface AccountSummary {
  account_id: string;
  window: Record<string, unknown>;
  currency: string;
  incoming_completed_count: number;
  incoming_completed_amount: number;
  outgoing_completed_count: number;
  outgoing_completed_amount: number;
  net_completed_amount: number;
  distinct_incoming_counterparties: number;
  distinct_outgoing_recipients: number;
  self_transfer_count: number;
  pending_count: number;
  failed_count: number;
  reversed_count: number;
  latest_assessment?: LatestAssessmentSummary | null;
  open_alert_count: number;
  complaint_correlation_count: number;
  active_entity_link_count: number;
  caveats: string[];
}

/** Query parameters the account list accepts. */
export interface AccountFilters {
  account_type?: string;
  status?: string;
  created_from?: string;
  created_to?: string;
  include_latest_assessment?: boolean;
  q?: string;
}

// ------------------------------------------------- assessment detail

/**
 * One risk indicator contributing to an assessment.
 *
 * `rule_hit_id` links an indicator back to the rule evaluation that produced
 * it, where there was one. An indicator without it came from the model or the
 * anomaly component rather than from a rule.
 */
export interface RiskIndicator {
  id: string;
  indicator_type: string;
  code: string;
  title: string;
  severity: string;
  measured_value?: number | null;
  threshold?: number | null;
  explanation?: string | null;
  evidence_refs: string[];
  rule_hit_id?: string | null;
}

/**
 * One rule evaluation.
 *
 * `triggered` false is informative, not noise: knowing that the fan-in rule
 * was evaluated and came back below threshold is evidence about the account,
 * and the measured value next to the threshold is what lets an analyst check
 * — or disagree with — the finding rather than take it on trust.
 */
export interface RuleHit {
  id: string;
  rule_code: string;
  rule_version: string;
  triggered: boolean;
  measured_value?: number | null;
  threshold?: number | null;
  severity: string;
  explanation?: string | null;
  evidence_refs: string[];
  evaluated_at: Iso8601;
}

export interface AssessmentDetail {
  id: string;
  account_id: string;
  as_of: Iso8601;
  scored_at: Iso8601;
  scoring_mode: string;
  score: number;
  score_type: string;
  score_version?: string | null;
  risk_band: string;
  model_version_id?: string | null;
  feature_snapshot_id?: string | null;
  analysis_run_id?: string | null;
  dataset_fingerprint?: string | null;
  /**
   * Per-component breakdown. Holds each component's normalised value and its
   * *effective* weight, which differs from the configured weight when a
   * component was unavailable and its weight was redistributed.
   */
  components_json?: Record<string, unknown> | null;
  explanation_json?: Record<string, unknown> | null;
  caveats_json?: unknown;
  evidence_refs: string[];
}

/**
 * The assessment endpoint's answer.
 *
 * `status` distinguishes "this account has no assessment" from an error. An
 * unassessed account is a normal state — nothing has analysed it yet — and
 * must not be rendered as a zero score.
 */
export interface AccountAssessment {
  available: boolean;
  status: 'available' | 'no_assessment';
  message?: string | null;
  assessment?: AssessmentDetail | null;
  indicators: RiskIndicator[];
  rule_hits: RuleHit[];
  evidence_refs: string[];
}

export type AssessmentHistoryResponse = PageResponse<LatestAssessmentSummary>;

/** A pseudonymous identifier linked to an account. */
export interface EntityLink {
  id: string;
  account_id: string;
  entity_id: string;
  entity_type: string;
  /** A display form. Most identifiers are stored only as hashes. */
  identifier_display?: string | null;
  source: string;
  match_method: string;
  /** Present on inferred links only. A deterministic link carries none. */
  confidence?: number | null;
  verification_state: string;
  valid_from: Iso8601;
  /** Null while the link is current. Links are time-bounded, not deleted. */
  valid_to?: Iso8601 | null;
  metadata_json?: Record<string, unknown> | null;
}

export type EntityLinkListResponse = PageResponse<EntityLink>;

/**
 * One entry inside an assessment's `components_json`.
 *
 * The column is untyped on the server — its shape is the scorer's own and
 * varies by scoring mode — so this records what the fusion writes rather than
 * a contract the API guarantees. Every field is optional, and a reader must
 * treat a missing value as "not computed" rather than as zero.
 *
 * `effective_weight` is the field that matters: it is the weight the component
 * actually carried after the weights of any unavailable components were
 * redistributed, so it can differ from the configured weight.
 */
export interface ScoreComponentEntry {
  name?: string;
  component?: string;
  normalised_value?: number;
  value?: number;
  score?: number;
  effective_weight?: number;
  weight?: number;
  contribution_points?: number;
  available?: boolean;
  source?: string;
}
