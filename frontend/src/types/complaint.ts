import type { Iso8601, PageResponse } from './common';

/** Complaint types, mirroring `app/api/v1/endpoints/complaints.py`. */

export type ComplaintReviewState =
  | 'UNREVIEWED'
  | 'REVIEWED'
  | 'ACCEPTED'
  | 'REJECTED'
  | 'NEEDS_MORE_INFO';

export type MatchMethod =
  | 'EXACT'
  | 'NORMALIZED'
  | 'ENTITY_TEMPORAL'
  | 'GRAPH_TEMPORAL'
  | 'NARRATIVE_EXTRACTION'
  | 'MANUAL'
  | 'UNKNOWN';

/** 1 strongest, 5 weakest. Tiers 1-2 are identities; 3-5 are inferences. */
export type MatchTier = 1 | 2 | 3 | 4 | 5;

/**
 * A complaint as filed.
 *
 * `narrative_available` rather than the narrative itself: the raw text is a
 * victim's own account of what happened to them, and reading it needs the
 * `complaint_narrative_read` permission. The list tells you whether there is
 * one without handing it over.
 *
 * `suspected_account_id` is the complainant's allegation carried through from
 * the filing. It is not a MuleGuard finding, and a victim who mistyped a UPI
 * handle names an innocent account here.
 */
export interface Complaint {
  id: string;
  reference: string;
  category: string;
  reported_at: Iso8601;
  amount?: number | null;
  currency?: string | null;
  source?: string | null;
  victim_account_id?: string | null;
  suspected_account_id?: string | null;
  transaction_reference?: string | null;
  narrative_available: boolean;
  created_at?: Iso8601 | null;
  updated_at?: Iso8601 | null;
  /** Present only when the request set `include_correlation_count`. */
  correlation_count?: number | null;
}

export type ComplaintListResponse = PageResponse<Complaint>;

/**
 * A link between a complaint and an account, transaction or entity.
 *
 * `confidence` is present only on an inferred correlation. A deterministic
 * match (tier 1-2) is an identity and carries none — rendering 0 there would
 * read as "no confidence", the opposite of the truth.
 */
export interface ComplaintCorrelation {
  id: string;
  complaint_id: string;
  complaint_reference?: string | null;
  complaint_category?: string | null;
  complaint_reported_at?: Iso8601 | null;
  complaint_amount?: number | null;
  complaint_currency?: string | null;
  complaint_source?: string | null;
  complaint_narrative_available: boolean;
  account_id?: string | null;
  transaction_id?: string | null;
  entity_id?: string | null;
  match_tier: number;
  match_method: string;
  confidence?: number | null;
  deterministic: boolean;
  review_state: string;
  evidence_refs: string[];
  created_at?: Iso8601 | null;
}

export type ComplaintCorrelationListResponse = PageResponse<ComplaintCorrelation>;

/** Fields every "linked X" row carries about the correlation that found it. */
export interface CorrelationFacts {
  correlation_id: string;
  match_tier: number;
  match_method: string;
  confidence?: number | null;
  deterministic: boolean;
  review_state: string;
}

export interface ComplaintLinkedAccount extends CorrelationFacts {
  id: string;
  account_type: string;
  status: string;
  created_at?: Iso8601 | null;
}

export interface ComplaintLinkedTransaction extends CorrelationFacts {
  id: string;
  sender_account_id: string;
  receiver_account_id: string;
  amount: number;
  currency: string;
  occurred_at: Iso8601;
  status: string;
  channel: string;
  reference: string;
}

export interface ComplaintLinkedEntity extends CorrelationFacts {
  id: string;
  entity_type: string;
  /** A display form, not the raw identifier: most are stored hashed. */
  identifier_display?: string | null;
  source: string;
}

export type ComplaintLinkedAccountListResponse = PageResponse<ComplaintLinkedAccount>;
export type ComplaintLinkedTransactionListResponse = PageResponse<ComplaintLinkedTransaction>;
export type ComplaintLinkedEntityListResponse = PageResponse<ComplaintLinkedEntity>;

export interface ComplaintHistoryEvent {
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

export type ComplaintHistoryListResponse = PageResponse<ComplaintHistoryEvent>;

export interface ComplaintExportBundle {
  complaint: Complaint;
  correlations: ComplaintCorrelation[];
  correlation_total: number;
  correlation_truncated: boolean;
  max_items: number;
  caveats: string[];
}

/**
 * Aggregate complaint statistics.
 *
 * `by_match_tier` is keyed by the tier as a string ('1'…'5'), and
 * `deterministic_count` plus `inferred_count` is the split that matters: an
 * identity and an inference are different kinds of claim and summing them
 * overstates what is known.
 */
export interface ComplaintStats {
  period: Record<string, unknown>;
  total_complaints: number;
  total_correlations: number;
  by_category: Record<string, number>;
  by_source: Record<string, number>;
  by_match_tier: Record<string, number>;
  by_review_state: Record<string, number>;
  deterministic_count: number;
  inferred_count: number;
  caveats: string[];
}

export interface ComplaintReviewUpdateRequest {
  review_state: ComplaintReviewState;
  note?: string;
}

export interface ComplaintReviewUpdateResult {
  correlation: ComplaintCorrelation;
  complaint: Complaint;
  changed: boolean;
  previous_state: string;
  new_state: string;
  audited: boolean;
  caveats: string[];
}

export interface ComplaintFilters {
  category?: string;
  source?: string;
  victim_account_id?: string;
  suspected_account_id?: string;
  transaction_reference?: string;
  date_from?: string;
  date_to?: string;
  min_amount?: number;
  max_amount?: number;
  include_correlation_count?: boolean;
  q?: string;
}

export interface CorrelationFilters {
  match_tier?: number;
  review_state?: string;
  deterministic?: boolean;
  match_method?: string;
  account_id?: string;
  transaction_id?: string;
  entity_id?: string;
  q?: string;
}
