import type { Iso8601, PageResponse } from './common';

/** Analysis types, mirroring `app/api/v1/endpoints/analysis.py`. */

export type AnalysisRunStatus =
  | 'QUEUED'
  | 'RUNNING'
  | 'SUCCEEDED'
  | 'FAILED'
  | 'CANCELLED'
  | 'PARTIAL';

export type IndicatorType =
  | 'RULE'
  | 'MODEL'
  | 'ANOMALY'
  | 'GRAPH'
  | 'COMPLAINT'
  | 'FEATURE'
  | 'FUSED_RISK';

export interface AccountFilterRequest {
  account_type?: string;
  status?: string;
  created_from?: string;
  created_to?: string;
}

export interface AnalysisRunRequest {
  /** Explicit accounts, or `account_filters` to select them by attribute. */
  account_ids?: string[];
  account_filters?: AccountFilterRequest;
  /**
   * The point in time to assess. Features see only data strictly before it,
   * so backdating this produces a correct assessment *as of then* — which is
   * how a finding is reproduced after the fact.
   */
  as_of?: string;
  options?: Record<string, unknown>;
}

/**
 * An analysis run.
 *
 * `PARTIAL` is a real outcome, not a failure: usable output with some
 * per-account errors. The UI distinguishes it from `SUCCEEDED`, because an
 * analyst drawing conclusions from a partial run should know which accounts
 * were not assessed.
 */
export interface AnalysisRun {
  id: string;
  status: string;
  scoring_mode: string;
  model_version_id?: string | null;
  model_version?: string | null;
  requested_by?: string | null;
  requested_by_username?: string | null;
  started_at?: Iso8601 | null;
  finished_at?: Iso8601 | null;
  created_at?: Iso8601 | null;
  updated_at?: Iso8601 | null;
  duration_seconds?: number | null;
  account_count: number;
  assessment_count: number;
  alert_count: number;
  parameters_json?: Record<string, unknown> | null;
  summary_json?: Record<string, unknown> | null;
  error_code?: string | null;
  error_message?: string | null;
  caveats: string[];
}

export type AnalysisRunListResponse = PageResponse<AnalysisRun>;

export interface AnalysisAssessment {
  id: string;
  account_id: string;
  /** The instant assessed. Features saw only data strictly before it. */
  as_of: Iso8601;
  /** When scoring ran. Later than `as_of`, and distinct on purpose. */
  scored_at: Iso8601;
  scoring_mode: string;
  score?: number | null;
  score_type?: string | null;
  risk_band: string;
  model_version_id?: string | null;
  feature_snapshot_id?: string | null;
  analysis_run_id?: string | null;
  explanation_available: boolean;
}

export interface AnalysisAlert {
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
  first_seen_at: Iso8601;
  last_seen_at: Iso8601;
}

/**
 * A run's output.
 *
 * `alerts_available` is false when alerting is switched off in this
 * deployment. That is different from "this run raised no alerts", and showing
 * an empty alert list for the first case would be misleading.
 */
export interface AnalysisRunResults {
  run: AnalysisRun;
  assessments: AnalysisAssessment[];
  assessment_total: number;
  assessment_truncated: boolean;
  alerts: AnalysisAlert[];
  alert_total: number;
  alert_truncated: boolean;
  alerts_available: boolean;
  page: number;
  page_size: number;
  caveats: string[];
}

export interface AnalysisRunHistoryEvent {
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

export type AnalysisRunHistoryListResponse = PageResponse<AnalysisRunHistoryEvent>;

/**
 * Whether analysis can run here, and under what constraints.
 *
 * `service_available` false means the analytical service itself is not
 * wired up, in which case starting a run returns 503. `require_trained_model`
 * true with no active model means the same. Both are worth showing before
 * someone clicks the button.
 */
export interface AnalysisStatus {
  enabled: boolean;
  service_available: boolean;
  scoring_mode: string;
  model_version_id?: string | null;
  model_version?: string | null;
  require_trained_model: boolean;
  dataset_mode: string;
  allow_all_accounts: boolean;
  max_accounts: number;
  max_date_span_days: number;
  default_as_of_policy: string;
  caveats: string[];
}

export interface AnalysisFilters {
  status?: string;
  scoring_mode?: string;
  requested_by?: string;
  created_from?: string;
  created_to?: string;
  started_from?: string;
  started_to?: string;
  finished_from?: string;
  finished_to?: string;
  q?: string;
}
