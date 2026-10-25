import type { Iso8601 } from './common';

/**
 * Dashboard types.
 *
 * These mirror the response models declared inside
 * `app/api/v1/endpoints/dashboard.py` — not `app/schemas/dashboard.py`. The
 * endpoint defines its own models locally, and the endpoint is what actually
 * answers the request, so it is the contract.
 *
 * Two consequences the UI has to respect:
 *
 * - **The window is `date_from`/`date_to`, not a day count.** `window_days` is
 *   a convenience the client turns into a pair of instants; the server echoes
 *   back the window it actually used, including whether it fell back to the
 *   default, and the UI renders the echo rather than its own request.
 *
 * - **Breakdowns are open maps, not fixed enums.** `by_risk_band`,
 *   `open_by_state` and friends are `dict[str, int]` server-side. A band or
 *   state added on the backend must still appear in the UI, so every consumer
 *   reads these as records with unknown keys and humanises what it finds.
 */

export interface DashboardWindow {
  date_from: Iso8601;
  date_to: Iso8601;
  /** True when the client sent no range and the server applied its default. */
  defaulted: boolean;
  default_window_days: number;
  max_span_days: number;
}

export interface DashboardAccountBreakdown {
  total: number;
  active: number;
  by_status: Record<string, number>;
  by_type: Record<string, number>;
}

export interface DashboardAlertBreakdown {
  total_all_time: number;
  open_all_time: number;
  created_in_window: number;
  open_by_state: Record<string, number>;
  created_by_state: Record<string, number>;
  created_by_priority: Record<string, number>;
}

export interface DashboardCaseBreakdown {
  total_all_time: number;
  open_all_time: number;
  created_in_window: number;
  open_by_status: Record<string, number>;
  created_by_status: Record<string, number>;
  created_by_priority: Record<string, number>;
}

export interface DashboardComplaintBreakdown {
  total_all_time: number;
  reported_in_window: number;
  by_category: Record<string, number>;
  by_source: Record<string, number>;
  correlations_total: number;
  /** Tier 1-2 identity matches. These carry no confidence value. */
  correlations_deterministic: number;
  /** Tier 3-5 inferred matches. These do carry a confidence. */
  correlations_inferred: number;
  correlations_unreviewed: number;
}

export interface DashboardTransactionBreakdown {
  total_in_window: number;
  /** Only this count is fund movement; the rest are excluded from aggregates. */
  completed: number;
  pending: number;
  failed: number;
  reversed: number;
}

export interface DashboardAssessmentBreakdown {
  total_in_window: number;
  by_scoring_mode: Record<string, number>;
  by_risk_band: Record<string, number>;
  /** Assessments carrying an explanation summary. The rest are not explainable. */
  explanation_available: number;
}

export interface DashboardOverview {
  generated_at: Iso8601;
  window: DashboardWindow;
  accounts: DashboardAccountBreakdown;
  alerts: DashboardAlertBreakdown;
  cases: DashboardCaseBreakdown;
  complaints: DashboardComplaintBreakdown;
  transactions: DashboardTransactionBreakdown;
  assessments: DashboardAssessmentBreakdown;
  caveats: string[];
}

export interface DashboardMetrics {
  generated_at: Iso8601;
  window: DashboardWindow;
  /** Window length in days, fractional. Divisor for the rates below. */
  days: number;
  totals: Record<string, number>;
  /**
   * Per-day rates over the window. Operational signals only: they are not
   * statistically calibrated and must not be presented as forecasts.
   */
  rates_per_day: Record<string, number>;
  caveats: string[];
}

export interface DashboardQueueItem {
  /** Which queue this came from: 'alert', 'case' or 'correlation'. */
  kind: string;
  id: string;
  title?: string | null;
  account_id?: string | null;
  priority?: string | null;
  state?: string | null;
  score?: number | null;
  assignee_id?: string | null;
  created_at?: Iso8601 | null;
  updated_at?: Iso8601 | null;
  /** Age in seconds, computed server-side so every row agrees on "now". */
  age_seconds?: number | null;
}

export interface DashboardQueueSection {
  items: DashboardQueueItem[];
  /** The full count. `items` is capped at the server's top limit. */
  total: number;
  truncated: boolean;
}

export interface DashboardQueues {
  generated_at: Iso8601;
  unassigned_alerts: DashboardQueueSection;
  my_alerts: DashboardQueueSection;
  new_cases: DashboardQueueSection;
  triaged_cases: DashboardQueueSection;
  under_investigation_cases: DashboardQueueSection;
  escalated_cases: DashboardQueueSection;
  unreviewed_complaint_correlations: DashboardQueueSection;
  caveats: string[];
}

export interface DashboardTrendPoint {
  /** UTC calendar date, `YYYY-MM-DD`. */
  date: string;
  alerts: number;
  cases: number;
  complaints: number;
  transactions: number;
  assessments: number;
}

export interface DashboardTrends {
  generated_at: Iso8601;
  period: DashboardWindow;
  /** Always 'day' at present. Read it rather than assuming. */
  bucket_size: string;
  points: DashboardTrendPoint[];
  caveats: string[];
}

export interface DashboardStatus {
  enabled: boolean;
  default_window_days: number;
  max_date_span_days: number;
  max_trend_buckets: number;
  top_limit_default: number;
  top_limit_max: number;
  caveats: string[];
}

/** A category count, derived client-side from an open `by_*` map. */
export interface CategoryCount {
  category: string;
  count: number;
}

/** Turn a `dict[str, int]` breakdown into a sorted array for charting. */
export function toCategoryCounts(
  counts: Record<string, number> | null | undefined,
): CategoryCount[] {
  if (!counts) return [];

  return Object.entries(counts)
    .filter(([, count]) => Number.isFinite(count))
    .map(([category, count]) => ({ category, count }))
    .sort((a, b) => b.count - a.count);
}
