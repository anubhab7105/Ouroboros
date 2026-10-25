import { cleanParams, endpoints } from '@/lib/api';
import { get } from '@/lib/apiClient';
import type {
  DashboardMetrics,
  DashboardOverview,
  DashboardQueues,
  DashboardStatus,
  DashboardTrends,
} from '@/types/dashboard';

/**
 * Dashboard reads.
 *
 * The API takes an explicit `date_from`/`date_to` pair rather than a day
 * count, so the day count the UI offers is converted here, in one place. The
 * server echoes back the window it used — including whether it fell back to a
 * default or clamped the span — and the UI renders that echo rather than its
 * own request, so a clamped window is visible instead of silently wrong.
 */

export interface WindowRange {
  date_from: string;
  date_to: string;
}

/**
 * Turn a day count into a UTC-calendar range ending now.
 *
 * `date_to` is *now* rather than end-of-day: a window ending at midnight
 * tomorrow would include a few hours that have not happened, and the rate
 * figures would be divided by a span longer than the data covers. The start
 * is the first UTC date in the selection so daily trends contain exactly the
 * requested number of buckets, even when `asOf` is near midnight.
 */
export function windowFromDays(days: number, asOf: Date = new Date()): WindowRange {
  const end = new Date(asOf.getTime());
  const start = new Date(
    Date.UTC(end.getUTCFullYear(), end.getUTCMonth(), end.getUTCDate() - days + 1),
  );

  return { date_from: start.toISOString(), date_to: end.toISOString() };
}

export async function fetchDashboardStatus(): Promise<DashboardStatus> {
  return get<DashboardStatus>(endpoints.dashboard.status());
}

export async function fetchOverview(
  range: WindowRange,
  topLimit?: number,
): Promise<DashboardOverview> {
  return get<DashboardOverview>(endpoints.dashboard.overview(), {
    params: cleanParams({ ...range, top_limit: topLimit }),
  });
}

export async function fetchMetrics(range: WindowRange): Promise<DashboardMetrics> {
  return get<DashboardMetrics>(endpoints.dashboard.metrics(), { params: cleanParams(range) });
}

export async function fetchQueues(topLimit?: number): Promise<DashboardQueues> {
  return get<DashboardQueues>(endpoints.dashboard.queues(), {
    params: cleanParams({ top_limit: topLimit }),
  });
}

export async function fetchTrends(range: WindowRange): Promise<DashboardTrends> {
  return get<DashboardTrends>(endpoints.dashboard.trends(), { params: cleanParams(range) });
}
