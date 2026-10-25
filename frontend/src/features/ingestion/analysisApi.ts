import { cleanParams, endpoints, pageParams } from '@/lib/api';
import { get, post } from '@/lib/apiClient';
import type {
  AnalysisFilters,
  AnalysisRun,
  AnalysisRunListResponse,
  AnalysisRunRequest,
  AnalysisRunResults,
  AnalysisStatus,
} from '@/types/api';
import type { PageQuery } from '@/types/common';

/**
 * Analysis runs.
 *
 * `fetchAnalysisStatus` is worth reading before offering the run button:
 * `service_available` false means the analytical service is not wired up and
 * starting a run returns 503, and `require_trained_model` with no active model
 * means the same. Both are better reported before the click than after.
 */

export async function fetchAnalysisStatus(): Promise<AnalysisStatus> {
  return get<AnalysisStatus>(endpoints.analysis.status());
}

export async function fetchAnalysisRuns(
  page: PageQuery & { filters?: AnalysisFilters } = {},
): Promise<AnalysisRunListResponse> {
  const { filters = {}, ...rest } = page;

  return get<AnalysisRunListResponse>(endpoints.analysis.runs(), {
    params: { ...pageParams(rest), ...cleanParams(filters) },
  });
}

export async function fetchAnalysisRun(id: string): Promise<AnalysisRun> {
  return get<AnalysisRun>(endpoints.analysis.run(id));
}

export async function fetchAnalysisResults(
  id: string,
  page: PageQuery & {
    account_id?: string;
    scoring_mode?: string;
    risk_band?: string;
    alert_state?: string;
    alert_priority?: string;
  } = {},
): Promise<AnalysisRunResults> {
  const { account_id, scoring_mode, risk_band, alert_state, alert_priority, ...rest } = page;

  return get<AnalysisRunResults>(endpoints.analysis.results(id), {
    params: {
      ...pageParams(rest),
      ...cleanParams({ account_id, scoring_mode, risk_band, alert_state, alert_priority }),
    },
  });
}

export async function startAnalysisRun(body: AnalysisRunRequest): Promise<AnalysisRun> {
  return post<AnalysisRun>(endpoints.analysis.createRun(), body);
}

export async function cancelAnalysisRun(id: string): Promise<AnalysisRun> {
  return post<AnalysisRun>(endpoints.analysis.cancel(id));
}

/** True while a run may still change. */
export function isRunInFlight(run: AnalysisRun): boolean {
  return run.status === 'QUEUED' || run.status === 'RUNNING';
}
