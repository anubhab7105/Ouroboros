import { cleanParams, endpoints, pageParams } from '@/lib/api';
import { get } from '@/lib/apiClient';
import type {
  Account,
  AccountAssessment,
  AccountFilters,
  AccountListResponse,
  AccountSummary,
  AssessmentHistoryResponse,
  EntityLinkListResponse,
} from '@/types/account';
import type { AlertListResponse } from '@/types/alert';
import type { PageQuery } from '@/types/common';
import type { ComplaintCorrelationListResponse } from '@/types/complaint';

/**
 * Account reads.
 *
 * `include_latest_assessment` defaults to **on** in `fetchAccounts`, because
 * without it every row shows "Not assessed" — which looks like a finding about
 * the data rather than a consequence of the request. The flag costs the server
 * one join, which is cheaper than an analyst drawing the wrong conclusion.
 */

export async function fetchAccounts(
  page: PageQuery & { filters: AccountFilters },
): Promise<AccountListResponse> {
  const { filters, ...rest } = page;

  return get<AccountListResponse>(endpoints.accounts.list(), {
    params: {
      ...pageParams(rest),
      ...cleanParams({ include_latest_assessment: true, ...filters }),
    },
  });
}

export async function fetchAccount(id: string): Promise<Account> {
  return get<Account>(endpoints.accounts.detail(id));
}

/**
 * Windowed activity for one account.
 *
 * The window is the server's `date_from`/`date_to` pair. Omitting both lets
 * the server apply its default, and the response echoes back which window it
 * used — which is what the UI displays, rather than the one it asked for.
 */
export async function fetchAccountSummary(
  id: string,
  options: { date_from?: string; date_to?: string; currency?: string } = {},
): Promise<AccountSummary> {
  return get<AccountSummary>(endpoints.accounts.summary(id), {
    params: cleanParams(options),
  });
}

/**
 * The account's assessment, with its rule hits and indicators.
 *
 * `as_of` reproduces a past assessment: features saw only data strictly before
 * that instant, so an assessment pulled for last month is correct about last
 * month rather than a re-score with today's knowledge.
 */
export async function fetchAccountAssessment(
  id: string,
  asOf?: string,
): Promise<AccountAssessment> {
  return get<AccountAssessment>(endpoints.accounts.assessment(id), {
    params: cleanParams({ as_of: asOf }),
  });
}

export async function fetchAssessmentHistory(
  id: string,
  page: PageQuery & { scoring_mode?: string; risk_band?: string } = {},
): Promise<AssessmentHistoryResponse> {
  const { scoring_mode, risk_band, ...rest } = page;

  return get<AssessmentHistoryResponse>(endpoints.accounts.assessments(id), {
    params: { ...pageParams(rest), ...cleanParams({ scoring_mode, risk_band }) },
  });
}

export async function fetchAccountAlerts(
  id: string,
  page: PageQuery & { state?: string; priority?: string } = {},
): Promise<AlertListResponse> {
  const { state, priority, ...rest } = page;

  return get<AlertListResponse>(endpoints.accounts.alerts(id), {
    params: { ...pageParams(rest), ...cleanParams({ state, priority }) },
  });
}

export async function fetchAccountEntities(
  id: string,
  page: PageQuery & {
    entity_type?: string;
    verification_state?: string;
    match_method?: string;
    as_of?: string;
  } = {},
): Promise<EntityLinkListResponse> {
  const { entity_type, verification_state, match_method, as_of, ...rest } = page;

  return get<EntityLinkListResponse>(endpoints.accounts.entities(id), {
    params: {
      ...pageParams(rest),
      ...cleanParams({ entity_type, verification_state, match_method, as_of }),
    },
  });
}

export async function fetchAccountCorrelations(
  id: string,
  page: PageQuery & {
    match_tier?: number;
    review_state?: string;
    deterministic?: boolean;
  } = {},
): Promise<ComplaintCorrelationListResponse> {
  const { match_tier, review_state, deterministic, ...rest } = page;

  return get<ComplaintCorrelationListResponse>(endpoints.accounts.complaintCorrelations(id), {
    params: {
      ...pageParams(rest),
      ...cleanParams({ match_tier, review_state, deterministic }),
    },
  });
}
