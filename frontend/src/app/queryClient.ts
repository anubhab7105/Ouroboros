import { QueryClient } from '@tanstack/react-query';

import { isRetryable, normaliseError } from '@/lib/apiClient';

/**
 * React Query configuration.
 *
 * The defaults are tuned for an investigative tool where staleness has a cost:
 *
 * - **`staleTime` is 30 seconds, not zero.** Navigating between an alert, its
 *   account and the graph re-reads the same records constantly; refetching all
 *   of them on every mount makes the app feel slow without telling the analyst
 *   anything new.
 *
 * - **`refetchOnWindowFocus` is off.** An analyst alt-tabs to a case note or a
 *   spreadsheet dozens of times an hour. Refetching on every return would
 *   re-sort a queue they were part-way through reading.
 *
 * - **Retries only when retrying can help.** A 403 or a 422 will return the
 *   same answer three times; retrying it just delays the error the user needs
 *   to see. Network failures and 5xx do get retried.
 *
 * - **Mutations never retry.** Every mutation here changes investigation
 *   state: a retried case transition or evidence attachment could duplicate
 *   an action whose first attempt actually succeeded.
 */

const MAX_QUERY_RETRIES = 2;

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 30_000,
        gcTime: 5 * 60_000,
        refetchOnWindowFocus: false,
        refetchOnReconnect: true,
        retry: (failureCount, error) => {
          if (failureCount >= MAX_QUERY_RETRIES) return false;
          return isRetryable(error);
        },
        retryDelay: (attempt) => Math.min(1_000 * 2 ** attempt, 8_000),
      },
      mutations: {
        // Never automatically; see the note above.
        retry: false,
      },
    },
  });
}

export const queryClient = createQueryClient();

/** Discard all cached data. Called on sign-out so the next user sees nothing. */
export function resetQueryCache(): void {
  queryClient.clear();
}

/** True when an error should not be surfaced as a page-level failure. */
export function isExpectedQueryError(error: unknown): boolean {
  const { status } = normaliseError(error);
  // 401 is handled by the client interceptor (redirect); 403 renders its own
  // permission-denied state rather than a generic error page.
  return status === 401 || status === 403;
}
