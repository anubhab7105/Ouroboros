import { normaliseError, type NormalisedApiError } from './apiClient';

/**
 * Turn an API error into something an analyst can act on.
 *
 * The backend's messages are written for an operator and are usually good, so
 * they are shown as-is. What this adds is the *action*: a 403 and a 409 both
 * produce a readable sentence, but what the user should do next is completely
 * different, and a generic "something went wrong" wastes their time.
 */

export interface FriendlyError {
  title: string;
  message: string;
  /** What to do next, when there is a useful answer. */
  action?: string;
  requestId?: string;
  /** Field-level problems, for inline form errors. */
  fieldErrors: Record<string, string>;
  isRetryable: boolean;
  /** True when the user should be shown the sign-in screen. */
  requiresReauth: boolean;
  status: number;
  code: string;
}

const TITLES: Record<number, string> = {
  0: 'Cannot reach the server',
  400: 'Request rejected',
  401: 'Session expired',
  403: 'Not permitted',
  404: 'Not found',
  409: 'Conflict',
  410: 'No longer available',
  413: 'Too large',
  415: 'Unsupported format',
  422: 'Validation failed',
  429: 'Too many requests',
  500: 'Server error',
  502: 'Backend unavailable',
  503: 'Service unavailable',
  504: 'Request timed out',
};

const ACTIONS: Record<number, string> = {
  0: 'Check that the backend is running, then retry.',
  401: 'Sign in again to continue.',
  403: 'Ask an administrator if you need this permission.',
  404: 'The record may have been removed. Return to the list and refresh.',
  409: 'Someone else may have changed this record. Reload and try again.',
  422: 'Correct the highlighted fields and resubmit.',
  429: 'Wait a moment before retrying.',
  500: 'Retry shortly. If it persists, quote the request id to support.',
  503: 'A required service is unavailable. Retry shortly.',
  504: 'The operation took too long. Narrow the date range or the number of accounts.',
};

/**
 * Error codes the backend raises whose cause is specific enough to deserve a
 * tailored next step.
 */
const CODE_ACTIONS: Record<string, string> = {
  service_unavailable:
    'A required service is not configured. Check the backend logs for which module is missing.',
  model_not_available:
    'No trained model is active. Scoring falls back to the transparent heuristic scorer.',
  report_generation_unavailable:
    'PDF rendering is unavailable. Request the report as JSON instead.',
  graph_limit_exceeded:
    'The traversal hit its configured limit. Reduce the hop count or narrow the date span.',
  invalid_case_transition:
    'That transition is not legal from the case’s current status. The allowed options are listed on the case.',
  idempotency_conflict:
    'This idempotency key was already used with a different payload. Use a new key.',
  ingestion_referential_integrity:
    'The batch references records that do not exist. Import the accounts before the transactions.',
  feature_computation_failed:
    'Feature construction failed, so no account could be scored. Check the analysis run error summary.',
  synthetic_data_required:
    'This operation is restricted to synthetic datasets in this deployment.',
};

export function toFriendlyError(error: unknown): FriendlyError {
  const normalised: NormalisedApiError = normaliseError(error);

  const fieldErrors: Record<string, string> = {};

  for (const detail of normalised.details) {
    if (detail.field) {
      // Strip FastAPI's `body.` prefix so the key matches the form field name.
      const key = detail.field.replace(/^body\./, '');
      fieldErrors[key] = detail.message;
    }
  }

  const action = CODE_ACTIONS[normalised.code] ?? ACTIONS[normalised.status];

  return {
    title: TITLES[normalised.status] ?? 'Something went wrong',
    message: normalised.message,
    action,
    requestId: normalised.requestId,
    fieldErrors,
    isRetryable:
      normalised.isNetworkError || normalised.status >= 500 || normalised.status === 429,
    requiresReauth: normalised.status === 401,
    status: normalised.status,
    code: normalised.code,
  };
}

/** One-line message for a toast. */
export function errorMessage(error: unknown): string {
  const friendly = toFriendlyError(error);
  return friendly.action ? `${friendly.message} ${friendly.action}` : friendly.message;
}
