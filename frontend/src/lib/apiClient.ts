import axios, {
  AxiosError,
  type AxiosInstance,
  type AxiosRequestConfig,
  type AxiosResponse,
  type InternalAxiosRequestConfig,
} from 'axios';

import { API_BASE_URL, API_TIMEOUT_MS } from './environment';
import { clearSession, getToken, isTokenExpired } from './auth';

/**
 * The single axios instance every request goes through.
 *
 * Behaviour that matters:
 *
 * - **A locally expired token is cleared before the request is sent.** Letting
 *   it go and handling the 401 works, but it means every page load after an
 *   expiry fires a round of doomed requests first.
 *
 * - **A 401 clears the session and redirects once.** `redirecting` guards
 *   against a page that fired six parallel queries producing six redirects.
 *
 * - **A 403 does not log the user out.** It means this user may not do this
 *   thing, which is different from not being signed in. Logging them out on a
 *   permission error is a confusing and common bug.
 *
 * - **Request ids are preserved.** The backend returns one on every response
 *   and error; it is attached to the thrown error so the UI can show it and a
 *   user can quote it in a support report.
 */

const REQUEST_ID_HEADER = 'x-request-id';

/** Status codes that must never be retried: the outcome will not change. */
const NON_RETRYABLE = new Set([400, 401, 403, 404, 405, 409, 410, 413, 415, 422]);

let redirecting = false;

export interface NormalisedApiError {
  status: number;
  /** Stable machine-readable code from the backend, when it supplied one. */
  code: string;
  message: string;
  requestId?: string;
  details: Array<{ field?: string | null; code?: string | null; message: string }>;
  /** True for a network failure or timeout rather than an HTTP response. */
  isNetworkError: boolean;
  isTimeout: boolean;
}

export class ApiError extends Error implements NormalisedApiError {
  readonly status: number;
  readonly code: string;
  readonly requestId?: string;
  readonly details: NormalisedApiError['details'];
  readonly isNetworkError: boolean;
  readonly isTimeout: boolean;

  constructor(payload: NormalisedApiError) {
    super(payload.message);
    this.name = 'ApiError';
    this.status = payload.status;
    this.code = payload.code;
    this.requestId = payload.requestId;
    this.details = payload.details;
    this.isNetworkError = payload.isNetworkError;
    this.isTimeout = payload.isTimeout;
  }
}

function extractRequestId(response?: AxiosResponse): string | undefined {
  const header = response?.headers?.[REQUEST_ID_HEADER];
  if (typeof header === 'string' && header.length > 0) return header;

  const body = response?.data as { request_id?: unknown } | undefined;
  if (body && typeof body.request_id === 'string') return body.request_id;

  return undefined;
}

export function normaliseError(error: unknown): NormalisedApiError {
  if (error instanceof ApiError) return error;

  if (axios.isAxiosError(error)) {
    const axiosError = error as AxiosError<Record<string, unknown>>;
    const response = axiosError.response;
    const isTimeout = axiosError.code === 'ECONNABORTED' || axiosError.code === 'ETIMEDOUT';

    if (!response) {
      return {
        status: 0,
        code: isTimeout ? 'timeout' : 'network_error',
        message: isTimeout
          ? 'The request timed out. The server may be busy processing a large analysis.'
          : 'Could not reach the server. Check that the backend is running.',
        details: [],
        isNetworkError: true,
        isTimeout,
      };
    }

    const body = (response.data ?? {}) as {
      error?: unknown;
      message?: unknown;
      detail?: unknown;
      details?: unknown;
    };

    // FastAPI's own validation errors use `detail`; MULEGUARD's handler uses
    // `error`/`message`. Both shapes land here.
    const rawDetail = body.detail;
    const message =
      (typeof body.message === 'string' && body.message) ||
      (typeof rawDetail === 'string' && rawDetail) ||
      axiosError.message ||
      'The request failed.';

    const details = Array.isArray(body.details)
      ? (body.details as NormalisedApiError['details'])
      : Array.isArray(rawDetail)
        ? (rawDetail as Array<Record<string, unknown>>).map((item) => ({
            field: Array.isArray(item.loc) ? item.loc.join('.') : null,
            code: typeof item.type === 'string' ? item.type : null,
            message: typeof item.msg === 'string' ? item.msg : String(item),
          }))
        : [];

    return {
      status: response.status,
      code: typeof body.error === 'string' ? body.error : `http_${response.status}`,
      message,
      requestId: extractRequestId(response),
      details,
      isNetworkError: false,
      isTimeout: false,
    };
  }

  return {
    status: 0,
    code: 'unknown_error',
    message: error instanceof Error ? error.message : 'An unexpected error occurred.',
    details: [],
    isNetworkError: false,
    isTimeout: false,
  };
}

function createClient(): AxiosInstance {
  const instance = axios.create({
    baseURL: API_BASE_URL,
    timeout: API_TIMEOUT_MS,
    headers: { Accept: 'application/json' },
  });

  instance.interceptors.request.use((config: InternalAxiosRequestConfig) => {
    const token = getToken();

    if (token) {
      if (isTokenExpired()) {
        // Clear now rather than sending a request we know will 401.
        clearSession();
      } else {
        config.headers.Authorization = `Bearer ${token}`;
      }
    }

    // Only set a JSON content type when there is a body and it is not a form
    // upload; letting axios choose the boundary for FormData is required.
    if (config.data && !(config.data instanceof FormData)) {
      config.headers['Content-Type'] = 'application/json';
    }

    return config;
  });

  instance.interceptors.response.use(
    (response) => response,
    (error: unknown) => {
      const normalised = normaliseError(error);

      if (normalised.status === 401) {
        clearSession();

        // One redirect regardless of how many requests failed together.
        if (!redirecting && typeof window !== 'undefined') {
          const path = window.location.pathname;

          if (!path.startsWith('/login')) {
            redirecting = true;
            const next = encodeURIComponent(path + window.location.search);
            window.location.assign(`/login?next=${next}`);
          }
        }
      }

      // A 403 is deliberately left alone: the user is signed in, this action
      // is simply not theirs to take.
      return Promise.reject(new ApiError(normalised));
    },
  );

  return instance;
}

export const apiClient = createClient();

/** True when a failed request is worth retrying. */
export function isRetryable(error: unknown): boolean {
  const normalised = normaliseError(error);

  if (normalised.isNetworkError) return true;
  if (NON_RETRYABLE.has(normalised.status)) return false;

  return normalised.status >= 500;
}

export async function get<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
  const response = await apiClient.get<T>(url, config);
  return response.data;
}

export async function post<T>(
  url: string,
  body?: unknown,
  config?: AxiosRequestConfig,
): Promise<T> {
  const response = await apiClient.post<T>(url, body, config);
  return response.data;
}

export async function patch<T>(
  url: string,
  body?: unknown,
  config?: AxiosRequestConfig,
): Promise<T> {
  const response = await apiClient.patch<T>(url, body, config);
  return response.data;
}

export async function put<T>(url: string, body?: unknown, config?: AxiosRequestConfig): Promise<T> {
  const response = await apiClient.put<T>(url, body, config);
  return response.data;
}

export async function del<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
  const response = await apiClient.delete<T>(url, config);
  return response.data;
}

/**
 * Fetch a binary download (a report PDF) with its filename.
 *
 * The filename comes from `Content-Disposition` when the server sets one,
 * because the server builds a sanitised, convention-following name and the
 * client should not invent its own.
 */
export async function getBlob(
  url: string,
  config?: AxiosRequestConfig,
): Promise<{ blob: Blob; filename?: string; contentType: string }> {
  const response = await apiClient.get<Blob>(url, { ...config, responseType: 'blob' });
  const disposition = String(response.headers?.['content-disposition'] ?? '');
  const match = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(disposition);

  return {
    blob: response.data,
    filename: match?.[1] ? decodeURIComponent(match[1]) : undefined,
    contentType: String(response.headers?.['content-type'] ?? 'application/octet-stream'),
  };
}

/** Reset the redirect guard. Test-only. */
export function __resetRedirectGuard(): void {
  redirecting = false;
}
