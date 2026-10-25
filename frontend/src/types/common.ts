/**
 * Shared primitives, mirroring the response models declared inside the
 * endpoint modules under `app/api/v1/endpoints/`.
 *
 * **Pagination is flat.** Every list endpoint returns `items` alongside
 * `page`, `page_size`, `total`, `total_pages`, `sort_by` and `sort_order` at
 * the top level — there is no `meta` envelope and no `has_next` flag. The
 * pager derives "is there a next page" from `page < total_pages`, which is the
 * server's own arithmetic rather than a second source of truth.
 *
 * `page_size` is what the server actually applied. It can be smaller than
 * what was requested, because the server caps it, so the pager reads this
 * value and never its own request parameters.
 */

export type Iso8601 = string;

/** The shape every paginated endpoint returns. */
export interface PageResponse<T> {
  items: T[];
  page: number;
  page_size: number;
  total: number;
  total_pages: number;
  sort_by?: string | null;
  sort_order: string;
  /** Interpretation limits that travel with the data. Always render them. */
  caveats?: string[];
}

/** The pagination fields alone, for a pager that does not need the rows. */
export type PageInfo = Omit<PageResponse<unknown>, 'items'>;

/** Pull the pagination fields out of any list response. */
export function pageInfo(response: PageResponse<unknown> | undefined): PageInfo | undefined {
  if (!response) return undefined;

  const { items: _items, ...rest } = response;
  return rest;
}

/** The standard query parameters every list endpoint accepts. */
export interface PageQuery {
  page?: number;
  page_size?: number;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
}

export interface ErrorDetail {
  field?: string | null;
  code?: string | null;
  message: string;
}

export interface ApiErrorPayload {
  error: string;
  message: string;
  status_code: number;
  request_id?: string | null;
  details?: ErrorDetail[];
}

export interface MessageResponse {
  message: string;
  request_id?: string | null;
}

export interface HealthStatus {
  status: 'ok' | 'degraded' | 'unavailable' | string;
  version?: string | null;
  environment?: string | null;
  checks?: Record<string, unknown>;
  degraded_reasons?: string[];
}

/**
 * Enum-like unions.
 *
 * The server types most of these as plain `str` in its response models even
 * where a Python enum backs them, so a value outside the union is possible
 * when the backend adds one. Everything that renders them humanises an
 * unrecognised value rather than dropping the row.
 */
export type RiskBand = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type Priority = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type ScoringMode =
  | 'TRAINED_MODEL'
  | 'HEURISTIC_FALLBACK'
  | 'RULES_ONLY'
  | 'ML_DISABLED'
  | 'UNKNOWN';

export interface SortState {
  sortBy?: string;
  sortOrder: 'asc' | 'desc';
}

/**
 * A window as the backend reports it: two instants, not a day count.
 *
 * `defaulted` is set when the client sent no range and the server applied its
 * own default, which is worth showing — a figure computed over a window the
 * user did not choose should say so.
 */
export interface WindowInfo {
  date_from: Iso8601;
  date_to: Iso8601;
  defaulted?: boolean;
  default_window_days?: number;
  max_span_days?: number;
}
