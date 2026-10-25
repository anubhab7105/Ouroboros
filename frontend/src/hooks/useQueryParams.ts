import { useCallback, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';

/**
 * Read and write filter state in the URL.
 *
 * Filters live in the query string rather than in component state so that a
 * filtered view is linkable. An investigator sharing "the critical unassigned
 * alerts I am looking at" should be able to paste a URL, and pressing back
 * should restore the previous filter rather than an empty list.
 *
 * Setting a parameter to undefined or '' removes it, which keeps the URL clean
 * and matches the API's treatment of an absent filter.
 */
/**
 * URL parameters the interface owns rather than the API.
 *
 * Declared so that they are discoverable in one place and cannot be confused
 * with API filter names. They are never sent to the server.
 */
export interface UiQueryParams {
  /** Which tab a detail view opens on. */
  tab?: string;
  /** Which tab the alert drawer opens on. */
  alert_tab?: string;
  /** The case a report is being previewed for. */
  case_id?: string;
  /** The dashboard window, in days. */
  window_days?: string;
  /** The root account of the network view. */
  root?: string;
  /** The correlation a complaint view should scroll to. */
  correlation_id?: string;
  /** The complaint a drawer should open. */
  complaint_id?: string;
}

export function useQueryParams<T extends Record<string, string | number | boolean | undefined>>() {
  const [searchParams, setSearchParams] = useSearchParams();

  const params = useMemo(() => {
    const out: Record<string, string> = {};
    searchParams.forEach((value, key) => {
      out[key] = value;
    });
    return out;
  }, [searchParams]);

  const setParams = useCallback(
    (next: Partial<T>, options: { replace?: boolean; resetPage?: boolean } = {}) => {
      setSearchParams(
        (current) => {
          const updated = new URLSearchParams(current);

          for (const [key, value] of Object.entries(next)) {
            if (value === undefined || value === null || value === '' || value === false) {
              updated.delete(key);
            } else {
              updated.set(key, String(value));
            }
          }

          // Changing a filter must reset to page 1: staying on page 7 of a
          // newly filtered list usually shows an empty page, which reads as
          // "no results" rather than "wrong page".
          if (options.resetPage !== false && !('page' in next)) {
            updated.delete('page');
          }

          return updated;
        },
        { replace: options.replace ?? true },
      );
    },
    [setSearchParams],
  );

  const clearParams = useCallback(
    (keys?: string[]) => {
      setSearchParams(
        (current) => {
          if (!keys) return new URLSearchParams();

          const updated = new URLSearchParams(current);
          keys.forEach((key) => updated.delete(key));
          updated.delete('page');
          return updated;
        },
        { replace: true },
      );
    },
    [setSearchParams],
  );

  const getString = useCallback(
    (key: string, fallback?: string): string | undefined => params[key] ?? fallback,
    [params],
  );

  const getNumber = useCallback(
    (key: string, fallback?: number): number | undefined => {
      const raw = params[key];
      if (raw === undefined) return fallback;
      const parsed = Number.parseInt(raw, 10);
      return Number.isFinite(parsed) ? parsed : fallback;
    },
    [params],
  );

  const getBoolean = useCallback(
    (key: string, fallback = false): boolean => {
      const raw = params[key];
      if (raw === undefined) return fallback;
      return raw === 'true' || raw === '1';
    },
    [params],
  );

  /** Number of active filters, excluding pagination and sort. */
  const activeFilterCount = useMemo(() => {
    const ignored = new Set(['page', 'page_size', 'sort_by', 'sort_order']);
    return Object.keys(params).filter((key) => !ignored.has(key)).length;
  }, [params]);

  return {
    params,
    setParams,
    clearParams,
    getString,
    getNumber,
    getBoolean,
    activeFilterCount,
  };
}
