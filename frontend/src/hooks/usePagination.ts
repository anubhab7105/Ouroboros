import { useCallback, useMemo } from 'react';

import { DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE } from '@/lib/constants';
import { useQueryParams } from './useQueryParams';

/**
 * Pagination state, held in the URL.
 *
 * `pageSize` is clamped to the server's cap here as well as on the server.
 * Asking for 5,000 rows and silently receiving 200 makes the pager's maths
 * wrong, so the client agrees on the limit up front.
 */
export function usePagination(defaultPageSize: number = DEFAULT_PAGE_SIZE) {
  const { getNumber, setParams } = useQueryParams();

  const page = Math.max(1, getNumber('page', 1) ?? 1);
  const pageSize = Math.min(
    MAX_PAGE_SIZE,
    Math.max(1, getNumber('page_size', defaultPageSize) ?? defaultPageSize),
  );

  const setPage = useCallback(
    (next: number) => setParams({ page: Math.max(1, next) }, { resetPage: false }),
    [setParams],
  );

  const setPageSize = useCallback(
    (next: number) =>
      // Changing page size invalidates the current offset, so return to page 1.
      setParams({ page_size: Math.min(MAX_PAGE_SIZE, Math.max(1, next)), page: 1 }, { resetPage: false }),
    [setParams],
  );

  return useMemo(
    () => ({ page, pageSize, setPage, setPageSize }),
    [page, pageSize, setPage, setPageSize],
  );
}
