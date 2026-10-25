import clsx from 'clsx';

import { PAGE_SIZE_OPTIONS } from '@/lib/constants';
import { formatCount } from '@/lib/amounts';
import type { PageInfo } from '@/types/common';

import { Button } from './Button';
import { Select } from './Select';

export interface PaginationProps {
  /** The list response's own pagination fields, minus the rows. */
  meta: PageInfo;
  onPageChange: (page: number) => void;
  onPageSizeChange?: (pageSize: number) => void;
  /** The page size this view asked for, to detect a server-side cap. */
  requestedPageSize?: number;
  /**
   * Set on lists ordered by score or recency. New analysis results genuinely
   * re-rank those, so rows move between pages and a repeat sighting is not a
   * bug.
   */
  orderingIsVolatile?: boolean;
  className?: string;
}

/**
 * The pager for a list view.
 *
 * Two honesty details:
 *
 * - When the server capped a larger requested page size, that is stated. The
 *   cap is invisible in the response itself — `page_size` simply comes back
 *   smaller — so the view passes what it asked for and the difference is
 *   surfaced rather than silently changing the arithmetic under the user.
 *
 * - On a score- or recency-ordered list, a note says rows can move between
 *   pages. New analysis results genuinely re-rank the queue, and an analyst
 *   who sees a row twice should know why rather than assume a bug.
 */
export function Pagination({
  meta,
  onPageChange,
  onPageSizeChange,
  requestedPageSize,
  orderingIsVolatile = false,
  className,
}: PaginationProps) {
  const { page, page_size: pageSize, total, total_pages: totalPages } = meta;

  const firstRow = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const lastRow = Math.min(page * pageSize, total);

  // The server sends no has_next/has_previous, so these come from its own
  // page arithmetic rather than from a second count the client keeps.
  const hasPrevious = page > 1;
  const hasNext = page < totalPages;

  // A cap is visible only by comparing what was asked for with what came back.
  const wasCapped = Boolean(requestedPageSize && requestedPageSize > pageSize);

  return (
    <nav
      aria-label="Pagination"
      className={clsx(
        'flex flex-wrap items-center justify-between gap-3 border-t border-ink-200 px-4 py-2.5 dark:border-ink-700',
        className,
      )}
    >
      <div className="flex flex-col gap-0.5">
        <p className="text-xs text-ink-600 dark:text-ink-300">
          {total === 0 ? (
            'No rows'
          ) : (
            <>
              <span className="tabular font-medium">{formatCount(firstRow)}</span>–
              <span className="tabular font-medium">{formatCount(lastRow)}</span> of{' '}
              <span className="tabular font-medium">{formatCount(total)}</span>
            </>
          )}
        </p>

        {wasCapped ? (
          <p className="text-2xs text-ink-500 dark:text-ink-400">
            Showing {pageSize} per page; {requestedPageSize} was requested but the server caps page
            size.
          </p>
        ) : null}

        {orderingIsVolatile ? (
          <p className="text-2xs text-ink-500 dark:text-ink-400">
            Ordering changes as new analysis results land, so rows can move between pages.
          </p>
        ) : null}
      </div>

      <div className="flex items-center gap-2">
        {onPageSizeChange ? (
          <label className="flex items-center gap-1.5 text-xs text-ink-600 dark:text-ink-300">
            <span className="whitespace-nowrap">Per page</span>
            <Select
              aria-label="Rows per page"
              value={String(pageSize)}
              onChange={(event) => onPageSizeChange(Number(event.target.value))}
              options={PAGE_SIZE_OPTIONS.map((size) => ({
                value: String(size),
                label: String(size),
              }))}
              className="w-20 py-1 text-xs"
            />
          </label>
        ) : null}

        <div className="flex items-center gap-1">
          <Button
            size="sm"
            variant="secondary"
            onClick={() => onPageChange(1)}
            disabled={!hasPrevious}
            aria-label="First page"
          >
            «
          </Button>
          <Button
            size="sm"
            variant="secondary"
            onClick={() => onPageChange(page - 1)}
            disabled={!hasPrevious}
          >
            Previous
          </Button>

          <span className="px-2 text-xs tabular text-ink-600 dark:text-ink-300">
            {page} / {Math.max(1, totalPages)}
          </span>

          <Button
            size="sm"
            variant="secondary"
            onClick={() => onPageChange(page + 1)}
            disabled={!hasNext}
          >
            Next
          </Button>
          <Button
            size="sm"
            variant="secondary"
            onClick={() => onPageChange(Math.max(1, totalPages))}
            disabled={!hasNext}
            aria-label="Last page"
          >
            »
          </Button>
        </div>
      </div>
    </nav>
  );
}
