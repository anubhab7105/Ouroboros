import clsx from 'clsx';
import { useMemo, type ReactNode } from 'react';

import { EmptyState } from './EmptyState';
import { LoadingOverlay } from './LoadingOverlay';

export interface Column<T> {
  /** Stable key. Used for the sort parameter when `sortable` is set. */
  key: string;
  header: ReactNode;
  render: (row: T, index: number) => ReactNode;
  /** Allow sorting by this column. The key is sent to the API as `sort_by`. */
  sortable?: boolean;
  /** Right-align: use for amounts, counts and scores. */
  numeric?: boolean;
  width?: string;
  className?: string;
  /** Hide below the large breakpoint, for secondary columns. */
  hideOnSmall?: boolean;
}

export interface DataTableProps<T> {
  columns: Array<Column<T>>;
  rows: T[];
  rowKey: (row: T, index: number) => string;
  isLoading?: boolean;
  /** True while refetching with data already on screen. */
  isRefetching?: boolean;
  emptyTitle?: string;
  emptyMessage?: string;
  emptyAction?: ReactNode;
  onRowClick?: (row: T) => void;
  selectedKey?: string | null;
  sortBy?: string | null;
  sortOrder?: 'asc' | 'desc';
  onSortChange?: (key: string, order: 'asc' | 'desc') => void;
  className?: string;
  /** Caption for assistive tech describing what the table contains. */
  caption?: string;
  /** Number of skeleton rows to show on first load. */
  skeletonRows?: number;
}

/**
 * The dense data table used by every list view.
 *
 * Decisions worth knowing:
 *
 * - **Sorting is server-side.** The table only reports the requested column
 *   and direction. Sorting the current page in the browser would order 25 rows
 *   out of 4,000 and look like it ordered everything, which is worse than not
 *   offering it.
 *
 * - **A clickable row is also a focusable, keyboard-operable one.** Rows open
 *   detail panels, and a div with an onClick is unreachable by keyboard, so
 *   each row carries a tabindex and handles Enter and Space.
 *
 * - **Refetching dims rather than clears.** Replacing rows with a spinner on
 *   every poll loses the reader's place in a queue they were part-way through.
 *
 * - **First load shows skeleton rows,** so the page does not jump in height
 *   when the data lands.
 */
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  isLoading = false,
  isRefetching = false,
  emptyTitle = 'Nothing to show',
  emptyMessage,
  emptyAction,
  onRowClick,
  selectedKey,
  sortBy,
  sortOrder = 'desc',
  onSortChange,
  className,
  caption,
  skeletonRows = 8,
}: DataTableProps<T>) {
  const visibleColumns = useMemo(() => columns, [columns]);

  const handleSort = (column: Column<T>) => {
    if (!column.sortable || !onSortChange) return;

    // Clicking the active column flips direction; a new column starts
    // descending, which is what a reader wants from a score or a date.
    const nextOrder = sortBy === column.key && sortOrder === 'desc' ? 'asc' : 'desc';
    onSortChange(column.key, nextOrder);
  };

  if (isLoading) {
    return (
      <div className={clsx('overflow-x-auto', className)}>
        <table className="mg-table">
          {caption ? <caption className="mg-visually-hidden">{caption}</caption> : null}
          <thead>
            <tr>
              {visibleColumns.map((column) => (
                <th
                  key={column.key}
                  scope="col"
                  style={column.width ? { width: column.width } : undefined}
                  className={clsx(column.hideOnSmall && 'hidden lg:table-cell')}
                >
                  {column.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {Array.from({ length: skeletonRows }).map((_, rowIndex) => (
              <tr key={`skeleton-${rowIndex}`}>
                {visibleColumns.map((column) => (
                  <td
                    key={column.key}
                    className={clsx(column.hideOnSmall && 'hidden lg:table-cell')}
                  >
                    <div className="mg-skeleton h-3.5 w-full" />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
        <span className="mg-visually-hidden" role="status">
          Loading table data
        </span>
      </div>
    );
  }

  if (rows.length === 0) {
    return (
      <EmptyState
        title={emptyTitle}
        message={emptyMessage}
        action={emptyAction}
        className={className}
      />
    );
  }

  return (
    <div className={clsx('relative overflow-x-auto', className)}>
      {isRefetching ? <LoadingOverlay message="Updating" /> : null}

      <table className="mg-table">
        {caption ? <caption className="mg-visually-hidden">{caption}</caption> : null}

        <thead>
          <tr>
            {visibleColumns.map((column) => {
              const isActive = sortBy === column.key;

              return (
                <th
                  key={column.key}
                  scope="col"
                  style={column.width ? { width: column.width } : undefined}
                  aria-sort={
                    isActive ? (sortOrder === 'asc' ? 'ascending' : 'descending') : undefined
                  }
                  className={clsx(
                    column.numeric && 'text-right',
                    column.hideOnSmall && 'hidden lg:table-cell',
                    column.className,
                  )}
                >
                  {column.sortable && onSortChange ? (
                    <button
                      type="button"
                      onClick={() => handleSort(column)}
                      className="inline-flex items-center gap-1 hover:text-ink-900 dark:hover:text-ink-50"
                    >
                      {column.header}
                      <span aria-hidden="true" className="text-2xs">
                        {isActive ? (sortOrder === 'asc' ? '▲' : '▼') : '↕'}
                      </span>
                    </button>
                  ) : (
                    column.header
                  )}
                </th>
              );
            })}
          </tr>
        </thead>

        <tbody>
          {rows.map((row, index) => {
            const key = rowKey(row, index);
            const clickable = Boolean(onRowClick);

            return (
              <tr
                key={key}
                aria-selected={selectedKey === key ? true : undefined}
                tabIndex={clickable ? 0 : undefined}
                role={clickable ? 'button' : undefined}
                onClick={clickable ? () => onRowClick?.(row) : undefined}
                onKeyDown={
                  clickable
                    ? (event) => {
                        if (event.key === 'Enter' || event.key === ' ') {
                          event.preventDefault();
                          onRowClick?.(row);
                        }
                      }
                    : undefined
                }
                className={clsx(clickable && 'cursor-pointer')}
              >
                {visibleColumns.map((column) => (
                  <td
                    key={column.key}
                    className={clsx(
                      column.numeric && 'text-right tabular',
                      column.hideOnSmall && 'hidden lg:table-cell',
                      column.className,
                    )}
                  >
                    {column.render(row, index)}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
