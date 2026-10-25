import clsx from 'clsx';
import type { ReactNode } from 'react';

export interface KeyValueEntry {
  label: string;
  value: ReactNode;
  /** Monospace the value, for identifiers and hashes. */
  mono?: boolean;
  /** Give the row the full width, for long text. */
  wide?: boolean;
  help?: string;
}

export interface KeyValueListProps {
  entries: KeyValueEntry[];
  columns?: 1 | 2 | 3 | 4;
  className?: string;
}

/**
 * A definition list for record detail.
 *
 * Rendered as `<dl>` rather than a table: these are label/value pairs about
 * one record, not rows of comparable things, and a screen reader announces a
 * definition list correctly where a one-row table does not.
 */
export function KeyValueList({ entries, columns = 2, className }: KeyValueListProps) {
  return (
    <dl
      className={clsx(
        'grid gap-x-6 gap-y-3',
        columns === 1 && 'grid-cols-1',
        columns === 2 && 'grid-cols-1 sm:grid-cols-2',
        columns === 3 && 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-3',
        columns === 4 && 'grid-cols-2 sm:grid-cols-2 lg:grid-cols-4',
        className,
      )}
    >
      {entries.map((entry) => (
        <div key={entry.label} className={clsx('min-w-0', entry.wide && 'sm:col-span-full')}>
          <dt
            className="text-2xs font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400"
            title={entry.help}
          >
            {entry.label}
          </dt>
          <dd
            className={clsx(
              'mt-0.5 break-words text-xs text-ink-900 dark:text-ink-100',
              entry.mono && 'mg-id',
            )}
          >
            {entry.value === null || entry.value === undefined || entry.value === '' ? (
              <span className="text-ink-400 dark:text-ink-500">—</span>
            ) : (
              entry.value
            )}
          </dd>
        </div>
      ))}
    </dl>
  );
}
