import clsx from 'clsx';
import type { ReactNode } from 'react';

export interface CardProps {
  children: ReactNode;
  title?: ReactNode;
  description?: ReactNode;
  /** Controls rendered at the top right: filters, a refresh, an export. */
  actions?: ReactNode;
  /** Caveats from the API. Rendered as a footer so they travel with the data. */
  caveats?: string[];
  className?: string;
  bodyClassName?: string;
  /** Remove body padding, for a card whose body is a full-bleed table. */
  flush?: boolean;
}

/**
 * The standard panel.
 *
 * `caveats` is a first-class prop rather than something each page remembers to
 * render. Most API responses that carry a risk judgement also carry their
 * interpretation limits, and a panel that shows the numbers while dropping the
 * limits is how a prioritisation score gets read as a finding of fact.
 */
export function Card({
  children,
  title,
  description,
  actions,
  caveats,
  className,
  bodyClassName,
  flush = false,
}: CardProps) {
  const hasHeader = Boolean(title || description || actions);

  return (
    <section className={clsx('mg-card flex flex-col', className)}>
      {hasHeader ? (
        <header className="flex items-start justify-between gap-3 border-b border-ink-200 px-4 py-3 dark:border-ink-700">
          <div className="min-w-0">
            {title ? (
              <h2 className="truncate text-sm font-semibold text-ink-900 dark:text-ink-50">
                {title}
              </h2>
            ) : null}
            {description ? (
              <p className="mt-0.5 text-xs text-ink-500 dark:text-ink-400">{description}</p>
            ) : null}
          </div>
          {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
        </header>
      ) : null}

      <div className={clsx('relative flex-1', !flush && 'p-4', bodyClassName)}>{children}</div>

      {caveats && caveats.length > 0 ? (
        <footer className="border-t border-ink-200 bg-ink-50 px-4 py-2.5 dark:border-ink-700 dark:bg-ink-800/60">
          <p className="mb-1 text-2xs font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
            How to read this
          </p>
          <ul className="space-y-1">
            {caveats.map((caveat) => (
              <li key={caveat} className="text-2xs leading-relaxed text-ink-600 dark:text-ink-300">
                {caveat}
              </li>
            ))}
          </ul>
        </footer>
      ) : null}
    </section>
  );
}
