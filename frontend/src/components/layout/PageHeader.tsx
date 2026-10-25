import clsx from 'clsx';
import type { ReactNode } from 'react';

import { Breadcrumbs } from './Breadcrumbs';

export interface PageHeaderProps {
  title: ReactNode;
  /** One line saying what this page is for and what it is not. */
  description?: ReactNode;
  actions?: ReactNode;
  /** Rendered under the title: filter chips, tabs, a status line. */
  children?: ReactNode;
  showBreadcrumbs?: boolean;
  className?: string;
}

/** The title block every page opens with. */
export function PageHeader({
  title,
  description,
  actions,
  children,
  showBreadcrumbs = true,
  className,
}: PageHeaderProps) {
  return (
    <header className={clsx('mb-5', className)}>
      {showBreadcrumbs ? <Breadcrumbs className="mb-2" /> : null}

      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-xl font-semibold tracking-tight text-ink-900 dark:text-ink-50">
            {title}
          </h1>
          {description ? (
            <p className="mt-1 max-w-3xl text-xs leading-relaxed text-ink-600 dark:text-ink-300">
              {description}
            </p>
          ) : null}
        </div>

        {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
      </div>

      {children ? <div className="mt-4">{children}</div> : null}
    </header>
  );
}
