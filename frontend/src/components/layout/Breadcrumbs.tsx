import clsx from 'clsx';
import { Link, useLocation } from 'react-router-dom';

import { truncateId } from '@/lib/formatters';
import { SECTION_LABELS } from '@/routes/paths';

export interface BreadcrumbsProps {
  className?: string;
}

/**
 * Breadcrumbs derived from the URL.
 *
 * Deriving them rather than passing them in means a page can never render a
 * trail that disagrees with the address bar. Identifier segments are
 * truncated in the middle, because account and transaction ids share long
 * prefixes and a head-truncated id tells the reader nothing.
 */
export function Breadcrumbs({ className }: BreadcrumbsProps) {
  const { pathname } = useLocation();
  const segments = pathname.split('/').filter(Boolean);

  if (segments.length === 0) return null;

  const crumbs = segments.map((segment, index) => {
    const href = '/' + segments.slice(0, index + 1).join('/');
    const known = SECTION_LABELS[segment];

    return {
      href,
      label: known ?? truncateId(decodeURIComponent(segment), 6),
      isLast: index === segments.length - 1,
    };
  });

  return (
    <nav aria-label="Breadcrumb" className={clsx('min-w-0', className)}>
      <ol className="flex flex-wrap items-center gap-1 text-2xs text-ink-500 dark:text-ink-400">
        {crumbs.map((crumb) => (
          <li key={crumb.href} className="flex items-center gap-1">
            {crumb.isLast ? (
              <span aria-current="page" className="font-medium text-ink-700 dark:text-ink-200">
                {crumb.label}
              </span>
            ) : (
              <>
                <Link
                  to={crumb.href}
                  className="rounded hover:text-ink-800 hover:underline dark:hover:text-ink-100"
                >
                  {crumb.label}
                </Link>
                <span aria-hidden="true" className="text-ink-300 dark:text-ink-600">
                  /
                </span>
              </>
            )}
          </li>
        ))}
      </ol>
    </nav>
  );
}
