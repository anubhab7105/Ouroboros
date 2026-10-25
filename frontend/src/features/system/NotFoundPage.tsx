import { Link, useLocation } from 'react-router-dom';

import { Card } from '@/components/common/Card';
import { paths } from '@/routes/paths';

/**
 * Not found.
 *
 * The path is echoed back. An investigator who followed a link from a report
 * or a colleague's message needs to know *which* identifier did not resolve —
 * often it is a truncated id pasted one character short.
 */
export default function NotFoundPage() {
  const { pathname } = useLocation();

  return (
    <Card title="That page does not exist">
      <p className="text-xs leading-relaxed text-ink-700 dark:text-ink-200">
        Nothing is served at{' '}
        <span className="break-all font-mono text-2xs">{pathname}</span>.
      </p>

      <p className="mt-2 text-xs leading-relaxed text-ink-600 dark:text-ink-300">
        If you followed a link containing a record identifier, check that it was copied in full —
        identifiers are long and are often truncated when pasted from a chat or a PDF.
      </p>

      <div className="mt-4 flex flex-wrap gap-3 text-xs">
        <Link to={paths.dashboard} className="font-medium text-accent-700 hover:underline dark:text-accent-300">
          Dashboard
        </Link>
        <Link to={paths.alerts} className="font-medium text-accent-700 hover:underline dark:text-accent-300">
          Alert queue
        </Link>
        <Link to={paths.cases} className="font-medium text-accent-700 hover:underline dark:text-accent-300">
          Cases
        </Link>
      </div>
    </Card>
  );
}
