import { Link } from 'react-router-dom';

import { Card } from '@/components/common/Card';
import { useAuth } from '@/features/auth/useAuth';
import { ROLE_DESCRIPTIONS, ROLE_LABELS } from '@/lib/permissions';
import { paths } from '@/routes/paths';

/**
 * Not permitted.
 *
 * Says which role the user holds and what that role is for, rather than only
 * that access was refused. The common cause is a link shared by a colleague
 * with broader rights, and the useful next step is knowing who to ask.
 */
export default function ForbiddenPage() {
  const { user } = useAuth();

  return (
    <Card title="You do not have access to that">
      {user ? (
        <>
          <p className="text-xs leading-relaxed text-ink-700 dark:text-ink-200">
            You are signed in as <span className="font-medium">{user.username}</span> with the{' '}
            <span className="font-medium">{ROLE_LABELS[user.role] ?? user.role}</span> role.
          </p>
          <p className="mt-1.5 text-xs leading-relaxed text-ink-600 dark:text-ink-300">
            {ROLE_DESCRIPTIONS[user.role]}
          </p>
          <p className="mt-2 text-xs leading-relaxed text-ink-600 dark:text-ink-300">
            If this page is part of your work, an administrator can change your role. Role changes
            are recorded in the audit trail.
          </p>
        </>
      ) : (
        <p className="text-xs text-ink-700 dark:text-ink-200">You are not signed in.</p>
      )}

      <Link
        to={paths.dashboard}
        className="mt-4 inline-block text-xs font-medium text-accent-700 hover:underline dark:text-accent-300"
      >
        Back to the dashboard
      </Link>
    </Card>
  );
}
