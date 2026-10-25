import clsx from 'clsx';

import { ROLE_LABELS } from '@/lib/permissions';
import type { UserRole } from '@/types/auth';

export interface PermissionDeniedStateProps {
  /** What the user was trying to do, in their words. */
  action?: string;
  /** Roles that can do it, so the user knows who to ask. */
  requiredRoles?: UserRole[];
  currentRole?: UserRole;
  className?: string;
  compact?: boolean;
}

/**
 * A permission refusal.
 *
 * Explains *who* can perform the action rather than only that the user cannot.
 * "Not permitted" alone leaves an investigator stuck; naming the role turns it
 * into a next step — go and ask a senior investigator.
 *
 * This is a UI courtesy, not the control. The backend refuses the request
 * regardless of what the interface chooses to render.
 */
export function PermissionDeniedState({
  action,
  requiredRoles,
  currentRole,
  className,
  compact = false,
}: PermissionDeniedStateProps) {
  const roleNames = (requiredRoles ?? []).map((role) => ROLE_LABELS[role] ?? role);

  return (
    <div
      role="status"
      className={clsx(
        'rounded-card border border-ink-200 bg-ink-50 text-center dark:border-ink-700 dark:bg-ink-800/60',
        compact ? 'p-4' : 'p-8',
        className,
      )}
    >
      <p className="text-sm font-semibold text-ink-800 dark:text-ink-100">
        {action ? `You cannot ${action}` : 'Not permitted'}
      </p>

      <p className="mx-auto mt-1.5 max-w-md text-xs leading-relaxed text-ink-600 dark:text-ink-300">
        {roleNames.length > 0 ? (
          <>
            This requires the {roleNames.join(' or ')} role
            {currentRole ? ` — you are signed in as ${ROLE_LABELS[currentRole] ?? currentRole}` : ''}.
            Ask an administrator if you need it.
          </>
        ) : (
          <>Your role does not include this permission. Ask an administrator if you need it.</>
        )}
      </p>
    </div>
  );
}
