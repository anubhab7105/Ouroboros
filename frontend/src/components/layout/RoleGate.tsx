import type { ReactNode } from 'react';

import { PermissionDeniedState } from '@/components/common/PermissionDeniedState';
import { usePermission } from '@/hooks/usePermission';
import type { Permission } from '@/lib/permissions';
import type { UserRole } from '@/types/auth';

export interface RoleGateProps {
  children: ReactNode;
  /** Any one of these permissions admits the user. */
  permissions?: Array<Permission | string>;
  /** Every one of these permissions is required. */
  requireAll?: boolean;
  roles?: UserRole[];
  /** Verb completing "You cannot …" in the denial message. */
  action?: string;
  /** Render nothing at all instead of an explanation. */
  silent?: boolean;
  fallback?: ReactNode;
}

/**
 * Show children only to a user who may use them.
 *
 * Two modes, and the choice matters:
 *
 * - **Explained (default).** Renders a denial that names the roles which can
 *   perform the action. Use this for a whole page or panel: an analyst who
 *   cannot see the audit trail is better served by being told who can than by
 *   a section that silently is not there.
 *
 * - **Silent** (`silent`). Renders nothing. Use this for an individual button
 *   inside a toolbar, where an explanation for each missing control would be
 *   noise.
 *
 * This is presentation only. Every one of these permissions is re-checked
 * against the database on the server for each request.
 */
export function RoleGate({
  children,
  permissions,
  requireAll = false,
  roles,
  action,
  silent = false,
  fallback,
}: RoleGateProps) {
  const { user, canAny, canAll, hasRole } = usePermission();

  const permissionOk =
    !permissions || permissions.length === 0
      ? true
      : requireAll
        ? canAll(permissions)
        : canAny(permissions);

  const roleOk = !roles || roles.length === 0 ? true : hasRole(...roles);

  if (permissionOk && roleOk) return <>{children}</>;
  if (fallback !== undefined) return <>{fallback}</>;
  if (silent) return null;

  return (
    <PermissionDeniedState
      action={action}
      requiredRoles={roles}
      currentRole={user?.role as UserRole | undefined}
    />
  );
}
