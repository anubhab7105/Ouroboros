import { useCallback } from 'react';

import { useAuth } from '@/features/auth/useAuth';
import { can, canAll, canAny, hasRole, roleAtLeast, type Permission } from '@/lib/permissions';
import type { UserRole } from '@/types/auth';

/**
 * Permission checks for the current user.
 *
 * These decide what to render only. The backend re-checks every permission
 * from the database on each request, so a user who edits their stored
 * permission list gets a visible button that returns 403, not access.
 */
export function usePermission() {
  const { user } = useAuth();

  const check = useCallback((permission: Permission | string) => can(user, permission), [user]);
  const checkAny = useCallback(
    (permissions: Array<Permission | string>) => canAny(user, permissions),
    [user],
  );
  const checkAll = useCallback(
    (permissions: Array<Permission | string>) => canAll(user, permissions),
    [user],
  );
  const checkRole = useCallback((...roles: UserRole[]) => hasRole(user, ...roles), [user]);
  const checkRoleAtLeast = useCallback((minimum: UserRole) => roleAtLeast(user, minimum), [user]);

  return {
    user,
    can: check,
    canAny: checkAny,
    canAll: checkAll,
    hasRole: checkRole,
    roleAtLeast: checkRoleAtLeast,
  };
}
