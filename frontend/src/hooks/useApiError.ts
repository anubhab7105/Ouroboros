import { useMemo } from 'react';

import { toFriendlyError, type FriendlyError } from '@/lib/errorMapper';

/**
 * Turn a query or mutation error into a renderable shape.
 *
 * Returns null when there is no error, so a component can branch on it
 * directly without re-deriving the mapping on every render.
 */
export function useApiError(error: unknown): FriendlyError | null {
  return useMemo(() => (error ? toFriendlyError(error) : null), [error]);
}
