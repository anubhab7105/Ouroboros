/**
 * Re-export so `@/hooks/useAuth` and `@/features/auth/useAuth` both resolve.
 *
 * The implementation lives with the auth feature, next to the context it
 * reads. This file exists because the hooks directory is where a reader looks
 * first.
 */
export { useAuth } from '@/features/auth/useAuth';
