import { Navigate, Outlet, useLocation } from 'react-router-dom';

import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { useAuth } from '@/features/auth/useAuth';
import { paths } from '@/routes/paths';

/**
 * Gate for every authenticated route.
 *
 * While the initial `/auth/me` check is in flight we render a spinner rather
 * than redirecting. Redirecting first would bounce a signed-in user to the
 * login page on every hard refresh, and then bounce them back — a visible
 * flicker that looks like a bug and loses the URL they typed.
 *
 * The attempted URL is carried in `?next=` so that signing in returns the
 * user to the page they asked for, not to a generic dashboard.
 */
export function ProtectedRoute() {
  const { isAuthenticated, isInitialising } = useAuth();
  const location = useLocation();

  if (isInitialising) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-ink-50 dark:bg-ink-950">
        <div className="flex flex-col items-center gap-3">
          <LoadingSpinner size="lg" label={null} />
          <p className="text-xs text-ink-500 dark:text-ink-400">Checking your session</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    const next = encodeURIComponent(location.pathname + location.search);
    return <Navigate to={`${paths.login}?next=${next}`} replace />;
  }

  return <Outlet />;
}
