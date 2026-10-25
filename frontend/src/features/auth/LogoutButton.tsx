import { useNavigate } from 'react-router-dom';

import { paths } from '@/routes/paths';

import { useAuth } from './useAuth';

/**
 * Sign out.
 *
 * No confirmation dialog: signing out is trivially reversible (sign back in)
 * and nothing is lost, so a prompt would be friction without a purpose. The
 * things that *do* get confirmed are case closure and evidence removal.
 */
export function LogoutButton({ className }: { className?: string }) {
  const { logout } = useAuth();
  const navigate = useNavigate();

  const handleClick = () => {
    logout();
    navigate(paths.login, { replace: true });
  };

  return (
    <button
      type="button"
      onClick={handleClick}
      className={
        className ??
        'w-full rounded-md px-2 py-1.5 text-left text-xs font-medium text-ink-700 hover:bg-ink-100 dark:text-ink-200 dark:hover:bg-ink-800'
      }
    >
      Sign out
    </button>
  );
}
