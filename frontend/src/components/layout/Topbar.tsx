import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';

import logo from '@/assets/muleguard-logo.svg';
import { IconButton } from '@/components/common/IconButton';
import { LogoutButton } from '@/features/auth/LogoutButton';
import { useAuth } from '@/features/auth/useAuth';
import { useLocalStorage } from '@/hooks/useLocalStorage';
import { APP_VERSION } from '@/lib/environment';
import { initials } from '@/lib/formatters';
import { ROLE_LABELS } from '@/lib/permissions';
import { STORAGE_KEYS } from '@/lib/storage';
import { paths } from '@/routes/paths';

export interface TopbarProps {
  onToggleSidebar: () => void;
  sidebarCollapsed: boolean;
}

type ThemeChoice = 'light' | 'dark' | 'system';

const THEME_ORDER: ThemeChoice[] = ['system', 'light', 'dark'];
const THEME_LABELS: Record<ThemeChoice, string> = {
  system: 'Match system',
  light: 'Light',
  dark: 'Dark',
};

/**
 * Apply a theme choice to the document.
 *
 * Tailwind is configured for class-based dark mode, so this sets
 * `data-theme` and the `dark` class on `<html>`. "System" tracks the OS
 * preference live, which matters for analysts who work into the evening on a
 * machine that switches at sunset.
 */
function useThemeChoice() {
  const [choice, setChoice] = useLocalStorage<ThemeChoice>(STORAGE_KEYS.theme, 'system');

  useEffect(() => {
    const root = document.documentElement;

    const apply = () => {
      const prefersDark =
        typeof window.matchMedia === 'function' &&
        window.matchMedia('(prefers-color-scheme: dark)').matches;

      const dark = choice === 'dark' || (choice === 'system' && prefersDark);

      root.classList.toggle('dark', dark);
      root.dataset.theme = dark ? 'dark' : 'light';
    };

    apply();

    if (choice !== 'system' || typeof window.matchMedia !== 'function') return;

    const media = window.matchMedia('(prefers-color-scheme: dark)');
    media.addEventListener('change', apply);
    return () => media.removeEventListener('change', apply);
  }, [choice]);

  const cycle = () => {
    const index = THEME_ORDER.indexOf(choice);
    setChoice(THEME_ORDER[(index + 1) % THEME_ORDER.length] ?? 'system');
  };

  return { choice, cycle };
}

/** The persistent header: identity, theme, account menu. */
export function Topbar({ onToggleSidebar, sidebarCollapsed }: TopbarProps) {
  const { user } = useAuth();
  const navigate = useNavigate();
  const { choice, cycle } = useThemeChoice();
  const [menuOpen, setMenuOpen] = useState(false);

  // Close the account menu on Escape and on any outside click.
  useEffect(() => {
    if (!menuOpen) return;

    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setMenuOpen(false);
    };
    const onClick = () => setMenuOpen(false);

    document.addEventListener('keydown', onKey);
    // Deferred so the click that opened the menu does not immediately close it.
    const timer = window.setTimeout(() => document.addEventListener('click', onClick), 0);

    return () => {
      document.removeEventListener('keydown', onKey);
      document.removeEventListener('click', onClick);
      window.clearTimeout(timer);
    };
  }, [menuOpen]);

  return (
    <header className="flex h-14 shrink-0 items-center gap-3 border-b border-ink-200 bg-white px-3 dark:border-ink-700 dark:bg-ink-900">
      <IconButton
        label={sidebarCollapsed ? 'Expand navigation' : 'Collapse navigation'}
        onClick={onToggleSidebar}
        icon={
          <svg viewBox="0 0 16 16" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M2 4h12M2 8h12M2 12h12" strokeLinecap="round" />
          </svg>
        }
      />

      <Link to={paths.dashboard} className="flex items-center gap-2 rounded px-1">
        <img src={logo} alt="" className="h-6 w-6" />
        <span className="text-sm font-semibold tracking-tight text-ink-900 dark:text-ink-50">
          MuleGuard
        </span>
        <span className="mg-visually-hidden">— go to dashboard</span>
      </Link>

      <span className="hidden text-2xs text-ink-400 dark:text-ink-500 sm:inline" title="Build version">
        v{APP_VERSION}
      </span>

      <div className="ml-auto flex items-center gap-1.5">
        <IconButton
          label={`Theme: ${THEME_LABELS[choice]}. Click to change.`}
          onClick={cycle}
          icon={
            <span aria-hidden="true" className="text-xs">
              {choice === 'dark' ? '◑' : choice === 'light' ? '◐' : '◒'}
            </span>
          }
        />

        <Link
          to={paths.serviceStatus}
          title="Service status: which analytical components are available"
          className="hidden rounded-md px-2 py-1 text-2xs font-medium text-ink-600 hover:bg-ink-100 dark:text-ink-300 dark:hover:bg-ink-800 sm:inline-block"
        >
          Status
        </Link>

        <div className="relative">
          <button
            type="button"
            aria-haspopup="menu"
            aria-expanded={menuOpen}
            onClick={(event) => {
              event.stopPropagation();
              setMenuOpen((open) => !open);
            }}
            className="flex items-center gap-2 rounded-md px-1.5 py-1 hover:bg-ink-100 dark:hover:bg-ink-800"
          >
            <span
              aria-hidden="true"
              className="flex h-7 w-7 items-center justify-center rounded-full bg-accent-100 text-2xs font-bold text-accent-800 dark:bg-accent-900/60 dark:text-accent-200"
            >
              {initials(user?.full_name ?? user?.username)}
            </span>
            <span className="hidden text-left leading-tight sm:block">
              <span className="block text-2xs font-semibold text-ink-800 dark:text-ink-100">
                {user?.full_name ?? user?.username ?? 'Signed out'}
              </span>
              <span className="block text-2xs text-ink-500 dark:text-ink-400">
                {user ? (ROLE_LABELS[user.role] ?? user.role) : ''}
              </span>
            </span>
          </button>

          {menuOpen ? (
            <div
              role="menu"
              onClick={(event) => event.stopPropagation()}
              className="absolute right-0 top-full z-30 mt-1 w-56 rounded-card border border-ink-200 bg-white p-2 shadow-lg dark:border-ink-700 dark:bg-ink-900"
            >
              <div className="border-b border-ink-200 px-2 pb-2 dark:border-ink-700">
                <p className="text-xs font-semibold text-ink-800 dark:text-ink-100">
                  {user?.full_name ?? user?.username}
                </p>
                <p className="truncate text-2xs text-ink-500 dark:text-ink-400">{user?.email}</p>
                <p className="mt-1 text-2xs text-ink-500 dark:text-ink-400">
                  {user ? (ROLE_LABELS[user.role] ?? user.role) : ''}
                </p>
              </div>

              <div className="pt-1">
                <button
                  type="button"
                  role="menuitem"
                  onClick={() => {
                    setMenuOpen(false);
                    navigate(paths.serviceStatus);
                  }}
                  className="w-full rounded-md px-2 py-1.5 text-left text-xs font-medium text-ink-700 hover:bg-ink-100 dark:text-ink-200 dark:hover:bg-ink-800"
                >
                  Service status
                </button>
                <LogoutButton />
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </header>
  );
}
