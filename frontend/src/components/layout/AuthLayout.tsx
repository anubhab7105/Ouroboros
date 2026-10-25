import type { ReactNode } from 'react';

import logo from '@/assets/muleguard-logo.svg';
import { APP_NAME, APP_VERSION, ENVIRONMENT_LABEL, SHOW_ENVIRONMENT_BANNER } from '@/lib/environment';

/**
 * The frame for unauthenticated pages.
 *
 * The environment is named here as well as in the application banner: a user
 * signing in to a staging copy with production credentials should find out
 * before they type them, not after.
 */
export function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-ink-100 px-4 py-10 dark:bg-ink-950">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center gap-2 text-center">
          <img src={logo} alt="" className="h-10 w-10" />
          <h1 className="text-lg font-semibold tracking-tight text-ink-900 dark:text-ink-50">
            {APP_NAME}
          </h1>
          <p className="text-xs text-ink-600 dark:text-ink-300">
            Mule account detection and financial fraud investigation
          </p>

          {SHOW_ENVIRONMENT_BANNER ? (
            <p className="mt-1 rounded-full bg-amber-100 px-2.5 py-0.5 text-2xs font-semibold uppercase tracking-wider text-amber-900 dark:bg-amber-950/60 dark:text-amber-200">
              {ENVIRONMENT_LABEL}
            </p>
          ) : null}
        </div>

        <div className="rounded-card border border-ink-200 bg-white p-5 shadow-sm dark:border-ink-700 dark:bg-ink-900">
          {children}
        </div>

        <p className="mt-4 text-center text-2xs text-ink-500 dark:text-ink-400">
          Access is logged. v{APP_VERSION}
        </p>
      </div>
    </div>
  );
}
