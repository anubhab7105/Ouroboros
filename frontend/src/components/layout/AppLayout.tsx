import { useEffect, useState } from 'react';
import { Outlet, useLocation } from 'react-router-dom';

import { useIsDesktop } from '@/hooks/useMediaQuery';
import { useLocalStorage } from '@/hooks/useLocalStorage';
import { STORAGE_KEYS } from '@/lib/storage';

import { EnvironmentBanner } from './EnvironmentBanner';
import { Sidebar } from './Sidebar';
import { Topbar } from './Topbar';

/**
 * The authenticated application frame.
 *
 * Two behaviours worth noting:
 *
 * - **The collapsed state is remembered** on desktop. Analysts work in this
 *   interface all day and a navigation column they keep closing is an
 *   irritation; on narrow screens the sidebar becomes a dismissable overlay
 *   instead, where remembering "collapsed" would make no sense.
 *
 * - **Route changes move focus to the main region** and scroll it to the top.
 *   Without this, a keyboard user who follows a link lands with focus still in
 *   the navigation and has to tab through it again, and a mouse user opening
 *   an alert from halfway down a list arrives mid-page.
 */
export function AppLayout() {
  const isDesktop = useIsDesktop();
  const [collapsed, setCollapsed] = useLocalStorage<boolean>(STORAGE_KEYS.sidebarCollapsed, false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const { pathname } = useLocation();

  useEffect(() => {
    setMobileOpen(false);

    const main = document.getElementById('mg-main');
    if (main) {
      main.scrollTop = 0;
      // tabindex="-1" on the region makes this focus call legal.
      main.focus({ preventScroll: true });
    }
  }, [pathname]);

  return (
    <div className="flex h-screen flex-col bg-ink-50 dark:bg-ink-950">
      <EnvironmentBanner />

      <Topbar
        sidebarCollapsed={collapsed}
        onToggleSidebar={() =>
          isDesktop ? setCollapsed((value) => !value) : setMobileOpen((open) => !open)
        }
      />

      <div className="flex min-h-0 flex-1">
        {isDesktop ? (
          <Sidebar collapsed={collapsed} className="shrink-0" />
        ) : mobileOpen ? (
          <div className="fixed inset-0 z-30 flex">
            <div
              className="absolute inset-0 bg-ink-950/40 animate-fade-in"
              aria-hidden="true"
              onClick={() => setMobileOpen(false)}
            />
            <div className="relative z-10 h-full">
              <Sidebar collapsed={false} onNavigate={() => setMobileOpen(false)} />
            </div>
          </div>
        ) : null}

        <main
          id="mg-main"
          tabIndex={-1}
          className="min-w-0 flex-1 overflow-y-auto px-4 py-5 focus:outline-none sm:px-6"
        >
          <div className="mx-auto max-w-[1600px]">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
