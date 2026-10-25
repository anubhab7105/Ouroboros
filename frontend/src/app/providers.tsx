import { QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { BrowserRouter } from 'react-router-dom';

import { AuthProvider } from '@/features/auth/AuthContext';

import { ErrorBoundary } from './ErrorBoundary';
import { queryClient } from './queryClient';

/**
 * Every provider the application needs, in the one order that works.
 *
 * `BrowserRouter` must sit outside `AuthProvider`, because signing out
 * navigates; `QueryClientProvider` must sit outside `AuthProvider`, because
 * signing out clears the query cache. The `ErrorBoundary` is outermost so
 * that a crash inside a provider still renders something a user can act on
 * rather than a blank page.
 */
export function AppProviders({ children }: { children: ReactNode }) {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <AuthProvider>{children}</AuthProvider>
        </BrowserRouter>
      </QueryClientProvider>
    </ErrorBoundary>
  );
}
