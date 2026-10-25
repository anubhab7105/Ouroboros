import { useContext } from 'react';

import { AuthContext, type AuthContextValue } from './AuthContext';

/**
 * Access the authenticated session.
 *
 * Throws when used outside the provider rather than returning a null-ish
 * object: a component silently believing nobody is signed in would render an
 * empty investigative view, which is a far more confusing bug than a clear
 * error at development time.
 */
export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error('useAuth must be used inside <AuthProvider>.');
  }

  return context;
}
