import {
  createContext,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';

import { resetQueryCache } from '@/app/queryClient';
import {
  clearSession,
  getStoredUser,
  hasSession,
  millisecondsUntilExpiry,
  storeSession,
  storeUser,
} from '@/lib/auth';
import { toFriendlyError, type FriendlyError } from '@/lib/errorMapper';
import type { CurrentUser, LoginRequest } from '@/types/auth';

import { fetchCurrentUser, login as loginRequest } from './authApi';

/**
 * Authentication state for the application.
 *
 * Design points:
 *
 * - **The stored user is shown immediately, then revalidated.** Reading the
 *   cached user from storage means a reload does not flash the login screen
 *   before `/auth/me` answers. The call still happens, so a revoked or
 *   role-changed account — and a changed capability map — is corrected within
 *   a second.
 *
 * - **A scheduled timer signs the user out at expiry.** Without it, an analyst
 *   who leaves a tab open overnight comes back to an interface that looks
 *   usable and 401s on the first click. Expiring cleanly is less confusing.
 *
 * - **Sign-out clears the React Query cache.** Otherwise the next user on a
 *   shared workstation would see the previous user's cached alerts and cases
 *   until each query refetched.
 *
 * - **A 403 does not sign the user out.** It means this action is not theirs
 *   to take, which is a different thing from not being signed in.
 */

export interface AuthContextValue {
  user: CurrentUser | null;
  isAuthenticated: boolean;
  /** True while the initial session check is in flight. */
  isInitialising: boolean;
  isLoggingIn: boolean;
  error: FriendlyError | null;
  login: (credentials: LoginRequest) => Promise<boolean>;
  logout: (reason?: string) => void;
  refreshUser: () => Promise<void>;
  clearError: () => void;
  /** Set when the session ended on its own, so the login page can explain why. */
  signedOutReason: string | null;
}

export const AuthContext = createContext<AuthContextValue | null>(null);

/** Sign out this long before the token actually expires. */
const EXPIRY_MARGIN_MS = 5_000;

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<CurrentUser | null>(() =>
    hasSession() ? getStoredUser() : null,
  );
  const [isInitialising, setIsInitialising] = useState<boolean>(() => hasSession());
  const [isLoggingIn, setIsLoggingIn] = useState(false);
  const [error, setError] = useState<FriendlyError | null>(null);
  const [signedOutReason, setSignedOutReason] = useState<string | null>(null);

  const expiryTimer = useRef<number | null>(null);

  const clearExpiryTimer = useCallback(() => {
    if (expiryTimer.current !== null) {
      window.clearTimeout(expiryTimer.current);
      expiryTimer.current = null;
    }
  }, []);

  const logout = useCallback(
    (reason?: string) => {
      clearExpiryTimer();
      clearSession();
      resetQueryCache();
      setUser(null);
      setSignedOutReason(reason ?? null);
    },
    [clearExpiryTimer],
  );

  /** Schedule an automatic sign-out at token expiry. */
  const scheduleExpiry = useCallback(() => {
    clearExpiryTimer();

    const remaining = millisecondsUntilExpiry();
    if (remaining === null) return;

    const delay = Math.max(0, remaining - EXPIRY_MARGIN_MS);

    // setTimeout saturates above ~24.8 days; nothing here comes close, but
    // clamping keeps the behaviour defined.
    expiryTimer.current = window.setTimeout(
      () => logout('Your session expired. Sign in again to continue.'),
      Math.min(delay, 2_147_483_000),
    );
  }, [clearExpiryTimer, logout]);

  const refreshUser = useCallback(async () => {
    if (!hasSession()) {
      setUser(null);
      return;
    }

    try {
      const fresh = await fetchCurrentUser();
      setUser(fresh);
      storeUser(fresh);

      if (!fresh.is_active) {
        logout('This account has been deactivated.');
      }
    } catch (caught) {
      const friendly = toFriendlyError(caught);

      // Only an authentication failure ends the session. A 403 or a transient
      // 500 must not log the user out of a working session.
      if (friendly.requiresReauth) {
        logout('Your session is no longer valid. Sign in again.');
      }
    }
  }, [logout]);

  // Initial session validation.
  useEffect(() => {
    let cancelled = false;

    const run = async () => {
      if (!hasSession()) {
        setIsInitialising(false);
        return;
      }

      scheduleExpiry();
      await refreshUser();

      if (!cancelled) setIsInitialising(false);
    };

    void run();

    return () => {
      cancelled = true;
    };
  }, [refreshUser, scheduleExpiry]);

  useEffect(() => clearExpiryTimer, [clearExpiryTimer]);

  const login = useCallback(
    async (credentials: LoginRequest): Promise<boolean> => {
      setIsLoggingIn(true);
      setError(null);
      setSignedOutReason(null);

      try {
        // The login response carries the signed-in user, so there is no
        // second round trip to /auth/me here.
        const token = await loginRequest(credentials);
        storeSession(token);
        storeUser(token.user);
        setUser(token.user);
        scheduleExpiry();

        return true;
      } catch (caught) {
        clearSession();
        setUser(null);
        setError(toFriendlyError(caught));
        return false;
      } finally {
        setIsLoggingIn(false);
      }
    },
    [scheduleExpiry],
  );

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      isAuthenticated: Boolean(user) && hasSession(),
      isInitialising,
      isLoggingIn,
      error,
      login,
      logout,
      refreshUser,
      clearError: () => setError(null),
      signedOutReason,
    }),
    [user, isInitialising, isLoggingIn, error, login, logout, refreshUser, signedOutReason],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
