import type { CurrentUser, LoginResponse } from '@/types/auth';
import { STORAGE_KEYS, readJson, readRaw, removeRaw, writeJson, writeRaw } from './storage';

/**
 * Session storage and token lifetime.
 *
 * The token lives in `localStorage`. That is a deliberate trade-off for an
 * internal tool: it survives a page reload, which analysts do constantly, at
 * the cost of being readable by script on the page. The mitigations are a
 * short token lifetime, a strict CSP from nginx, and the fact that the backend
 * re-checks authorisation from the database on every request rather than
 * trusting claims in the token.
 *
 * `EXPIRY_SKEW_MS` exists because the client clock and the server clock
 * disagree. Treating a token as expired slightly early turns a confusing
 * mid-action 401 into a clean redirect.
 */

const EXPIRY_SKEW_MS = 30_000;

export function getToken(): string | null {
  return readRaw(STORAGE_KEYS.token);
}

export function getTokenExpiry(): number | null {
  const raw = readRaw(STORAGE_KEYS.tokenExpiry);
  if (!raw) return null;

  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) ? parsed : null;
}

export function isTokenExpired(now: number = Date.now()): boolean {
  const expiry = getTokenExpiry();
  if (expiry === null) return false; // no recorded expiry: let the server decide
  return now + EXPIRY_SKEW_MS >= expiry;
}

export function getStoredUser(): CurrentUser | null {
  return readJson<CurrentUser | null>(STORAGE_KEYS.user, null);
}

export function hasSession(): boolean {
  return Boolean(getToken()) && !isTokenExpired();
}

export function storeSession(token: LoginResponse): void {
  writeRaw(STORAGE_KEYS.token, token.access_token);

  /*
   * The server sends `issued_at` and a lifetime in seconds, not an absolute
   * expiry. The arithmetic is done against the server's own `issued_at`
   * wherever it parses, so a client clock that is minutes out does not shorten
   * or extend the session; `Date.now()` is only the fallback.
   */
  const issuedAt = Date.parse(token.issued_at);
  const lifetimeMs = Math.max(0, token.expires_in) * 1000;
  const expiry = (Number.isFinite(issuedAt) ? issuedAt : Date.now()) + lifetimeMs;

  writeRaw(STORAGE_KEYS.tokenExpiry, String(expiry));
}

export function storeUser(user: CurrentUser): void {
  writeJson(STORAGE_KEYS.user, user);
}

export function clearSession(): void {
  removeRaw(STORAGE_KEYS.token);
  removeRaw(STORAGE_KEYS.tokenExpiry);
  removeRaw(STORAGE_KEYS.user);
}

/** Milliseconds until expiry, or null when unknown. */
export function millisecondsUntilExpiry(now: number = Date.now()): number | null {
  const expiry = getTokenExpiry();
  if (expiry === null) return null;
  return Math.max(0, expiry - now);
}
