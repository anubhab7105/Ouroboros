/**
 * Browser storage with a guard around every access.
 *
 * `localStorage` throws in a few real situations: Safari private mode, blocked
 * site data, and some embedded webviews. An unguarded read in a module's
 * initialiser takes the whole app down with a blank page, so every access here
 * is wrapped and falls back to in-memory.
 *
 * The in-memory fallback means a user in private mode keeps a working session
 * for the tab rather than being unable to log in at all.
 */

const PREFIX = 'muleguard.';

const memoryStore = new Map<string, string>();

function available(): boolean {
  try {
    const probe = `${PREFIX}__probe__`;
    window.localStorage.setItem(probe, '1');
    window.localStorage.removeItem(probe);
    return true;
  } catch {
    return false;
  }
}

const hasLocalStorage = typeof window !== 'undefined' && available();

export function readRaw(key: string): string | null {
  const namespaced = `${PREFIX}${key}`;

  if (!hasLocalStorage) {
    return memoryStore.get(namespaced) ?? null;
  }

  try {
    return window.localStorage.getItem(namespaced);
  } catch {
    return memoryStore.get(namespaced) ?? null;
  }
}

export function writeRaw(key: string, value: string): void {
  const namespaced = `${PREFIX}${key}`;
  memoryStore.set(namespaced, value);

  if (!hasLocalStorage) return;

  try {
    window.localStorage.setItem(namespaced, value);
  } catch {
    // Quota exceeded or blocked: the in-memory copy above still serves this tab.
  }
}

export function removeRaw(key: string): void {
  const namespaced = `${PREFIX}${key}`;
  memoryStore.delete(namespaced);

  if (!hasLocalStorage) return;

  try {
    window.localStorage.removeItem(namespaced);
  } catch {
    /* nothing useful to do */
  }
}

export function readJson<T>(key: string, fallback: T): T {
  const raw = readRaw(key);
  if (raw === null) return fallback;

  try {
    return JSON.parse(raw) as T;
  } catch {
    // Corrupt value: discard it rather than failing on every read.
    removeRaw(key);
    return fallback;
  }
}

export function writeJson(key: string, value: unknown): void {
  try {
    writeRaw(key, JSON.stringify(value));
  } catch {
    /* unserialisable value: skip */
  }
}

/** True when persistence is real rather than per-tab memory. */
export const isPersistent = hasLocalStorage;

export const STORAGE_KEYS = {
  token: 'auth.token',
  tokenExpiry: 'auth.expiresAt',
  user: 'auth.user',
  theme: 'theme',
  sidebarCollapsed: 'ui.sidebarCollapsed',
  tablePageSize: 'ui.tablePageSize',
  graphLayout: 'ui.graphLayout',
} as const;
