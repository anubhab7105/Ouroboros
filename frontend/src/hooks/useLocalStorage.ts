import { useCallback, useState } from 'react';

import { readJson, writeJson } from '@/lib/storage';

/**
 * State backed by localStorage, via the guarded storage helpers.
 *
 * Reads go through `readJson`, which falls back to in-memory when storage is
 * unavailable (private mode, blocked site data). That means the hook never
 * throws on mount, which an unguarded `JSON.parse(localStorage.getItem(...))`
 * in a render would.
 */
export function useLocalStorage<T>(key: string, initialValue: T) {
  const [value, setValue] = useState<T>(() => readJson<T>(key, initialValue));

  const update = useCallback(
    (next: T | ((previous: T) => T)) => {
      setValue((previous) => {
        const resolved =
          typeof next === 'function' ? (next as (p: T) => T)(previous) : next;
        writeJson(key, resolved);
        return resolved;
      });
    },
    [key],
  );

  return [value, update] as const;
}
