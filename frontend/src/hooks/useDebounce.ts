import { useEffect, useState } from 'react';

/**
 * Debounce a value.
 *
 * Used for search inputs. Without it, every keystroke in the account search
 * fires a request, and the responses can arrive out of order so the list ends
 * up showing results for a prefix the user has already typed past.
 */
export function useDebounce<T>(value: T, delayMs = 300): T {
  const [debounced, setDebounced] = useState(value);

  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(value), delayMs);
    return () => window.clearTimeout(timer);
  }, [value, delayMs]);

  return debounced;
}
