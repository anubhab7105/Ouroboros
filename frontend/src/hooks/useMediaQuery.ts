import { useEffect, useState } from 'react';

/**
 * Subscribe to a media query.
 *
 * Guards against `matchMedia` being absent, which is the case in jsdom and in
 * a few embedded webviews. Returning `false` there is the right default: the
 * layout then renders its mobile-safe branch rather than crashing.
 */
export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState<boolean>(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return false;
    return window.matchMedia(query).matches;
  });

  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return;

    const list = window.matchMedia(query);
    const handler = (event: MediaQueryListEvent) => setMatches(event.matches);

    setMatches(list.matches);

    // addEventListener is unavailable on older Safari's MediaQueryList.
    if (typeof list.addEventListener === 'function') {
      list.addEventListener('change', handler);
      return () => list.removeEventListener('change', handler);
    }

    list.addListener(handler);
    return () => list.removeListener(handler);
  }, [query]);

  return matches;
}

export const useIsDesktop = () => useMediaQuery('(min-width: 1024px)');
export const usePrefersReducedMotion = () =>
  useMediaQuery('(prefers-reduced-motion: reduce)');
