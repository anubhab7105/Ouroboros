import clsx from 'clsx';
import { useEffect, useId, useRef, type ReactNode } from 'react';

export interface DrawerProps {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  footer?: ReactNode;
  width?: 'md' | 'lg' | 'xl';
}

const WIDTHS = { md: 'max-w-md', lg: 'max-w-xl', xl: 'max-w-3xl' } as const;

/**
 * A side panel for record detail.
 *
 * Used instead of a modal for alert, transaction and complaint detail: it
 * keeps the list visible behind it, so an analyst working a queue retains
 * their place and can see what comes next. A modal would hide exactly the
 * context they are comparing against.
 *
 * Escape closes it, focus moves in and back out, and background scroll is
 * locked while it is open.
 */
export function Drawer({ open, onClose, title, children, footer, width = 'lg' }: DrawerProps) {
  const panelRef = useRef<HTMLDivElement>(null);
  const previouslyFocused = useRef<HTMLElement | null>(null);
  const titleId = useId();

  useEffect(() => {
    if (!open) return;

    previouslyFocused.current = document.activeElement as HTMLElement | null;
    const { overflow } = document.body.style;
    document.body.style.overflow = 'hidden';
    panelRef.current?.focus();

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        onClose();
      }
    };

    document.addEventListener('keydown', onKeyDown);

    return () => {
      document.removeEventListener('keydown', onKeyDown);
      document.body.style.overflow = overflow;
      previouslyFocused.current?.focus();
    };
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-40 flex justify-end">
      <div className="absolute inset-0 bg-ink-950/40 animate-fade-in" onClick={onClose} aria-hidden="true" />

      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        className={clsx(
          'relative z-10 flex h-full w-full flex-col bg-white shadow-panel',
          'animate-slide-in-right dark:bg-ink-900',
          WIDTHS[width],
        )}
      >
        <header className="flex items-start justify-between gap-3 border-b border-ink-200 px-4 py-3 dark:border-ink-700">
          <h2 id={titleId} className="text-sm font-semibold text-ink-900 dark:text-ink-50">
            {title}
          </h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close panel"
            className="rounded p-1 text-ink-500 hover:bg-ink-100 hover:text-ink-800 dark:hover:bg-ink-800 dark:hover:text-ink-100"
          >
            <svg viewBox="0 0 16 16" className="h-4 w-4" aria-hidden="true">
              <path d="M4 4l8 8M12 4l-8 8" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
            </svg>
          </button>
        </header>

        <div className="flex-1 overflow-y-auto px-4 py-4">{children}</div>

        {footer ? (
          <footer className="flex items-center justify-end gap-2 border-t border-ink-200 bg-ink-50 px-4 py-3 dark:border-ink-700 dark:bg-ink-800/60">
            {footer}
          </footer>
        ) : null}
      </div>
    </div>
  );
}
