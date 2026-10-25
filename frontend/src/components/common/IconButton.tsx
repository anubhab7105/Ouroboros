import clsx from 'clsx';
import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from 'react';

export interface IconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  /** Required: an icon-only control is unusable without an accessible name. */
  label: string;
  icon: ReactNode;
  size?: 'sm' | 'md';
  active?: boolean;
}

/**
 * An icon-only button.
 *
 * `label` is mandatory and becomes both `aria-label` and the tooltip. An
 * icon-only control with no accessible name is invisible to a screen reader
 * and ambiguous to everyone else, which is why it is not optional here.
 */
export const IconButton = forwardRef<HTMLButtonElement, IconButtonProps>(function IconButton(
  { label, icon, size = 'md', active = false, className, type = 'button', ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      aria-label={label}
      aria-pressed={active || undefined}
      title={label}
      className={clsx(
        'inline-flex items-center justify-center rounded-md text-ink-600 transition-colors duration-fast',
        'hover:bg-ink-100 hover:text-ink-900 disabled:cursor-not-allowed disabled:text-ink-300',
        'dark:text-ink-300 dark:hover:bg-ink-800 dark:hover:text-ink-50',
        active && 'bg-accent-100 text-accent-800 dark:bg-accent-900/50 dark:text-accent-200',
        size === 'sm' ? 'h-6 w-6' : 'h-8 w-8',
        className,
      )}
      {...rest}
    >
      {icon}
    </button>
  );
});
