import clsx from 'clsx';
import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from 'react';

import { LoadingSpinner } from './LoadingSpinner';

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger';
export type ButtonSize = 'sm' | 'md';

const VARIANTS: Record<ButtonVariant, string> = {
  primary:
    'bg-accent-700 text-white hover:bg-accent-800 disabled:bg-accent-700/50 dark:bg-accent-600 dark:hover:bg-accent-500',
  secondary:
    'border border-ink-300 bg-white text-ink-800 hover:bg-ink-100 disabled:bg-white/60 dark:border-ink-600 dark:bg-ink-900 dark:text-ink-100 dark:hover:bg-ink-800',
  ghost:
    'text-ink-700 hover:bg-ink-100 disabled:text-ink-400 dark:text-ink-200 dark:hover:bg-ink-800',
  // Reserved for genuinely consequential actions: closing a case, removing
  // evidence. Overusing it makes the real ones invisible.
  danger:
    'bg-state-danger text-white hover:brightness-110 disabled:bg-state-danger/50',
};

const SIZES: Record<ButtonSize, string> = {
  sm: 'px-2.5 py-1 text-xs',
  md: 'px-3 py-1.5 text-sm',
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  isLoading?: boolean;
  leadingIcon?: ReactNode;
  fullWidth?: boolean;
}

/**
 * The standard button.
 *
 * While `isLoading`, the button is disabled and keeps its label beside the
 * spinner. Replacing the label with a spinner makes the control change width
 * and loses the only clue about what is in progress.
 */
export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  {
    variant = 'secondary',
    size = 'md',
    isLoading = false,
    leadingIcon,
    fullWidth = false,
    className,
    children,
    disabled,
    type = 'button',
    ...rest
  },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      disabled={disabled || isLoading}
      aria-busy={isLoading || undefined}
      className={clsx(
        'inline-flex items-center justify-center gap-1.5 rounded-md font-semibold',
        'transition-colors duration-fast disabled:cursor-not-allowed',
        VARIANTS[variant],
        SIZES[size],
        fullWidth && 'w-full',
        className,
      )}
      {...rest}
    >
      {isLoading ? <LoadingSpinner size="xs" /> : leadingIcon}
      {children}
    </button>
  );
});
