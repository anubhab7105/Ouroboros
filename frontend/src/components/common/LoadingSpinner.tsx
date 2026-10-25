import clsx from 'clsx';

const SIZES = {
  xs: 'h-3 w-3 border',
  sm: 'h-4 w-4 border-2',
  md: 'h-6 w-6 border-2',
  lg: 'h-10 w-10 border-[3px]',
} as const;

export interface LoadingSpinnerProps {
  size?: keyof typeof SIZES;
  className?: string;
  /** Accessible label. Set to null inside a control that already has one. */
  label?: string | null;
}

/**
 * A spinner.
 *
 * `aria-hidden` when there is no label, so a button that already announces
 * "Loading" via aria-busy does not announce it twice.
 */
export function LoadingSpinner({ size = 'md', className, label = 'Loading' }: LoadingSpinnerProps) {
  return (
    <span
      role={label ? 'status' : undefined}
      aria-hidden={label ? undefined : true}
      className={clsx('inline-flex items-center', className)}
    >
      <span
        className={clsx(
          'animate-spin rounded-full border-ink-300 border-t-accent-600 dark:border-ink-600 dark:border-t-accent-400',
          SIZES[size],
        )}
      />
      {label ? <span className="mg-visually-hidden">{label}</span> : null}
    </span>
  );
}
