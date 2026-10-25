import clsx from 'clsx';
import type { ReactNode } from 'react';

export type BadgeTone = 'neutral' | 'accent' | 'success' | 'warning' | 'danger' | 'info';

const TONE_CLASSES: Record<BadgeTone, string> = {
  neutral: 'bg-ink-100 text-ink-700 dark:bg-ink-800 dark:text-ink-200',
  accent: 'bg-accent-100 text-accent-800 dark:bg-accent-900/50 dark:text-accent-200',
  success: 'bg-emerald-50 text-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-200',
  warning: 'bg-amber-50 text-amber-900 dark:bg-amber-950/40 dark:text-amber-200',
  danger: 'bg-red-50 text-red-900 dark:bg-red-950/40 dark:text-red-200',
  info: 'bg-accent-50 text-accent-800 dark:bg-accent-900/40 dark:text-accent-200',
};

export interface BadgeProps {
  children: ReactNode;
  tone?: BadgeTone;
  /** Hex for a left rule, used by the risk and severity ramps. */
  accentColor?: string;
  className?: string;
  title?: string;
  /** Explicit label for assistive tech when the visible text is abbreviated. */
  srLabel?: string;
}

/**
 * A small status label.
 *
 * `accentColor` draws a coloured left rule rather than tinting the whole
 * badge. The text stays high-contrast and legible, and the colour works as a
 * scanning cue down a column without becoming the only thing carrying the
 * meaning.
 */
export function Badge({
  children,
  tone = 'neutral',
  accentColor,
  className,
  title,
  srLabel,
}: BadgeProps) {
  return (
    <span
      className={clsx('mg-badge', TONE_CLASSES[tone], accentColor && 'border-l-2 pl-1.5', className)}
      style={accentColor ? { borderLeftColor: accentColor } : undefined}
      title={title}
    >
      {srLabel ? <span className="mg-visually-hidden">{srLabel}</span> : null}
      {children}
    </span>
  );
}
