import clsx from 'clsx';
import { useId, useState, type ReactNode } from 'react';

export interface TooltipProps {
  content: ReactNode;
  children: ReactNode;
  side?: 'top' | 'bottom' | 'left' | 'right';
  className?: string;
}

const SIDE_CLASSES = {
  top: 'bottom-full left-1/2 mb-1.5 -translate-x-1/2',
  bottom: 'top-full left-1/2 mt-1.5 -translate-x-1/2',
  left: 'right-full top-1/2 mr-1.5 -translate-y-1/2',
  right: 'left-full top-1/2 ml-1.5 -translate-y-1/2',
} as const;

/**
 * A tooltip that works from the keyboard.
 *
 * Opens on focus as well as hover, and the trigger carries `aria-describedby`.
 * A hover-only tooltip hides its content from keyboard and screen-reader
 * users, and in this app tooltips carry real information — what a scoring mode
 * means, why a correlation tier is weak — not decoration.
 */
export function Tooltip({ content, children, side = 'top', className }: TooltipProps) {
  const [open, setOpen] = useState(false);
  const id = useId();

  return (
    <span
      className="relative inline-flex"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
    >
      <span aria-describedby={open ? id : undefined}>{children}</span>

      {open ? (
        <span
          role="tooltip"
          id={id}
          className={clsx(
            'pointer-events-none absolute z-50 w-max max-w-xs rounded-md bg-ink-900 px-2 py-1.5',
            'text-2xs font-normal leading-relaxed text-ink-50 shadow-panel',
            'dark:bg-ink-700',
            SIDE_CLASSES[side],
            className,
          )}
        >
          {content}
        </span>
      ) : null}
    </span>
  );
}
