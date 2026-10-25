import { useCallback, useState } from 'react';

import { IconButton } from './IconButton';

export interface CopyButtonProps {
  value: string;
  label?: string;
  size?: 'sm' | 'md';
  className?: string;
}

/**
 * Copy a value to the clipboard.
 *
 * Investigators copy account ids and transaction references constantly, into
 * notes, tickets and other systems. The confirmation state matters: without it
 * there is no way to tell whether the click registered, and a silently failed
 * copy means pasting a stale identifier into a report.
 *
 * Falls back to a hidden textarea and `execCommand` where the async Clipboard
 * API is unavailable, which includes non-HTTPS origins.
 */
export function CopyButton({ value, label = 'Copy', size = 'sm', className }: CopyButtonProps) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');

  const handleCopy = useCallback(async () => {
    const reset = () => window.setTimeout(() => setState('idle'), 1_500);

    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value);
        setState('copied');
        reset();
        return;
      }

      // Insecure origin or an older browser: fall back to a selection copy.
      const area = document.createElement('textarea');
      area.value = value;
      area.setAttribute('readonly', '');
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.appendChild(area);
      area.select();

      const ok = document.execCommand('copy');
      document.body.removeChild(area);

      setState(ok ? 'copied' : 'failed');
      reset();
    } catch {
      setState('failed');
      reset();
    }
  }, [value]);

  return (
    <IconButton
      size={size}
      className={className}
      label={
        state === 'copied'
          ? 'Copied'
          : state === 'failed'
            ? 'Copy failed — select the value and copy manually'
            : label
      }
      onClick={() => void handleCopy()}
      icon={
        state === 'copied' ? (
          <svg viewBox="0 0 16 16" className="h-3.5 w-3.5" aria-hidden="true">
            <path
              d="M13 4.5 6.5 11 3 7.5"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        ) : state === 'failed' ? (
          <svg viewBox="0 0 16 16" className="h-3.5 w-3.5" aria-hidden="true">
            <path
              d="M4 4l8 8M12 4l-8 8"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
            />
          </svg>
        ) : (
          <svg viewBox="0 0 16 16" className="h-3.5 w-3.5" aria-hidden="true">
            <rect
              x="5.5"
              y="5.5"
              width="8"
              height="8"
              rx="1.5"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.4"
            />
            <path
              d="M10.5 5.5v-1A1.5 1.5 0 0 0 9 3H4a1.5 1.5 0 0 0-1.5 1.5v5A1.5 1.5 0 0 0 4 11h1"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.4"
              strokeLinecap="round"
            />
          </svg>
        )
      }
    />
  );
}
