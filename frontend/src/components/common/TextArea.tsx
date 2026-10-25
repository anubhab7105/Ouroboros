import clsx from 'clsx';
import { forwardRef, type TextareaHTMLAttributes } from 'react';

export interface TextAreaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  invalid?: boolean;
  /** Show a live character count, for fields with a server-side limit. */
  showCount?: boolean;
}

/**
 * A multi-line input.
 *
 * `showCount` is for case notes, where the backend caps the body at 10,000
 * characters. Discovering the limit by having a long note rejected on submit
 * is the kind of data loss that makes people distrust a tool.
 */
export const TextArea = forwardRef<HTMLTextAreaElement, TextAreaProps>(function TextArea(
  { invalid = false, showCount = false, className, maxLength, value, rows = 4, ...rest },
  ref,
) {
  const length = typeof value === 'string' ? value.length : 0;
  const nearLimit = Boolean(maxLength && length > maxLength * 0.9);

  return (
    <div className="min-w-0">
      <textarea
        ref={ref}
        rows={rows}
        maxLength={maxLength}
        value={value}
        aria-invalid={invalid || undefined}
        className={clsx(
          'mg-input resize-y',
          invalid && 'border-state-danger focus-visible:ring-state-danger/50',
          className,
        )}
        {...rest}
      />
      {showCount && maxLength ? (
        <p
          className={clsx(
            'mt-1 text-right text-2xs tabular',
            nearLimit ? 'font-medium text-state-warning' : 'text-ink-500 dark:text-ink-400',
          )}
        >
          {length.toLocaleString()} / {maxLength.toLocaleString()}
        </p>
      ) : null}
    </div>
  );
});
