import clsx from 'clsx';
import { forwardRef, type InputHTMLAttributes } from 'react';

export interface TextInputProps extends InputHTMLAttributes<HTMLInputElement> {
  invalid?: boolean;
  /** Monospace, for identifiers and references. */
  mono?: boolean;
}

export const TextInput = forwardRef<HTMLInputElement, TextInputProps>(function TextInput(
  { invalid = false, mono = false, className, ...rest },
  ref,
) {
  return (
    <input
      ref={ref}
      aria-invalid={invalid || undefined}
      className={clsx(
        'mg-input',
        mono && 'font-mono text-xs',
        invalid && 'border-state-danger focus-visible:ring-state-danger/50',
        className,
      )}
      {...rest}
    />
  );
});
