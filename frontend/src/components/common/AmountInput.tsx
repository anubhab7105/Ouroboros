import clsx from 'clsx';
import { forwardRef, type InputHTMLAttributes } from 'react';

export interface AmountInputProps
  extends Omit<InputHTMLAttributes<HTMLInputElement>, 'type' | 'value' | 'onChange'> {
  value: string;
  onValueChange: (value: string) => void;
  currency?: string;
  invalid?: boolean;
}

/**
 * A monetary input.
 *
 * Kept as a string rather than a number in state: parsing on each keystroke
 * makes "1." and a leading "0" impossible to type, and an empty field becomes
 * `NaN`. The caller parses once on submit.
 *
 * `inputMode="decimal"` gives the numeric keypad on mobile while still
 * allowing a decimal separator.
 */
export const AmountInput = forwardRef<HTMLInputElement, AmountInputProps>(function AmountInput(
  { value, onValueChange, currency, invalid = false, className, ...rest },
  ref,
) {
  return (
    <div className="relative">
      <input
        ref={ref}
        type="text"
        inputMode="decimal"
        value={value}
        onChange={(event) => {
          const next = event.target.value;
          // Digits, one decimal point, optional leading minus.
          if (next === '' || /^-?\d*\.?\d{0,2}$/.test(next)) {
            onValueChange(next);
          }
        }}
        aria-invalid={invalid || undefined}
        className={clsx(
          'mg-input text-right font-mono tabular',
          currency && 'pr-12',
          invalid && 'border-state-danger focus-visible:ring-state-danger/50',
          className,
        )}
        {...rest}
      />
      {currency ? (
        <span className="pointer-events-none absolute inset-y-0 right-2.5 flex items-center text-2xs font-semibold text-ink-500 dark:text-ink-400">
          {currency.toUpperCase()}
        </span>
      ) : null}
    </div>
  );
});
