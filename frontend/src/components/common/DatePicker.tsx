import clsx from 'clsx';
import { forwardRef, type InputHTMLAttributes } from 'react';

export interface DatePickerProps
  extends Omit<InputHTMLAttributes<HTMLInputElement>, 'type' | 'value' | 'onChange'> {
  /** `YYYY-MM-DD`, or empty. */
  value: string;
  onValueChange: (value: string) => void;
  invalid?: boolean;
  /** Prevent choosing a future date. */
  noFuture?: boolean;
}

/**
 * A date input.
 *
 * `<input type="date">` rather than a custom calendar: it is keyboard
 * accessible, localised by the browser, and uses the platform picker on
 * mobile.
 *
 * `noFuture` sets `max` to today for the filters where a future date is
 * meaningless — an analysis `as_of` in the future would silently match
 * nothing, which looks like a clean result rather than an empty one.
 */
export const DatePicker = forwardRef<HTMLInputElement, DatePickerProps>(function DatePicker(
  { value, onValueChange, invalid = false, noFuture = false, className, ...rest },
  ref,
) {
  const today = new Date().toISOString().slice(0, 10);

  return (
    <input
      ref={ref}
      type="date"
      value={value}
      max={noFuture ? today : rest.max}
      onChange={(event) => onValueChange(event.target.value)}
      aria-invalid={invalid || undefined}
      className={clsx(
        'mg-input',
        invalid && 'border-state-danger focus-visible:ring-state-danger/50',
        className,
      )}
      {...rest}
    />
  );
});
