import clsx from 'clsx';
import { forwardRef, type SelectHTMLAttributes } from 'react';

export interface SelectOption {
  value: string;
  label: string;
  disabled?: boolean;
}

export interface SelectProps extends Omit<SelectHTMLAttributes<HTMLSelectElement>, 'children'> {
  options: SelectOption[];
  /** Label for the empty option, e.g. "Any status". Omit to require a choice. */
  placeholder?: string;
  invalid?: boolean;
}

/**
 * A native select.
 *
 * Native rather than a custom listbox: it gets keyboard behaviour, mobile
 * pickers and screen-reader support for free, and every select in this app is
 * a short list of known enum values where a custom widget would add risk
 * without adding anything.
 *
 * `placeholder` renders as an empty-valued option, which is how a filter is
 * cleared — the API treats an absent parameter as "no filter".
 */
export const Select = forwardRef<HTMLSelectElement, SelectProps>(function Select(
  { options, placeholder, invalid = false, className, ...rest },
  ref,
) {
  return (
    <select
      ref={ref}
      aria-invalid={invalid || undefined}
      className={clsx(
        'mg-input pr-8',
        invalid && 'border-state-danger focus-visible:ring-state-danger/50',
        className,
      )}
      {...rest}
    >
      {placeholder ? <option value="">{placeholder}</option> : null}
      {options.map((option) => (
        <option key={option.value} value={option.value} disabled={option.disabled}>
          {option.label}
        </option>
      ))}
    </select>
  );
});
