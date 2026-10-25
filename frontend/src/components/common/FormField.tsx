import clsx from 'clsx';
import { useId, type ReactNode } from 'react';

export interface FormFieldProps {
  label: string;
  children: (props: { id: string; describedBy?: string; invalid: boolean }) => ReactNode;
  hint?: string;
  error?: string;
  required?: boolean;
  className?: string;
}

/**
 * Label, control, hint and error, wired together.
 *
 * The render-prop shape exists so the control receives the generated `id` and
 * `aria-describedby` rather than the caller having to remember them. A label
 * that is not programmatically associated with its input is a label a screen
 * reader cannot announce, and hand-wiring ids is where that always breaks.
 */
export function FormField({
  label,
  children,
  hint,
  error,
  required = false,
  className,
}: FormFieldProps) {
  const id = useId();
  const hintId = hint ? `${id}-hint` : undefined;
  const errorId = error ? `${id}-error` : undefined;
  const describedBy = [errorId, hintId].filter(Boolean).join(' ') || undefined;

  return (
    <div className={clsx('min-w-0', className)}>
      <label htmlFor={id} className="mg-label">
        {label}
        {required ? (
          <span className="ml-0.5 text-state-danger" aria-hidden="true">
            *
          </span>
        ) : null}
        {required ? <span className="mg-visually-hidden"> (required)</span> : null}
      </label>

      {children({ id, describedBy, invalid: Boolean(error) })}

      {error ? (
        <p id={errorId} className="mg-error-text" role="alert">
          {error}
        </p>
      ) : null}
      {hint && !error ? (
        <p id={hintId} className="mg-hint">
          {hint}
        </p>
      ) : null}
    </div>
  );
}
