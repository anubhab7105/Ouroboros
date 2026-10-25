import { Component, type ErrorInfo, type ReactNode } from 'react';

/**
 * Top-level error boundary.
 *
 * A render error in one panel must not blank the whole application. The
 * fallback shows what failed and offers a reload, and it prints the error text
 * rather than hiding it: this is an internal tool, and an analyst reporting a
 * problem is far more useful to a developer when they can paste the message.
 *
 * React does not catch errors in event handlers or async code with a boundary,
 * so this is a backstop for render-time failures only. Request failures are
 * handled per-query by `ErrorState`.
 */

interface Props {
  children: ReactNode;
  /** Label for the region, so the message says what broke. */
  label?: string;
  fallback?: ReactNode;
}

interface State {
  error: Error | null;
  componentStack: string | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null, componentStack: null };

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // Kept as console.error on purpose: there is no error-reporting backend in
    // this prototype, and swallowing it would make the failure invisible.
    console.error('[MULEGUARD] render error', error, info.componentStack);
    this.setState({ componentStack: info.componentStack ?? null });
  }

  private handleReset = (): void => {
    this.setState({ error: null, componentStack: null });
  };

  private handleReload = (): void => {
    window.location.reload();
  };

  render(): ReactNode {
    const { error, componentStack } = this.state;
    const { children, fallback, label } = this.props;

    if (!error) return children;
    if (fallback) return fallback;

    return (
      <div
        role="alert"
        className="m-4 rounded-card border border-state-danger/40 bg-red-50 p-6 dark:bg-red-950/30"
      >
        <h2 className="text-base font-semibold text-red-900 dark:text-red-200">
          {label ? `${label} failed to render` : 'Something went wrong'}
        </h2>
        <p className="mt-2 max-w-2xl text-sm text-red-900/90 dark:text-red-200/90">
          This part of the interface hit an unexpected error. Your data is not
          affected — nothing was saved or changed by this failure.
        </p>

        <pre className="mt-3 max-h-48 overflow-auto rounded border border-red-200 bg-white/70 p-3 font-mono text-2xs text-red-900 dark:border-red-900 dark:bg-ink-900 dark:text-red-200">
          {error.message}
          {componentStack ? `\n${componentStack}` : ''}
        </pre>

        <div className="mt-4 flex gap-2">
          <button
            type="button"
            onClick={this.handleReset}
            className="rounded-md bg-accent-700 px-3 py-1.5 text-xs font-semibold text-white hover:bg-accent-800"
          >
            Try again
          </button>
          <button
            type="button"
            onClick={this.handleReload}
            className="rounded-md border border-ink-300 px-3 py-1.5 text-xs font-semibold text-ink-700 hover:bg-ink-100 dark:border-ink-600 dark:text-ink-200 dark:hover:bg-ink-800"
          >
            Reload the page
          </button>
        </div>
      </div>
    );
  }
}
