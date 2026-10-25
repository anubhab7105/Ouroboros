import { useEffect, useState, type FormEvent } from 'react';
import { Navigate, useNavigate, useSearchParams } from 'react-router-dom';

import { Button } from '@/components/common/Button';
import { ErrorState } from '@/components/common/ErrorState';
import { FormField } from '@/components/common/FormField';
import { TextInput } from '@/components/common/TextInput';
import { AuthLayout } from '@/components/layout/AuthLayout';
import { useAuth } from '@/features/auth/useAuth';
import { paths } from '@/routes/paths';

/** Only in-application paths are accepted as a post-login destination. */
function safeNext(raw: string | null): string {
  if (!raw) return paths.dashboard;

  try {
    const decoded = decodeURIComponent(raw);

    // A `next` of `//evil.example` or `https://…` would be an open redirect:
    // the browser treats a protocol-relative path as another origin.
    if (!decoded.startsWith('/') || decoded.startsWith('//')) return paths.dashboard;
    if (decoded.startsWith(paths.login)) return paths.dashboard;

    return decoded;
  } catch {
    return paths.dashboard;
  }
}

/**
 * Sign-in.
 *
 * The form does no credential validation beyond "both fields filled". Checking
 * password rules here would tell an attacker which of the two fields was
 * wrong, and would reject a legitimate password set before the rules changed.
 * The server answers with one indistinguishable message either way.
 */
export default function LoginPage() {
  const { login, isLoggingIn, error, clearError, isAuthenticated, isInitialising, signedOutReason } =
    useAuth();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [submitted, setSubmitted] = useState(false);

  const next = safeNext(searchParams.get('next'));

  // Clear a stale error when the user starts editing again.
  useEffect(() => {
    if (error && submitted) setSubmitted(false);
  }, [error, submitted]);

  if (!isInitialising && isAuthenticated) {
    return <Navigate to={next} replace />;
  }

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setSubmitted(true);
    clearError();

    if (!identifier.trim() || !password) return;

    const ok = await login({ identifier: identifier.trim(), password });
    if (ok) navigate(next, { replace: true });
  };

  return (
    <AuthLayout>
      <form onSubmit={handleSubmit} className="space-y-4" noValidate>
        {signedOutReason ? (
          <p
            role="status"
            className="rounded-md border border-ink-200 bg-ink-50 p-2.5 text-2xs text-ink-700 dark:border-ink-700 dark:bg-ink-800/60 dark:text-ink-200"
          >
            {signedOutReason}
          </p>
        ) : null}

        {error ? <ErrorState error={error} compact /> : null}

        <FormField
          label="Username or email"
          required
          hint="Either works; the server decides which you gave it."
          error={submitted && !identifier.trim() ? 'Enter your username or email.' : undefined}
        >
          {({ id, describedBy, invalid }) => (
            <TextInput
              id={id}
              aria-describedby={describedBy}
              invalid={invalid}
              name="identifier"
              value={identifier}
              onChange={(event) => setIdentifier(event.target.value)}
              autoComplete="username"
              autoFocus
              required
            />
          )}
        </FormField>

        <FormField
          label="Password"
          required
          error={submitted && !password ? 'Enter your password.' : undefined}
        >
          {({ id, describedBy, invalid }) => (
            <TextInput
              id={id}
              aria-describedby={describedBy}
              invalid={invalid}
              name="password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="current-password"
              required
            />
          )}
        </FormField>

        <Button type="submit" variant="primary" fullWidth isLoading={isLoggingIn}>
          Sign in
        </Button>

        <p className="text-2xs leading-relaxed text-ink-500 dark:text-ink-400">
          Repeated failed attempts lock the account. Every sign-in, successful or not, is recorded
          in the audit trail.
        </p>
      </form>
    </AuthLayout>
  );
}
