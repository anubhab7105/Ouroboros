import { AppProviders } from '@/app/providers';
import { AppRoutes } from '@/app/router';

/**
 * The application root.
 *
 * Deliberately thin: providers in one file, routes in another, so that
 * neither has to be read to understand the other.
 */
export default function App() {
  return (
    <AppProviders>
      <AppRoutes />
    </AppProviders>
  );
}
