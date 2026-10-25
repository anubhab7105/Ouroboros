import { Suspense, lazy, type ComponentType } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';

import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { AppLayout } from '@/components/layout/AppLayout';
import { ProtectedRoute } from '@/components/layout/ProtectedRoute';
import { RoleGate } from '@/components/layout/RoleGate';
import { PERMISSIONS, type Permission } from '@/lib/permissions';
import { paths } from '@/routes/paths';

/**
 * Routing.
 *
 * Pages are code-split per route. The graph page alone pulls in Cytoscape,
 * which is larger than the rest of the application put together; loading it
 * for someone who only ever triages alerts would be a tax on every page load.
 *
 * Each route declares the permissions that admit it, and the gate renders an
 * explanation naming who *can* open the page rather than a bare 403. The
 * server enforces the same permissions independently.
 */

const Dashboard = lazy(() => import('@/features/dashboard/DashboardPage'));
const Accounts = lazy(() => import('@/features/accounts/AccountsPage'));
const AccountDetail = lazy(() => import('@/features/accounts/AccountDetailPage'));
const Transactions = lazy(() => import('@/features/transactions/TransactionsPage'));
const Alerts = lazy(() => import('@/features/alerts/AlertsPage'));
const Cases = lazy(() => import('@/features/cases/CasesPage'));
const CaseDetail = lazy(() => import('@/features/cases/CaseDetailPage'));
const Complaints = lazy(() => import('@/features/complaints/ComplaintsPage'));
const Graph = lazy(() => import('@/features/graph/GraphPage'));
const Reports = lazy(() => import('@/features/reports/ReportsPage'));
const ModelMonitoring = lazy(() => import('@/features/model-monitoring/ModelMonitoringPage'));
const Ingestion = lazy(() => import('@/features/ingestion/IngestionPage'));
const Audit = lazy(() => import('@/features/system/AuditPage'));
const ServiceStatus = lazy(() => import('@/features/system/ServiceStatusPage'));
const Login = lazy(() => import('@/features/auth/LoginPage'));
const NotFound = lazy(() => import('@/features/system/NotFoundPage'));
const Forbidden = lazy(() => import('@/features/system/ForbiddenPage'));

function RouteFallback() {
  return (
    <div className="flex min-h-[40vh] items-center justify-center">
      <LoadingSpinner size="lg" label="Loading page" />
    </div>
  );
}

/** Wrap a lazy page in its permission gate and suspense boundary. */
function Guarded({
  component: Component,
  permissions,
  action,
}: {
  component: ComponentType;
  permissions?: Array<Permission | string>;
  action?: string;
}) {
  return (
    <RoleGate permissions={permissions} action={action}>
      <Suspense fallback={<RouteFallback />}>
        <Component />
      </Suspense>
    </RoleGate>
  );
}

export function AppRoutes() {
  return (
    <Routes>
      <Route
        path={paths.login}
        element={
          <Suspense fallback={<RouteFallback />}>
            <Login />
          </Suspense>
        }
      />

      <Route element={<ProtectedRoute />}>
        <Route element={<AppLayout />}>
          <Route path={paths.root} element={<Navigate to={paths.dashboard} replace />} />

          <Route
            path={paths.dashboard}
            element={
              <Guarded
                component={Dashboard}
                permissions={[PERMISSIONS.readDashboard]}
                action="see the dashboard"
              />
            }
          />

          <Route
            path={paths.accounts}
            element={
              <Guarded
                component={Accounts}
                action="browse accounts"
              />
            }
          />
          <Route
            path={paths.accountPattern}
            element={
              <Guarded
                component={AccountDetail}
                action="open an account"
              />
            }
          />

          <Route
            path={paths.transactions}
            element={
              <Guarded
                component={Transactions}
                action="browse transactions"
              />
            }
          />

          <Route
            path={paths.alerts}
            element={
              <Guarded
                component={Alerts}
                action="see alerts"
              />
            }
          />
          {/* A single alert is the list page with its detail drawer open, so
              that closing the drawer returns to the queue the analyst was
              working through rather than to an empty list. */}
          <Route
            path={paths.alertPattern}
            element={
              <Guarded
                component={Alerts}
                action="open an alert"
              />
            }
          />

          <Route
            path={paths.cases}
            element={
              <Guarded component={Cases} />
            }
          />
          <Route
            path={paths.casePattern}
            element={
              <Guarded
                component={CaseDetail}
                action="open a case"
              />
            }
          />

          <Route
            path={paths.complaints}
            element={
              <Guarded
                component={Complaints}
                action="see complaints"
              />
            }
          />

          <Route
            path={paths.graph}
            element={
              <Guarded
                component={Graph}
                action="explore the network"
              />
            }
          />

          <Route
            path={paths.reports}
            element={
              <Guarded
                component={Reports}
                action="see reports"
              />
            }
          />

          <Route
            path={paths.modelMonitoring}
            element={
              <Guarded
                component={ModelMonitoring}
                action="see model monitoring"
              />
            }
          />

          <Route
            path={paths.ingestion}
            element={
              <Guarded
                component={Ingestion}
                permissions={[PERMISSIONS.runIngestion, PERMISSIONS.runAnalysis]}
                action="load data or run analysis"
              />
            }
          />

          <Route
            path={paths.audit}
            element={
              <Guarded
                component={Audit}
                permissions={[PERMISSIONS.readAudit]}
                action="see the audit trail"
              />
            }
          />

          {/* Service status needs no permission: it is what you look at when
              something is not working, including your own access. */}
          <Route
            path={paths.serviceStatus}
            element={
              <Suspense fallback={<RouteFallback />}>
                <ServiceStatus />
              </Suspense>
            }
          />

          <Route
            path={paths.forbidden}
            element={
              <Suspense fallback={<RouteFallback />}>
                <Forbidden />
              </Suspense>
            }
          />

          <Route
            path={paths.notFound}
            element={
              <Suspense fallback={<RouteFallback />}>
                <NotFound />
              </Suspense>
            }
          />
        </Route>
      </Route>
    </Routes>
  );
}
