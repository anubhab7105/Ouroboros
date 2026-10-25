/**
 * Route paths, in one place.
 *
 * Builders rather than string literals so a route rename is one edit, and so
 * a link can never be assembled from a stale pattern. The `pattern` values are
 * what `<Route path>` receives; the functions are what `<Link to>` receives.
 */

export const paths = {
  root: '/',
  login: '/login',

  dashboard: '/dashboard',

  accounts: '/accounts',
  account: (id: string) => `/accounts/${encodeURIComponent(id)}`,
  accountPattern: '/accounts/:accountId',

  transactions: '/transactions',

  alerts: '/alerts',
  alertPattern: '/alerts/:alertId',
  alert: (id: string) => `/alerts/${encodeURIComponent(id)}`,

  cases: '/cases',
  casePattern: '/cases/:caseId',
  case: (id: string) => `/cases/${encodeURIComponent(id)}`,

  complaints: '/complaints',
  complaint: (id: string) => `/complaints?complaintId=${encodeURIComponent(id)}`,

  graph: '/graph',
  /** Open the graph rooted at one account. */
  graphForAccount: (accountId: string) =>
    `/graph?root=${encodeURIComponent(accountId)}`,

  reports: '/reports',
  modelMonitoring: '/model',
  ingestion: '/ingestion',
  audit: '/audit',

  serviceStatus: '/status',
  forbidden: '/forbidden',
  notFound: '*',
} as const;

/** Breadcrumb labels per top-level section. */
export const SECTION_LABELS: Record<string, string> = {
  dashboard: 'Dashboard',
  accounts: 'Accounts',
  transactions: 'Transactions',
  alerts: 'Alerts',
  cases: 'Cases',
  complaints: 'Complaints',
  graph: 'Network',
  reports: 'Reports',
  model: 'Model monitoring',
  ingestion: 'Data',
  audit: 'Audit trail',
  status: 'Service status',
};
