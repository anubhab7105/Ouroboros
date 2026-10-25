import type { AccountFilters } from '@/types/account';
import type { AlertFilters } from '@/types/alert';
import type { AuditFilters } from '@/types/audit';
import type { CaseFilters } from '@/types/case';
import type { ComplaintFilters } from '@/types/complaint';
import type { MoneyTrailQuery, PathQuery, SharedEntitiesQuery, SubgraphQuery } from '@/types/graph';
import type { TransactionFilters } from '@/types/transaction';

/**
 * React Query cache keys, in one place.
 *
 * Keys are hierarchical so a mutation can invalidate a whole subtree with one
 * call: `invalidateQueries({ queryKey: queryKeys.alerts.all })` catches every
 * alert list and detail regardless of its filters. Scattering ad-hoc key
 * arrays through feature modules is how stale lists survive a mutation.
 *
 * Filter objects are part of the key, so two different filter sets cache
 * separately rather than overwriting each other.
 */

export const queryKeys = {
  auth: {
    all: ['auth'] as const,
    me: () => [...queryKeys.auth.all, 'me'] as const,
  },

  system: {
    all: ['system'] as const,
    health: () => [...queryKeys.system.all, 'health'] as const,
    status: () => [...queryKeys.system.all, 'status'] as const,
    limitations: () => [...queryKeys.system.all, 'limitations'] as const,
  },

  dashboard: {
    all: ['dashboard'] as const,
    overview: (windowDays: number) => [...queryKeys.dashboard.all, 'overview', windowDays] as const,
    metrics: (windowDays: number) => [...queryKeys.dashboard.all, 'metrics', windowDays] as const,
    queues: (assigneeId?: string) => [...queryKeys.dashboard.all, 'queues', assigneeId ?? 'all'] as const,
    trends: (windowDays: number) => [...queryKeys.dashboard.all, 'trends', windowDays] as const,
    riskDistribution: (windowDays: number) =>
      [...queryKeys.dashboard.all, 'risk-distribution', windowDays] as const,
    complaintCategories: (windowDays: number) =>
      [...queryKeys.dashboard.all, 'complaint-categories', windowDays] as const,
  },

  accounts: {
    all: ['accounts'] as const,
    list: (page: number, pageSize: number, filters: AccountFilters, sort?: string) =>
      [...queryKeys.accounts.all, 'list', { page, pageSize, filters, sort }] as const,
    detail: (id: string) => [...queryKeys.accounts.all, 'detail', id] as const,
    summary: (id: string, range?: { date_from?: string; date_to?: string }) =>
      [...queryKeys.accounts.all, 'summary', id, range ?? 'default'] as const,
    transactions: (id: string, page: number, filters: TransactionFilters) =>
      [...queryKeys.accounts.all, 'transactions', id, { page, filters }] as const,
    assessments: (id: string) => [...queryKeys.accounts.all, 'assessments', id] as const,
    assessment: (id: string) => [...queryKeys.accounts.all, 'assessment', id] as const,
    alerts: (id: string) => [...queryKeys.accounts.all, 'alerts', id] as const,
    entities: (id: string) => [...queryKeys.accounts.all, 'entities', id] as const,
    complaints: (id: string) => [...queryKeys.accounts.all, 'complaints', id] as const,
    features: (id: string) => [...queryKeys.accounts.all, 'features', id] as const,
    cases: (id: string) => [...queryKeys.accounts.all, 'cases', id] as const,
  },

  transactions: {
    all: ['transactions'] as const,
    list: (page: number, pageSize: number, filters: TransactionFilters, sort?: string) =>
      [...queryKeys.transactions.all, 'list', { page, pageSize, filters, sort }] as const,
    detail: (id: string) => [...queryKeys.transactions.all, 'detail', id] as const,
    correlations: (id: string) => [...queryKeys.transactions.all, 'correlations', id] as const,
    alerts: (id: string) => [...queryKeys.transactions.all, 'alerts', id] as const,
    evidence: (id: string) => [...queryKeys.transactions.all, 'evidence', id] as const,
  },

  alerts: {
    all: ['alerts'] as const,
    list: (page: number, pageSize: number, filters: AlertFilters, sort?: string) =>
      [...queryKeys.alerts.all, 'list', { page, pageSize, filters, sort }] as const,
    detail: (id: string) => [...queryKeys.alerts.all, 'detail', id] as const,
    evidence: (id: string) => [...queryKeys.alerts.all, 'evidence', id] as const,
    history: (id: string) => [...queryKeys.alerts.all, 'history', id] as const,
  },

  cases: {
    all: ['cases'] as const,
    list: (page: number, pageSize: number, filters: CaseFilters, sort?: string) =>
      [...queryKeys.cases.all, 'list', { page, pageSize, filters, sort }] as const,
    detail: (id: string) => [...queryKeys.cases.all, 'detail', id] as const,
    notes: (id: string, page = 1) => [...queryKeys.cases.all, 'notes', id, page] as const,
    evidence: (id: string, page = 1, evidenceType = '', includeInactive = false) =>
      [...queryKeys.cases.all, 'evidence', id, { page, evidenceType, includeInactive }] as const,
    events: (id: string, page = 1) => [...queryKeys.cases.all, 'events', id, page] as const,
    audit: (id: string, page = 1) => [...queryKeys.cases.all, 'audit', id, page] as const,
    export: (id: string, includeInactive = false) =>
      [...queryKeys.cases.all, 'export', id, includeInactive] as const,
  },

  complaints: {
    all: ['complaints'] as const,
    list: (page: number, pageSize: number, filters: ComplaintFilters, sort?: string) =>
      [...queryKeys.complaints.all, 'list', { page, pageSize, filters, sort }] as const,
    detail: (id: string) => [...queryKeys.complaints.all, 'detail', id] as const,
    correlations: (id: string) => [...queryKeys.complaints.all, 'correlations', id] as const,
    stats: () => [...queryKeys.complaints.all, 'stats'] as const,
  },

  graph: {
    all: ['graph'] as const,
    status: () => [...queryKeys.graph.all, 'status'] as const,
    subgraph: (query: SubgraphQuery) => [...queryKeys.graph.all, 'subgraph', query] as const,
    paths: (query: PathQuery) => [...queryKeys.graph.all, 'paths', query] as const,
    trails: (query: MoneyTrailQuery) => [...queryKeys.graph.all, 'trails', query] as const,
    sharedEntities: (query: SharedEntitiesQuery) =>
      [...queryKeys.graph.all, 'shared-entities', query] as const,
  },

  analysis: {
    all: ['analysis'] as const,
    status: () => [...queryKeys.analysis.all, 'status'] as const,
    runs: (page: number, pageSize: number) =>
      [...queryKeys.analysis.all, 'runs', { page, pageSize }] as const,
    run: (id: string) => [...queryKeys.analysis.all, 'run', id] as const,
    results: (id: string, page: number) =>
      [...queryKeys.analysis.all, 'results', id, page] as const,
  },

  model: {
    all: ['model'] as const,
    status: () => [...queryKeys.model.all, 'status'] as const,
    current: () => [...queryKeys.model.all, 'current'] as const,
    limitations: () => [...queryKeys.model.all, 'limitations'] as const,
    featureSchema: () => [...queryKeys.model.all, 'feature-schema'] as const,
    versions: (page: number, pageSize: number) =>
      [...queryKeys.model.all, 'versions', { page, pageSize }] as const,
    version: (id: string) => [...queryKeys.model.all, 'version', id] as const,
    evaluations: (versionId: string, page: number) =>
      [...queryKeys.model.all, 'evaluations', versionId, page] as const,
    compare: (versionIds: string[]) =>
      [...queryKeys.model.all, 'compare', [...versionIds].sort()] as const,
  },

  reports: {
    all: ['reports'] as const,
    status: () => [...queryKeys.reports.all, 'status'] as const,
    limitations: () => [...queryKeys.reports.all, 'limitations'] as const,
    preview: (caseId: string) => [...queryKeys.reports.all, 'preview', caseId] as const,
    evidenceIndex: (caseId: string) =>
      [...queryKeys.reports.all, 'evidence-index', caseId] as const,
  },

  audit: {
    all: ['audit'] as const,
    status: () => [...queryKeys.audit.all, 'status'] as const,
    list: (page: number, pageSize: number, filters: AuditFilters) =>
      [...queryKeys.audit.all, 'list', { page, pageSize, filters }] as const,
    detail: (id: string) => [...queryKeys.audit.all, 'detail', id] as const,
    stats: (from?: string, to?: string) =>
      [...queryKeys.audit.all, 'stats', from ?? 'any', to ?? 'any'] as const,
  },

  users: {
    all: ['users'] as const,
    list: (page: number, pageSize: number, search?: string) =>
      [...queryKeys.users.all, 'list', { page, pageSize, search }] as const,
    detail: (id: string) => [...queryKeys.users.all, 'detail', id] as const,
  },

  ingestion: {
    all: ['ingestion'] as const,
    status: () => [...queryKeys.ingestion.all, 'status'] as const,
  },
} as const;

/**
 * Keys to invalidate after an analysis run, in dependency order.
 *
 * A run writes assessments, alerts, correlations and graph runs, so almost
 * every list is stale afterwards. Listing them explicitly is better than
 * clearing the whole cache, which would also discard the user's current page
 * of unrelated data.
 */
export const ANALYSIS_RUN_INVALIDATIONS = [
  queryKeys.dashboard.all,
  queryKeys.alerts.all,
  queryKeys.accounts.all,
  queryKeys.analysis.all,
  queryKeys.complaints.all,
  queryKeys.graph.all,
  queryKeys.model.all,
] as const;
