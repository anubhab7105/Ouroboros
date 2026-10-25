/**
 * The API surface, as paths.
 *
 * Every endpoint the frontend calls is declared here and nowhere else. A URL
 * built inline in a feature module is a URL that silently rots when the
 * backend route changes; collecting them means a route rename is one edit and
 * a grep confirms the coverage.
 *
 * Paths are relative to `API_BASE_URL` (`/api/v1` by default) and mirror the
 * mounted prefixes in `app/api/v1/__init__.py` exactly.
 */

const encode = (value: string): string => encodeURIComponent(String(value));

export const endpoints = {
  // --------------------------------------------------------------- health
  health: {
    live: () => '/health/live',
    ready: () => '/health/ready',
    root: () => '/health',
    status: () => '/health/status',
  },

  // ----------------------------------------------------------------- auth
  auth: {
    login: () => '/auth/login',
    me: () => '/auth/me',
    changePassword: () => '/auth/password/change',
  },


  // ------------------------------------------------------------ dashboard
  // The dashboard exposes exactly these five. Risk distribution and
  // complaint categories are not endpoints of their own: they arrive as
  // breakdown maps inside `/dashboard/overview`.
  dashboard: {
    status: () => '/dashboard/status',
    overview: () => '/dashboard/overview',
    metrics: () => '/dashboard/metrics',
    queues: () => '/dashboard/queues',
    trends: () => '/dashboard/trends',
  },

  // ------------------------------------------------------------- accounts
  accounts: {
    list: () => '/accounts',
    detail: (id: string) => `/accounts/${encode(id)}`,
    summary: (id: string) => `/accounts/${encode(id)}/summary`,
    transactions: (id: string) => `/accounts/${encode(id)}/transactions`,
    assessment: (id: string) => `/accounts/${encode(id)}/assessment`,
    assessments: (id: string) => `/accounts/${encode(id)}/assessments`,
    alerts: (id: string) => `/accounts/${encode(id)}/alerts`,
    entities: (id: string) => `/accounts/${encode(id)}/entities`,
    complaintCorrelations: (id: string) => `/accounts/${encode(id)}/complaint-correlations`,
  },

  // --------------------------------------------------------- transactions
  transactions: {
    list: () => '/transactions',
    detail: (id: string) => `/transactions/${encode(id)}`,
    complaintCorrelations: (id: string) => `/transactions/${encode(id)}/complaint-correlations`,
    alerts: (id: string) => `/transactions/${encode(id)}/alerts`,
    evidence: (id: string) => `/transactions/${encode(id)}/evidence`,
  },

  // --------------------------------------------------------------- alerts
  alerts: {
    list: () => '/alerts',
    detail: (id: string) => `/alerts/${encode(id)}`,
    evidence: (id: string) => `/alerts/${encode(id)}/evidence`,
    history: (id: string) => `/alerts/${encode(id)}/history`,
    acknowledge: (id: string) => `/alerts/${encode(id)}/acknowledge`,
    assign: (id: string) => `/alerts/${encode(id)}/assign`,
    escalate: (id: string) => `/alerts/${encode(id)}/escalate`,
    close: (id: string) => `/alerts/${encode(id)}/close`,
    reopen: (id: string) => `/alerts/${encode(id)}/reopen`,
    createCase: (id: string) => `/alerts/${encode(id)}/case`,
  },

  // ---------------------------------------------------------------- cases
  cases: {
    list: () => '/cases',
    create: () => '/cases',
    detail: (id: string) => `/cases/${encode(id)}`,
    update: (id: string) => `/cases/${encode(id)}`,
    assign: (id: string) => `/cases/${encode(id)}/assign`,
    start: (id: string) => `/cases/${encode(id)}/start`,
    escalate: (id: string) => `/cases/${encode(id)}/escalate`,
    close: (id: string) => `/cases/${encode(id)}/close`,
    reopen: (id: string) => `/cases/${encode(id)}/reopen`,
    notes: (id: string) => `/cases/${encode(id)}/notes`,
    evidence: (id: string) => `/cases/${encode(id)}/evidence`,
    removeEvidence: (caseId: string, evidenceId: string) =>
      `/cases/${encode(caseId)}/evidence/${encode(evidenceId)}/remove`,
    events: (id: string) => `/cases/${encode(id)}/events`,
    audit: (id: string) => `/cases/${encode(id)}/audit`,
    export: (id: string) => `/cases/${encode(id)}/export`,
  },

  // ----------------------------------------------------------- complaints
  complaints: {
    list: () => '/complaints',
    stats: () => '/complaints/stats',
    detail: (id: string) => `/complaints/${encode(id)}`,
    correlations: (id: string) => `/complaints/${encode(id)}/correlations`,
    reviewCorrelation: (complaintId: string, correlationId: string) =>
      `/complaints/${encode(complaintId)}/correlations/${encode(correlationId)}/review-state`,
    accounts: (id: string) => `/complaints/${encode(id)}/accounts`,
    transactions: (id: string) => `/complaints/${encode(id)}/transactions`,
    entities: (id: string) => `/complaints/${encode(id)}/entities`,
    alerts: (id: string) => `/complaints/${encode(id)}/alerts`,
    history: (id: string) => `/complaints/${encode(id)}/history`,
    export: (id: string) => `/complaints/${encode(id)}/export`,
  },

  // ------------------------------------------------------------- entities
  entities: {
    list: () => '/entities',
    detail: (id: string) => `/entities/${encode(id)}`,
    accounts: (id: string) => `/entities/${encode(id)}/accounts`,
    verifyLink: (entityId: string, linkId: string) =>
      `/entities/${encode(entityId)}/links/${encode(linkId)}/verification-state`,
    complaintCorrelations: (id: string) => `/entities/${encode(id)}/complaint-correlations`,
    alerts: (id: string) => `/entities/${encode(id)}/alerts`,
  },

  // ---------------------------------------------------------------- graph
  graph: {
    status: () => '/graph/status',
    subgraph: () => '/graph/subgraph',
    paths: () => '/graph/paths',
    sharedEntities: () => '/graph/shared-entities',
    moneyTrails: () => '/graph/money-trails',
  },

  // ------------------------------------------------------------- analysis
  analysis: {
    status: () => '/analysis/status',
    runs: () => '/analysis/runs',
    createRun: () => '/analysis/runs',
    run: (id: string) => `/analysis/runs/${encode(id)}`,
    results: (id: string) => `/analysis/runs/${encode(id)}/results`,
    history: (id: string) => `/analysis/runs/${encode(id)}/history`,
    cancel: (id: string) => `/analysis/runs/${encode(id)}/cancel`,
  },

  // ---------------------------------------------------------------- model
  model: {
    status: () => '/model/status',
    current: () => '/model/current',
    limitations: () => '/model/limitations',
    featureSchema: () => '/model/feature-schema',
    versions: () => '/model/versions',
    version: (id: string) => `/model/versions/${encode(id)}`,
    versionEvaluations: (id: string) => `/model/versions/${encode(id)}/evaluations`,
    evaluation: (id: string) => `/model/evaluations/${encode(id)}`,
    compare: () => '/model/compare',
  },

  // -------------------------------------------------------------- reports
  reports: {
    status: () => '/reports/status',
    limitations: () => '/reports/limitations',
    casePreview: (id: string) => `/reports/cases/${encode(id)}/preview`,
    caseEvidenceIndex: (id: string) => `/reports/cases/${encode(id)}/evidence-index`,
    caseDownload: (id: string) => `/reports/cases/${encode(id)}`,
    caseGenerate: (id: string) => `/reports/cases/${encode(id)}/generate`,
  },

  // ------------------------------------------------------------ ingestion
  ingestion: {
    status: () => '/ingestion/status',
    accounts: () => '/ingestion/accounts',
    transactions: () => '/ingestion/transactions',
    complaints: () => '/ingestion/complaints',
    entities: () => '/ingestion/entities',
    entityLinks: () => '/ingestion/entity-links',
  },

  // ---------------------------------------------------------------- audit
  audit: {
    status: () => '/audit/status',
    list: () => '/audit',
    stats: () => '/audit/stats',
    export: () => '/audit/export',
    detail: (id: string) => `/audit/${encode(id)}`,
  },

  // ---------------------------------------------------------------- users
  users: {
    list: () => '/users',
    create: () => '/users',
    detail: (id: string) => `/users/${encode(id)}`,
    update: (id: string) => `/users/${encode(id)}`,
    deactivate: (id: string) => `/users/${encode(id)}/deactivate`,
    reactivate: (id: string) => `/users/${encode(id)}/reactivate`,
    unlock: (id: string) => `/users/${encode(id)}/unlock`,
    resetPassword: (id: string) => `/users/${encode(id)}/reset-password`,
  },
} as const;

/**
 * Drop empty values from a query parameter object.
 *
 * The API rejects unknown and malformed parameters rather than ignoring them
 * (`extra="forbid"` on request schemas), so sending `status=""` from a cleared
 * filter is a 422 rather than "no filter". Stripping them here is what makes
 * "clear this filter" work.
 */
export function cleanParams(params: object): Record<string, unknown> {
  const out: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) continue;
    if (typeof value === 'string' && value.trim() === '') continue;
    if (Array.isArray(value) && value.length === 0) continue;

    out[key] = value;
  }

  return out;
}

/**
 * Build the standard pagination and sort parameters.
 *
 * The keys are the API's own — `page_size`, `sort_by`, `sort_order` — rather
 * than camelCase equivalents. Translating here would mean every caller
 * silently depended on the translation, and a caller that passed the API's
 * names (the obvious thing to do) would have them dropped by `cleanParams`
 * with no error. Keeping one spelling end to end removes that trap.
 */
export function pageParams(options: {
  page?: number;
  page_size?: number;
  sort_by?: string;
  sort_order?: 'asc' | 'desc' | string;
}): Record<string, unknown> {
  return cleanParams({
    page: options.page,
    page_size: options.page_size,
    sort_by: options.sort_by,
    sort_order: options.sort_order,
  });
}
