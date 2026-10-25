import type { CapabilityName, CurrentUser, UserRole } from '@/types/auth';

/**
 * What the signed-in user may do, for deciding what to render.
 *
 * The server answers this question directly: `/auth/me` returns a map of
 * capability booleans, resolved from the user's role and from whatever role
 * overrides the deployment has configured. The frontend reads that map rather
 * than re-deriving permissions from the role, because a deployment that has
 * widened `CASE_CLOSE_ROLES` would otherwise have an interface that disagrees
 * with its own backend.
 *
 * None of this is a security control. Every protected endpoint re-resolves the
 * real permission on every request, so editing a capability in a console
 * yields a visible button that returns 403, not access.
 *
 * Hiding an action the user cannot take is still worth doing — an investigator
 * should not be offered a control that will fail — but the honest version is
 * to explain who *can* do it where the action is discoverable, which is what
 * `PermissionDeniedState` and `RoleGate` do.
 */

export const CAPABILITIES = {
  readDashboard: 'read_dashboard',
  runAnalysis: 'run_analysis',
  triageAlerts: 'triage_alerts',
  assignAlerts: 'assign_alerts',
  escalateAlerts: 'escalate_alerts',
  createCase: 'create_case',
  assignCase: 'assign_case',
  closeCase: 'close_case',
  reopenCase: 'reopen_case',
  addCaseNote: 'add_case_note',
  addCaseEvidence: 'add_case_evidence',
  removeCaseEvidence: 'remove_case_evidence',
  readAudit: 'read_audit',
  exportAudit: 'export_audit',
  manageUsers: 'manage_users',
  readConfig: 'read_config',
  writeConfig: 'write_config',
  runIngestion: 'run_ingestion',
  trainModel: 'train_model',
  evaluateModel: 'evaluate_model',
  generateReport: 'generate_report',
  downloadReport: 'download_report',
  readComplaintNarrative: 'read_complaint_narrative',
} as const satisfies Record<string, CapabilityName>;

/** Kept as the name the rest of the application already imports. */
export const PERMISSIONS = CAPABILITIES;

export type Capability = (typeof CAPABILITIES)[keyof typeof CAPABILITIES];
export type Permission = Capability;

const ROLE_RANK: Record<string, number> = {
  AUDITOR: 1,
  ANALYST: 2,
  SENIOR_INVESTIGATOR: 3,
  ADMIN: 4,
};

/**
 * The roles each capability is granted to by default.
 *
 * Used only for the explanatory half of a denial — "senior investigators and
 * administrators can close a case" — never to decide access. A deployment may
 * have overridden any of these, in which case this table is a reasonable
 * guess and the server's capability map is the truth.
 */
const DEFAULT_ROLES: Record<string, UserRole[]> = {
  read_dashboard: ['ADMIN', 'SENIOR_INVESTIGATOR', 'ANALYST', 'AUDITOR'],
  run_analysis: ['ANALYST', 'SENIOR_INVESTIGATOR', 'ADMIN'],
  triage_alerts: ['ANALYST', 'SENIOR_INVESTIGATOR', 'ADMIN'],
  assign_alerts: ['SENIOR_INVESTIGATOR', 'ADMIN'],
  escalate_alerts: ['SENIOR_INVESTIGATOR', 'ADMIN'],
  create_case: ['ANALYST', 'SENIOR_INVESTIGATOR', 'ADMIN'],
  assign_case: ['SENIOR_INVESTIGATOR', 'ADMIN'],
  close_case: ['SENIOR_INVESTIGATOR', 'ADMIN'],
  reopen_case: ['SENIOR_INVESTIGATOR', 'ADMIN'],
  add_case_note: ['ANALYST', 'SENIOR_INVESTIGATOR', 'ADMIN'],
  add_case_evidence: ['ANALYST', 'SENIOR_INVESTIGATOR', 'ADMIN'],
  remove_case_evidence: ['SENIOR_INVESTIGATOR', 'ADMIN'],
  read_audit: ['AUDITOR', 'ADMIN'],
  export_audit: ['ADMIN'],
  manage_users: ['ADMIN'],
  read_config: ['ADMIN'],
  write_config: ['ADMIN'],
  run_ingestion: ['ADMIN'],
  train_model: ['ADMIN'],
  evaluate_model: ['ADMIN'],
  generate_report: ['ANALYST', 'SENIOR_INVESTIGATOR', 'ADMIN'],
  download_report: ['ADMIN', 'SENIOR_INVESTIGATOR', 'ANALYST', 'AUDITOR'],
  read_complaint_narrative: ['SENIOR_INVESTIGATOR', 'ADMIN'],
};

/** Which roles can perform a capability, for an explanatory denial. */
export function rolesForPermission(capability: string): UserRole[] {
  return DEFAULT_ROLES[capability] ?? [];
}

/** The capabilities the server granted this user, as a set of names. */
export function effectivePermissions(user: CurrentUser | null): Set<string> {
  if (!user || !user.is_active) return new Set();

  return new Set(
    Object.entries(user.capabilities ?? {})
      .filter(([, granted]) => granted === true)
      .map(([name]) => name),
  );
}

export function can(user: CurrentUser | null, capability: Capability | string): boolean {
  if (!user || !user.is_active) return false;
  return user.capabilities?.[capability] === true;
}

export function canAny(user: CurrentUser | null, capabilities: Array<Capability | string>): boolean {
  if (capabilities.length === 0) return true;
  return capabilities.some((capability) => can(user, capability));
}

export function canAll(user: CurrentUser | null, capabilities: Array<Capability | string>): boolean {
  if (capabilities.length === 0) return true;
  return capabilities.every((capability) => can(user, capability));
}

/**
 * True when the user may read the investigation surfaces.
 *
 * Accounts, transactions, alerts, cases, complaints and the network graph are
 * granted to every role, so the server publishes no capability flag for them.
 * Any active user can read them; an inactive one can do nothing at all.
 */
export function canRead(user: CurrentUser | null): boolean {
  return Boolean(user?.is_active);
}

export function hasRole(user: CurrentUser | null, ...roles: UserRole[]): boolean {
  return Boolean(user && roles.includes(user.role as UserRole));
}

/** True when the user's role ranks at or above `minimum`. */
export function roleAtLeast(user: CurrentUser | null, minimum: UserRole): boolean {
  if (!user) return false;
  return (ROLE_RANK[user.role] ?? 0) >= (ROLE_RANK[minimum] ?? 0);
}

/** Fallback labels. The server's `role_display_name` is preferred. */
export const ROLE_LABELS: Record<string, string> = {
  ADMIN: 'Administrator',
  SENIOR_INVESTIGATOR: 'Senior investigator',
  ANALYST: 'Analyst',
  AUDITOR: 'Auditor',
};

export const ROLE_DESCRIPTIONS: Record<string, string> = {
  ADMIN:
    'Full access, including loading data, managing users and training models. Every administrative action is recorded in the audit trail.',
  SENIOR_INVESTIGATOR:
    'Everything an analyst can do, plus assigning and escalating alerts, closing and reopening cases, removing evidence, reviewing complaint correlations and reading complaint narratives.',
  ANALYST:
    'Triage alerts, open and work cases, add notes and evidence, run analysis and generate reports. Cannot close a case, assign work to others, or read a complaint narrative.',
  AUDITOR:
    'Read-only across the investigation surfaces, plus the audit trail. An auditor who could close a case would be reviewing their own work, so they cannot.',
};
