import type { Iso8601, PageResponse } from './common';

/** Audit types, mirroring `app/api/v1/endpoints/audit.py`. */

export type AuditOutcome = 'SUCCESS' | 'FAILURE' | 'DENIED' | 'WARNING';

/**
 * One audit entry.
 *
 * `ip_hash` and `user_agent_hash` arrive hashed and are displayed as hashes.
 * They exist to let an auditor tell two sessions apart, not to locate a
 * person, so nothing in the UI attempts to resolve them.
 */
export interface AuditEvent {
  id: string;
  action: string;
  outcome: string;
  actor_id?: string | null;
  actor_username?: string | null;
  actor_role?: string | null;
  resource_type?: string | null;
  resource_id?: string | null;
  request_id?: string | null;
  correlation_id?: string | null;
  ip_hash?: string | null;
  user_agent_hash?: string | null;
  metadata_json?: Record<string, unknown> | null;
  created_at: Iso8601;
}

export type AuditListResponse = PageResponse<AuditEvent>;

export interface AuditFilters {
  actor_id?: string;
  actor_username?: string;
  action?: string;
  outcome?: string;
  resource_type?: string;
  resource_id?: string;
  date_from?: string;
  date_to?: string;
  q?: string;
}
