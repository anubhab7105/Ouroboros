import { endpoints } from '@/lib/api';
import { get } from '@/lib/apiClient';
import type { AuditEvent, AuditFilters } from '@/types/audit';
import type { HealthStatus, PageResponse } from '@/types/common';
import type { ReportLimitations } from '@/types/model';

/**
 * Health, status and audit reads.
 *
 * `fetchStatus` is the one call in the application that must not be retried
 * aggressively: it is what a user looks at when something is already wrong,
 * and hammering a struggling backend to render its own status page is unkind.
 * The query that uses it sets `retry: false`.
 */

export async function fetchHealth(): Promise<HealthStatus> {
  return get<HealthStatus>(endpoints.health.root());
}

export interface ServiceStatus {
  status: string;
  version?: string | null;
  environment?: string | null;
  /** Per-component availability, as the backend's own status endpoint reports. */
  components?: Record<string, unknown>;
  degraded_reasons?: string[];
  [key: string]: unknown;
}

export async function fetchStatus(): Promise<ServiceStatus> {
  return get<ServiceStatus>(endpoints.health.status());
}

export async function fetchLimitations(): Promise<ReportLimitations> {
  return get<ReportLimitations>(endpoints.reports.limitations());
}

export async function fetchAuditEvents(params: {
  page: number;
  page_size: number;
  sort_by?: string;
  sort_order?: 'asc' | 'desc';
  filters: AuditFilters;
}): Promise<PageResponse<AuditEvent>> {
  const { filters, ...rest } = params;
  return get<PageResponse<AuditEvent>>(endpoints.audit.list(), {
    params: { ...rest, ...filters },
  });
}

/** The detail endpoint wraps the event, so unwrap it for the caller. */
export async function fetchAuditEvent(id: string): Promise<AuditEvent> {
  const response = await get<{ event: AuditEvent }>(endpoints.audit.detail(id));
  return response.event;
}

export interface AuditTopItem {
  value?: string | null;
  count: number;
}

export interface AuditStats {
  period: Record<string, unknown>;
  total_events: number;
  outcome_counts: Record<string, number>;
  distinct_actor_count: number;
  top_actions: AuditTopItem[];
  top_resource_types: AuditTopItem[];
  top_actors: AuditTopItem[];
  caveats: string[];
}

export async function fetchAuditStats(params?: {
  date_from?: string;
  date_to?: string;
  top_limit?: number;
}): Promise<AuditStats> {
  return get<AuditStats>(endpoints.audit.stats(), { params });
}
