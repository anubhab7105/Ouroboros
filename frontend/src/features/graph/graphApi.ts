import { cleanParams, endpoints } from '@/lib/api';
import { get } from '@/lib/apiClient';
import type {
  GraphPathsResult,
  GraphStatus,
  GraphSubgraph,
  MoneyTrailQuery,
  MoneyTrailsResult,
  PathQuery,
  SharedEntitiesQuery,
  SharedEntitiesResult,
  SubgraphQuery,
} from '@/types/graph';

/**
 * Network reads.
 *
 * Every one of these is bounded and clamps silently: a request for depth 8
 * against a deployment capped at 3 returns depth 3 rather than an error. The
 * response carries the limits that were applied and whether truncation
 * happened, and the UI renders those rather than the parameters it sent — the
 * difference between the two is exactly where a false conclusion comes from.
 */

export async function fetchGraphStatus(): Promise<GraphStatus> {
  return get<GraphStatus>(endpoints.graph.status());
}

export async function fetchSubgraph(query: SubgraphQuery): Promise<GraphSubgraph> {
  return get<GraphSubgraph>(endpoints.graph.subgraph(), { params: cleanParams(query) });
}

export async function fetchPaths(query: PathQuery): Promise<GraphPathsResult> {
  return get<GraphPathsResult>(endpoints.graph.paths(), { params: cleanParams(query) });
}

export async function fetchMoneyTrails(query: MoneyTrailQuery): Promise<MoneyTrailsResult> {
  return get<MoneyTrailsResult>(endpoints.graph.moneyTrails(), { params: cleanParams(query) });
}

export async function fetchSharedEntities(
  query: SharedEntitiesQuery,
): Promise<SharedEntitiesResult> {
  return get<SharedEntitiesResult>(endpoints.graph.sharedEntities(), {
    params: cleanParams(query),
  });
}
