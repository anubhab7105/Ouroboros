import { useCallback, useMemo } from 'react';

import { useQueryParams } from '@/hooks/useQueryParams';
import type { GraphDirection, GraphStatus, SubgraphQuery } from '@/types/graph';

/**
 * The traversal parameters, held in the URL.
 *
 * A network view is the thing investigators share with each other most often
 * — "look at this account two hops out, transfers only" — and a view that
 * cannot be sent as a link gets screenshotted instead, which loses the
 * caveats along with the interactivity.
 *
 * Requested values are clamped against the deployment's published limits
 * before being sent. The server clamps anyway; doing it here as well means the
 * control shows the value that will actually be used rather than the one the
 * user typed, which otherwise reads as the interface ignoring them.
 */

export interface GraphFilterState extends SubgraphQuery {
  account_id: string;
}

const DEFAULTS = {
  depth: 2,
  direction: 'both' as GraphDirection,
  include_transactions: true,
  include_entities: true,
  include_complaints: true,
  include_alerts: true,
  include_assessments: false,
};

export function useGraphFilters(status?: GraphStatus) {
  const { params, setParams, clearParams } = useQueryParams<Record<string, string>>();

  const rootAccountId = params.root ?? '';

  const clamp = useCallback(
    (value: number, max: number | undefined, fallback: number) => {
      if (!Number.isFinite(value) || value <= 0) return fallback;
      if (max === undefined) return value;
      return Math.min(value, max);
    },
    [],
  );

  const readBool = (key: string, fallback: boolean): boolean => {
    const raw = params[key];
    if (raw === undefined) return fallback;
    return raw === 'true' || raw === '1';
  };

  const filters = useMemo<GraphFilterState>(() => {
    const depth = clamp(Number(params.depth ?? DEFAULTS.depth), status?.max_depth, DEFAULTS.depth);

    return {
      account_id: rootAccountId,
      depth,
      direction: (params.direction as GraphDirection | undefined) ?? DEFAULTS.direction,
      include_transactions: readBool('include_transactions', DEFAULTS.include_transactions),
      include_entities: readBool('include_entities', DEFAULTS.include_entities),
      include_complaints: readBool('include_complaints', DEFAULTS.include_complaints),
      include_alerts: readBool('include_alerts', DEFAULTS.include_alerts),
      include_assessments: readBool('include_assessments', DEFAULTS.include_assessments),
      as_of: params.as_of,
      date_from: params.date_from,
      date_to: params.date_to,
      min_amount: params.min_amount ? Number(params.min_amount) : undefined,
      max_nodes: params.max_nodes
        ? clamp(Number(params.max_nodes), status?.hard_max_nodes, status?.max_nodes ?? 200)
        : undefined,
      max_edges: params.max_edges
        ? clamp(Number(params.max_edges), status?.hard_max_edges, status?.max_edges ?? 800)
        : undefined,
    };
  }, [params, rootAccountId, status, clamp]);

  /** True when the user asked for more than this deployment allows. */
  const clampedFields = useMemo(() => {
    const clamped: string[] = [];

    if (params.depth && status?.max_depth && Number(params.depth) > status.max_depth) {
      clamped.push(`depth to ${status.max_depth}`);
    }
    if (params.max_nodes && status?.max_nodes && Number(params.max_nodes) > status.max_nodes) {
      clamped.push(`node limit to ${status.max_nodes}`);
    }
    if (params.max_edges && status?.max_edges && Number(params.max_edges) > status.max_edges) {
      clamped.push(`edge limit to ${status.max_edges}`);
    }

    return clamped;
  }, [params, status]);

  const setRoot = useCallback(
    (accountId: string) => setParams({ root: accountId }, { resetPage: false }),
    [setParams],
  );

  const update = useCallback(
    (next: Record<string, string | number | boolean | undefined>) => {
      const normalised: Record<string, string | undefined> = {};

      for (const [key, value] of Object.entries(next)) {
        normalised[key] = value === undefined ? undefined : String(value);
      }

      setParams(normalised, { resetPage: false });
    },
    [setParams],
  );

  const reset = useCallback(() => {
    clearParams([
      'depth',
      'direction',
      'include_transactions',
      'include_entities',
      'include_complaints',
      'include_alerts',
      'include_assessments',
      'as_of',
      'date_from',
      'date_to',
      'min_amount',
      'max_nodes',
      'max_edges',
    ]);
  }, [clearParams]);

  return { filters, rootAccountId, clampedFields, setRoot, update, reset };
}
