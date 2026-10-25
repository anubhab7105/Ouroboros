import { useQuery } from '@tanstack/react-query';

import { Badge } from '@/components/common/Badge';
import { Card } from '@/components/common/Card';
import { EmptyState } from '@/components/common/EmptyState';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { Tabs } from '@/components/common/Tabs';
import { formatConfidence, formatCount } from '@/lib/amounts';
import { ENTITY_TYPE_TOKENS } from '@/lib/constants';
import { humaniseField, truncateId } from '@/lib/formatters';
import { queryKeys } from '@/lib/queryKeys';
import type { GraphEdge, GraphNode, GraphStatus } from '@/types/graph';

import { EdgeDetailPanel } from './EdgeDetailPanel';
import { GraphControls } from './GraphControls';
import { GraphLegend } from './GraphLegend';
import { NodeDetailPanel } from './NodeDetailPanel';
import { fetchSharedEntities } from './graphApi';
import type { GraphFilterState } from './useGraphFilters';

export interface GraphSidePanelProps {
  activeTab: string;
  onTabChange: (tab: string) => void;

  filters: GraphFilterState;
  status?: GraphStatus;
  clampedFields: string[];
  layout: string;
  onLayoutChange: (layout: string) => void;
  onRootChange: (accountId: string) => void;
  onUpdate: (next: Record<string, string | number | boolean | undefined>) => void;
  onReset: () => void;
  onFit: () => void;

  selectedNode?: GraphNode | null;
  selectedEdge?: GraphEdge | null;
  onHighlight?: (accountIds: string[]) => void;
}

/**
 * The panel beside the canvas.
 *
 * Tabs rather than a stack, because the four things in here are used at
 * different moments: the controls while setting a view up, the selection
 * while reading it, the clusters when a shared identifier is the lead, and
 * the legend whenever somebody is unsure what a shape means.
 *
 * The selection tab switches on what is selected rather than showing both
 * panels, since only one of a node and an edge can be selected at a time.
 */
export function GraphSidePanel({
  activeTab,
  onTabChange,
  filters,
  status,
  clampedFields,
  layout,
  onLayoutChange,
  onRootChange,
  onUpdate,
  onReset,
  onFit,
  selectedNode,
  selectedEdge,
  onHighlight,
}: GraphSidePanelProps) {
  const clustersQuery = useQuery({
    queryKey: queryKeys.graph.sharedEntities({ account_id: filters.account_id }),
    queryFn: () =>
      fetchSharedEntities({
        account_id: filters.account_id,
        min_accounts: 2,
        as_of: filters.as_of,
      }),
    enabled: Boolean(filters.account_id) && activeTab === 'clusters',
  });

  const clusters = clustersQuery.data?.groups ?? [];

  return (
    <Card flush>
      <div className="px-4 pt-4">
        <Tabs
          activeId={activeTab}
          onChange={onTabChange}
          items={[
            {
              id: 'controls',
              label: 'View',
              content: (
                <GraphControls
                  filters={filters}
                  status={status}
                  clampedFields={clampedFields}
                  layout={layout}
                  onLayoutChange={onLayoutChange}
                  onRootChange={onRootChange}
                  onUpdate={onUpdate}
                  onReset={onReset}
                  onFit={onFit}
                />
              ),
            },
            {
              id: 'selection',
              label: 'Selection',
              content: selectedEdge ? (
                <EdgeDetailPanel edge={selectedEdge} />
              ) : (
                <NodeDetailPanel node={selectedNode} onSetRoot={onRootChange} />
              ),
            },
            {
              id: 'clusters',
              label: 'Clusters',
              badge: clusters.length || undefined,
              content: (
                <div>
                  <p className="mb-2 text-2xs leading-relaxed text-ink-600 dark:text-ink-300">
                    Accounts around the root that share a pseudonymous identifier. Sharing one
                    suggests a connection; it does not establish common control, and the
                    verification state says whether anybody has checked.
                  </p>

                  {!filters.account_id ? (
                    <EmptyState title="Choose a root account first" compact />
                  ) : clustersQuery.isLoading ? (
                    <LoadingSpinner label="Finding clusters" />
                  ) : clusters.length === 0 ? (
                    <EmptyState
                      title="No shared identifier found"
                      message="No identifier around this account is shared with another. That is not evidence of independence — the platform only sees the identifiers it has been given."
                      compact
                    />
                  ) : (
                    <ul className="space-y-2.5">
                      {clusters.map((group) => {
                        const token = group.entity.entity_type
                          ? ENTITY_TYPE_TOKENS[group.entity.entity_type]
                          : undefined;

                        return (
                          <li
                            key={group.entity.id}
                            className="rounded-md border border-ink-200 p-2.5 dark:border-ink-700"
                          >
                            <div className="mb-1 flex flex-wrap items-center gap-1.5">
                              <Badge accentColor={token?.hex} title={token?.description}>
                                {group.entity.entity_type
                                  ? humaniseField(group.entity.entity_type)
                                  : 'Identifier'}
                              </Badge>
                              <span className="text-2xs tabular text-ink-700 dark:text-ink-200">
                                {formatCount(group.account_count)} accounts
                              </span>
                              {group.deterministic ? (
                                <Badge
                                  tone="neutral"
                                  title="Every link in this group is an exact identifier match."
                                >
                                  Identity
                                </Badge>
                              ) : (
                                <Badge
                                  tone="warning"
                                  title="At least one link in this group is an inference."
                                >
                                  Inferred
                                </Badge>
                              )}
                            </div>

                            <p className="break-all font-mono text-2xs text-ink-600 dark:text-ink-300">
                              {/* The graph node carries a display label; the
                                  raw identifier is stored hashed and is not
                                  served to this view. */}
                              {group.entity.label || truncateId(group.entity.id, 14)}
                            </p>

                            <p className="mt-1 text-2xs text-ink-500 dark:text-ink-400">
                              {group.verification_states.length > 0
                                ? `Verification: ${group.verification_states.map(humaniseField).join(', ')}. `
                                : ''}
                              {group.max_confidence !== null && group.max_confidence !== undefined
                                ? `Confidence up to ${formatConfidence(group.max_confidence)}.`
                                : ''}
                            </p>

                            <ul className="mt-1.5 flex flex-wrap gap-1">
                              {group.accounts.slice(0, 8).map((account) => (
                                <li key={account.id}>
                                  <button
                                    type="button"
                                    onClick={() =>
                                      onHighlight?.(
                                        group.accounts.map((item) => item.account_id ?? item.id),
                                      )
                                    }
                                    className="rounded bg-ink-100 px-1.5 py-0.5 font-mono text-2xs text-ink-700 hover:bg-ink-200 dark:bg-ink-800 dark:text-ink-200 dark:hover:bg-ink-700"
                                    title={`Highlight this cluster on the canvas (${account.account_id ?? account.id})`}
                                  >
                                    {truncateId(account.account_id ?? account.id, 6)}
                                  </button>
                                </li>
                              ))}
                              {group.accounts.length > 8 ? (
                                <li className="self-center text-2xs text-ink-500 dark:text-ink-400">
                                  +{group.accounts.length - 8}
                                </li>
                              ) : null}
                            </ul>
                          </li>
                        );
                      })}
                    </ul>
                  )}

                  {clustersQuery.data?.truncated ? (
                    <p className="mt-2 text-2xs text-ink-700 dark:text-ink-200">
                      The cluster search was truncated at this deployment's limit, so there may be
                      more.
                    </p>
                  ) : null}
                </div>
              ),
            },
            {
              id: 'legend',
              label: 'Legend',
              content: <GraphLegend />,
            },
          ]}
        />
      </div>
    </Card>
  );
}
