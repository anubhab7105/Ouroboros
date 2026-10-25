import { useQuery } from '@tanstack/react-query';
import { useMemo, useState } from 'react';

import { Card } from '@/components/common/Card';
import { PageHeader } from '@/components/layout/PageHeader';
import { useApiError } from '@/hooks/useApiError';
import { useLocalStorage } from '@/hooks/useLocalStorage';
import { useQueryParams } from '@/hooks/useQueryParams';
import { STORAGE_KEYS } from '@/lib/storage';
import { queryKeys } from '@/lib/queryKeys';

import { GraphCanvas } from './GraphCanvas';
import { GraphSidePanel } from './GraphSidePanel';
import { MoneyTrailResultsTable } from './MoneyTrailResultsTable';
import { MoneyTrailSearchForm, type TrailSearchState } from './MoneyTrailSearchForm';
import { fetchGraphStatus, fetchMoneyTrails, fetchPaths, fetchSubgraph } from './graphApi';
import { useGraphFilters } from './useGraphFilters';

/**
 * The network view.
 *
 * Three surfaces that answer different questions, in the order they are
 * usually asked:
 *
 * 1. **The canvas** — what is around this account.
 * 2. **Trail and path search** — where did money go, or is there a route
 *    between these two accounts.
 * 3. **The side panel** — what the selected thing is, which identifier
 *    clusters exist, and what the shapes mean.
 *
 * The whole view is driven from the URL, so a particular traversal is a link
 * a colleague can open and see exactly the same thing, caveats included. That
 * matters more here than anywhere else in the application: a graph is the most
 * persuasive surface it has, and a screenshot of one travels without the
 * limits that produced it.
 */
export default function GraphPage() {
  const { setParams } = useQueryParams();

  const statusQuery = useQuery({
    queryKey: queryKeys.graph.status(),
    queryFn: fetchGraphStatus,
    staleTime: 10 * 60_000,
  });

  const status = statusQuery.data;
  const { filters, rootAccountId, clampedFields, setRoot, update, reset } =
    useGraphFilters(status);

  const [layout, setLayout] = useLocalStorage<string>(STORAGE_KEYS.graphLayout, 'dagre');
  const [sideTab, setSideTab] = useState('controls');
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);
  const [highlighted, setHighlighted] = useState<string[]>([]);

  const [search, setSearch] = useState<TrailSearchState>({
    mode: 'trails',
    accountId: rootAccountId,
    destinationId: '',
    direction: 'outgoing',
    maxHops: 3,
    minAmount: '',
    dateFrom: '',
    dateTo: '',
  });
  const [searchKey, setSearchKey] = useState(0);

  const subgraphQuery = useQuery({
    queryKey: queryKeys.graph.subgraph(filters),
    queryFn: () => fetchSubgraph(filters),
    enabled: Boolean(rootAccountId),
  });

  const trailsQuery = useQuery({
    queryKey: [
      ...queryKeys.graph.trails({
        account_id: search.accountId,
        direction: search.direction,
        max_hops: search.maxHops,
      }),
      searchKey,
    ],
    queryFn: () =>
      fetchMoneyTrails({
        account_id: search.accountId.trim(),
        direction: search.direction,
        max_hops: search.maxHops,
        min_amount: search.minAmount ? Number(search.minAmount) : undefined,
        date_from: search.dateFrom || undefined,
        date_to: search.dateTo || undefined,
      }),
    enabled: searchKey > 0 && search.mode === 'trails' && Boolean(search.accountId.trim()),
  });

  const pathsQuery = useQuery({
    queryKey: [
      ...queryKeys.graph.paths({
        from_account_id: search.accountId,
        to_account_id: search.destinationId,
        max_depth: search.maxHops,
      }),
      searchKey,
    ],
    queryFn: () =>
      fetchPaths({
        from_account_id: search.accountId.trim(),
        to_account_id: search.destinationId.trim(),
        max_depth: search.maxHops,
        min_amount: search.minAmount ? Number(search.minAmount) : undefined,
        date_from: search.dateFrom || undefined,
        date_to: search.dateTo || undefined,
      }),
    enabled:
      searchKey > 0 &&
      search.mode === 'paths' &&
      Boolean(search.accountId.trim()) &&
      Boolean(search.destinationId.trim()),
  });

  const subgraphError = useApiError(subgraphQuery.error);
  const searchError = useApiError(
    search.mode === 'paths' ? pathsQuery.error : trailsQuery.error,
  );

  const subgraph = subgraphQuery.data;

  const selectedNode = useMemo(
    () => subgraph?.nodes.find((node) => node.id === selectedNodeId) ?? null,
    [subgraph, selectedNodeId],
  );

  const selectedEdge = useMemo(
    () => subgraph?.edges.find((edge) => edge.id === selectedEdgeId) ?? null,
    [subgraph, selectedEdgeId],
  );

  /**
   * Highlighting a chain needs the *node ids* on the canvas, and a trail
   * reports account ids. For an account node the two coincide only when the
   * node id is the account id, so both are matched.
   */
  const highlightAccounts = (accountIds: string[]) => {
    const ids = new Set(accountIds);
    const nodeIds = (subgraph?.nodes ?? [])
      .filter((node) => ids.has(node.id) || (node.account_id ? ids.has(node.account_id) : false))
      .map((node) => node.id);

    setHighlighted(nodeIds.length > 0 ? nodeIds : accountIds);
  };

  return (
    <div className="space-y-5">
      <PageHeader
        title="Network"
        description="Fund flows and shared identifiers around an account. Every traversal here is bounded, and what is drawn is what the traversal returned — not everything that exists."
      />

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <div className="space-y-5">
          <GraphCanvas
            subgraph={subgraph}
            isLoading={subgraphQuery.isLoading}
            error={subgraphError}
            onRetry={() => void subgraphQuery.refetch()}
            rootId={subgraph?.root_node_id ?? null}
            layout={layout}
            onSelectNode={(id) => {
              setSelectedNodeId(id);
              if (id) setSideTab('selection');
            }}
            onSelectEdge={(id) => {
              setSelectedEdgeId(id);
              if (id) setSideTab('selection');
            }}
            highlightNodeIds={highlighted}
          />

          <Card
            title="Follow the money"
            description="Trails from one account, or routes between two. Both answer with chains that exist in the ledger — not with a tracing of particular funds."
          >
            <MoneyTrailSearchForm
              value={search}
              onChange={(next) => setSearch((current) => ({ ...current, ...next }))}
              onSearch={() => setSearchKey((key) => key + 1)}
              isSearching={trailsQuery.isFetching || pathsQuery.isFetching}
              status={status}
            />
          </Card>

          {searchKey > 0 ? (
            <MoneyTrailResultsTable
              trails={search.mode === 'trails' ? trailsQuery.data : undefined}
              paths={search.mode === 'paths' ? pathsQuery.data : undefined}
              isLoading={search.mode === 'paths' ? pathsQuery.isLoading : trailsQuery.isLoading}
              error={searchError}
              onRetry={() =>
                void (search.mode === 'paths' ? pathsQuery.refetch() : trailsQuery.refetch())
              }
              onHighlight={highlightAccounts}
            />
          ) : null}
        </div>

        <GraphSidePanel
          activeTab={sideTab}
          onTabChange={setSideTab}
          filters={filters}
          status={status}
          clampedFields={clampedFields}
          layout={layout}
          onLayoutChange={setLayout}
          onRootChange={(accountId) => {
            setRoot(accountId);
            setSearch((current) => ({ ...current, accountId }));
            setHighlighted([]);
          }}
          onUpdate={update}
          onReset={() => {
            reset();
            setHighlighted([]);
            setParams({ tab: undefined }, { resetPage: false });
          }}
          onFit={() => setHighlighted([])}
          selectedNode={selectedNode}
          selectedEdge={selectedEdge}
          onHighlight={highlightAccounts}
        />
      </div>
    </div>
  );
}
