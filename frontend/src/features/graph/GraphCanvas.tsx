import { useEffect, useMemo, useState } from 'react';

import { Badge } from '@/components/common/Badge';
import { Button } from '@/components/common/Button';
import { EmptyState } from '@/components/common/EmptyState';
import { ErrorState } from '@/components/common/ErrorState';
import { LoadingOverlay } from '@/components/common/LoadingOverlay';
import { formatCount } from '@/lib/amounts';
import type { FriendlyError } from '@/lib/errorMapper';
import { saveBlob } from '@/lib/download';
import type { GraphSubgraph } from '@/types/graph';

import { useCytoscape } from './useCytoscape';
import type { ThemeMode } from './cytoscapeTheme';

export interface GraphCanvasProps {
  subgraph?: GraphSubgraph;
  isLoading?: boolean;
  error?: FriendlyError | null;
  onRetry?: () => void;
  rootId?: string | null;
  layout: string;
  onSelectNode?: (nodeId: string | null) => void;
  onSelectEdge?: (edgeId: string | null) => void;
  /** Account ids to highlight, from a selected trail or path. */
  highlightNodeIds?: string[];
  height?: number;
}

/** Follow the document theme, which the topbar sets on `<html>`. */
function useDocumentTheme(): ThemeMode {
  const [mode, setMode] = useState<ThemeMode>(() =>
    typeof document !== 'undefined' && document.documentElement.classList.contains('dark')
      ? 'dark'
      : 'light',
  );

  useEffect(() => {
    if (typeof MutationObserver === 'undefined') return;

    const observer = new MutationObserver(() => {
      setMode(document.documentElement.classList.contains('dark') ? 'dark' : 'light');
    });

    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['class', 'data-theme'],
    });

    return () => observer.disconnect();
  }, []);

  return mode;
}

/**
 * The network canvas.
 *
 * The caption under it is not decoration. A graph is the most persuasive
 * surface in this application and the easiest to over-read: the canvas shows
 * what the traversal returned, which is not the same as what exists. So every
 * render states the node and edge counts against the limits that were applied,
 * and says plainly when the traversal was truncated — because at that point
 * the absence of a path is evidence of nothing at all.
 *
 * Cytoscape is loaded on demand inside `useCytoscape`; if that fails, the
 * failure is reported rather than leaving an empty box.
 */
export function GraphCanvas({
  subgraph,
  isLoading,
  error,
  onRetry,
  rootId,
  layout,
  onSelectNode,
  onSelectEdge,
  highlightNodeIds,
  height = 560,
}: GraphCanvasProps) {
  const theme = useDocumentTheme();

  const nodes = useMemo(() => subgraph?.nodes ?? [], [subgraph]);
  const edges = useMemo(() => subgraph?.edges ?? [], [subgraph]);

  const { containerRef, isReady, loadError, highlightPath, clearHighlight, fit, exportPng } =
    useCytoscape({
      nodes,
      edges,
      rootId,
      layout,
      theme,
      onSelectNode,
      onSelectEdge,
    });

  useEffect(() => {
    if (!isReady) return;

    if (highlightNodeIds && highlightNodeIds.length > 0) {
      highlightPath(highlightNodeIds);
    } else {
      clearHighlight();
    }
  }, [highlightNodeIds, isReady, highlightPath, clearHighlight]);

  const stats = subgraph?.stats;
  const truncated = stats?.truncated ?? false;

  const handleExport = () => {
    const dataUrl = exportPng();
    if (!dataUrl) return;

    // A data URL to a Blob, so the existing save path is reused.
    const [, base64] = dataUrl.split(',');
    if (!base64) return;

    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }

    saveBlob(
      new Blob([bytes], { type: 'image/png' }),
      `muleguard-network-${rootId ?? 'view'}.png`,
    );
  };

  if (error) {
    return <ErrorState error={error} onRetry={onRetry} />;
  }

  if (loadError) {
    return (
      <div
        role="alert"
        className="rounded-card border border-state-danger/30 bg-red-50 p-5 dark:bg-red-950/25"
      >
        <p className="text-sm font-semibold text-red-900 dark:text-red-200">
          The network view could not load
        </p>
        <p className="mt-1 text-xs text-red-900/90 dark:text-red-200/90">{loadError}</p>
        <p className="mt-2 text-2xs text-red-900/80 dark:text-red-200/80">
          The money-trail and path searches below do not depend on it and still work.
        </p>
      </div>
    );
  }

  return (
    <div>
      <div className="relative rounded-card border border-ink-200 bg-white dark:border-ink-700 dark:bg-ink-900">
        {isLoading ? <LoadingOverlay message="Building the network" /> : null}

        {!isLoading && nodes.length === 0 ? (
          <div style={{ height }} className="flex items-center justify-center">
            <EmptyState
              title={rootId ? 'Nothing connected within these limits' : 'Choose a root account'}
              message={
                rootId
                  ? 'No node was returned for this traversal. Raise the depth, widen the dates, or lower the minimum transfer — and remember that an empty canvas is not evidence that no connection exists.'
                  : 'Enter an account id to start the traversal, or open the network view from an account.'
              }
              compact
            />
          </div>
        ) : (
          <div
            ref={containerRef}
            style={{ height }}
            className="w-full"
            role="img"
            aria-label={
              stats
                ? `Network around ${rootId ?? 'the root account'}: ${formatCount(stats.node_count)} nodes and ${formatCount(stats.edge_count)} edges${truncated ? ', truncated at the traversal limit' : ''}.`
                : 'Network canvas'
            }
          />
        )}

        {nodes.length > 0 ? (
          <div className="absolute right-2 top-2 flex gap-1.5">
            <Button size="sm" variant="secondary" onClick={fit}>
              Fit
            </Button>
            <Button size="sm" variant="secondary" onClick={handleExport}>
              Save image
            </Button>
          </div>
        ) : null}
      </div>

      {stats ? (
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <Badge tone="neutral">
            {formatCount(stats.node_count)} of up to {formatCount(stats.max_nodes)} nodes
          </Badge>
          <Badge tone="neutral">
            {formatCount(stats.edge_count)} of up to {formatCount(stats.max_edges)} edges
          </Badge>
          <Badge tone="neutral">depth {stats.depth_requested}</Badge>

          {truncated ? (
            <Badge
              tone="warning"
              title="A limit was reached, so this is part of the network rather than all of it."
            >
              Truncated
            </Badge>
          ) : null}
        </div>
      ) : null}

      {truncated ? (
        <p className="mt-1.5 text-2xs leading-relaxed text-ink-700 dark:text-ink-200">
          The traversal hit a limit and stopped. What is on screen is a part of the network, not
          the whole of it — so a connection that is not drawn here may still exist. Narrow the
          date range or the direction to see further within the same limits.
        </p>
      ) : null}

      {subgraph?.caveats && subgraph.caveats.length > 0 ? (
        <ul className="mt-1.5 space-y-0.5">
          {subgraph.caveats.map((caveat) => (
            <li key={caveat} className="text-2xs text-ink-600 dark:text-ink-300">
              — {caveat}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
