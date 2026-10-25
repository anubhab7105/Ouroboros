import { useCallback, useEffect, useRef, useState } from 'react';

import type { GraphEdge, GraphNode } from '@/types/graph';

import {
  cytoscapeStylesheet,
  layoutOptions,
  toCytoscapeEdge,
  toCytoscapeNode,
  type ThemeMode,
} from './cytoscapeTheme';

export interface UseCytoscapeOptions {
  nodes: GraphNode[];
  edges: GraphEdge[];
  rootId?: string | null;
  layout: string;
  theme: ThemeMode;
  onSelectNode?: (nodeId: string | null) => void;
  onSelectEdge?: (edgeId: string | null) => void;
}

/**
 * Mount Cytoscape onto a container and keep it in step with the data.
 *
 * Cytoscape is loaded dynamically, for two reasons. It is the largest
 * dependency in the application by a wide margin, and most users of this
 * platform never open the network view — paying for it on every page load
 * would be a tax on the triage queue. It also keeps the library off the
 * server-render path entirely, since it needs a real DOM.
 *
 * The instance is created once and its elements are replaced on each data
 * change rather than being torn down. Tearing down loses the viewport, and an
 * investigator who has panned to a cluster and then tightened a filter should
 * not be thrown back to the whole graph.
 *
 * A layout is re-run only when the elements or the chosen layout actually
 * change. Re-running on every render makes the canvas jump continuously, which
 * is the single most common way an interactive graph becomes unusable.
 */
export function useCytoscape({
  nodes,
  edges,
  rootId,
  layout,
  theme,
  onSelectNode,
  onSelectEdge,
}: UseCytoscapeOptions) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const cyRef = useRef<any>(null);
  const [isReady, setIsReady] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  // Mount: load the library, create the instance, wire selection handlers.
  useEffect(() => {
    let cancelled = false;

    const mount = async () => {
      if (!containerRef.current) return;

      try {
        const [{ default: cytoscape }, { default: dagre }, { default: coseBilkent }] =
          await Promise.all([
            import('cytoscape'),
            import('cytoscape-dagre'),
            import('cytoscape-cose-bilkent'),
          ]);

        if (cancelled || !containerRef.current) return;

        // Registering twice throws, and this effect can run twice under
        // StrictMode in development.
        const registry = cytoscape as unknown as { __muleguardLayouts?: boolean };
        if (!registry.__muleguardLayouts) {
          cytoscape.use(dagre);
          cytoscape.use(coseBilkent);
          registry.__muleguardLayouts = true;
        }

        const instance = cytoscape({
          container: containerRef.current,
          style: cytoscapeStylesheet(theme),
          elements: [],
          // Box selection is off: on a dense graph it is almost always an
          // accidental drag rather than an intentional multi-select.
          boxSelectionEnabled: false,
          wheelSensitivity: 0.25,
          minZoom: 0.15,
          maxZoom: 3,
        });

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        instance.on('tap', 'node', (event: any) => {
          onSelectEdge?.(null);
          onSelectNode?.(event.target.id());
        });

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        instance.on('tap', 'edge', (event: any) => {
          onSelectNode?.(null);
          onSelectEdge?.(event.target.id());
        });

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        instance.on('tap', (event: any) => {
          // A tap on the background clears the selection.
          if (event.target === instance) {
            onSelectNode?.(null);
            onSelectEdge?.(null);
          }
        });

        cyRef.current = instance;
        setIsReady(true);
      } catch (caught) {
        setLoadError(
          caught instanceof Error
            ? `The network view could not load: ${caught.message}`
            : 'The network view could not load.',
        );
      }
    };

    void mount();

    return () => {
      cancelled = true;
      cyRef.current?.destroy();
      cyRef.current = null;
      setIsReady(false);
    };
    // Mount once. Theme and handlers are applied by the effects below, so
    // that a theme change does not rebuild the instance and lose the viewport.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Theme changes restyle in place.
  useEffect(() => {
    if (!cyRef.current) return;
    cyRef.current.style(cytoscapeStylesheet(theme));
  }, [theme, isReady]);

  // Data changes replace the elements and re-run the layout.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    const elements = [
      ...nodes.map((node) => toCytoscapeNode(node, rootId)),
      // An edge whose endpoints are not both present would throw, which
      // happens when a traversal was truncated mid-way.
      ...edges
        .filter(
          (edge) =>
            nodes.some((node) => node.id === edge.source) &&
            nodes.some((node) => node.id === edge.target),
        )
        .map(toCytoscapeEdge),
    ];

    cy.elements().remove();
    cy.add(elements);

    if (elements.length > 0) {
      cy.layout(layoutOptions(layout, nodes.length)).run();
    }
  }, [nodes, edges, rootId, layout, isReady]);

  /** Dim everything except one path, for showing a trail on the canvas. */
  const highlightPath = useCallback((nodeIds: string[]) => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.elements().removeClass('highlighted').removeClass('dimmed');

    if (nodeIds.length === 0) return;

    const selector = nodeIds.map((id) => `[id = "${id}"]`).join(', ');
    const pathNodes = cy.nodes(selector);
    const pathEdges = pathNodes.edgesWith(pathNodes);

    cy.elements().addClass('dimmed');
    pathNodes.removeClass('dimmed').addClass('highlighted');
    pathEdges.removeClass('dimmed').addClass('highlighted');
  }, []);

  const clearHighlight = useCallback(() => {
    cyRef.current?.elements().removeClass('highlighted').removeClass('dimmed');
  }, []);

  const fit = useCallback(() => {
    cyRef.current?.fit(undefined, 24);
  }, []);

  const centreOn = useCallback((nodeId: string) => {
    const cy = cyRef.current;
    if (!cy) return;

    const node = cy.getElementById(nodeId);
    if (node && node.length > 0) {
      cy.animate({ center: { eles: node }, zoom: 1.2 }, { duration: 250 });
    }
  }, []);

  /** A PNG of the current canvas, for attaching to a case note by hand. */
  const exportPng = useCallback((): string | null => {
    const cy = cyRef.current;
    if (!cy) return null;

    return cy.png({ full: true, scale: 2, bg: '#ffffff' });
  }, []);

  return {
    containerRef,
    isReady,
    loadError,
    highlightPath,
    clearHighlight,
    fit,
    centreOn,
    exportPng,
  };
}
