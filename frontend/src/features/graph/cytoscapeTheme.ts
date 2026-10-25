import { ENTITY_TYPE_TOKENS, RISK_BAND_TOKENS, SEVERITY_TOKENS } from '@/lib/constants';
import type { RiskBand } from '@/types/common';
import type { GraphEdge, GraphNode } from '@/types/graph';

/**
 * The Cytoscape stylesheet, and the element mapping that feeds it.
 *
 * Three decisions worth stating:
 *
 * - **Node shape carries the node's kind, colour carries its risk.** The graph
 *   is heterogeneous — accounts, transactions, identifiers, complaints,
 *   alerts — and using colour for both would leave neither legible. Shape
 *   survives colour blindness and a greyscale print; risk colour is a second,
 *   redundant channel on top of a label that already says the band.
 *
 * - **An inferred edge is dashed.** Entity links and complaint correlations
 *   below tier 3 are inferences, and a solid line between two accounts reads
 *   as a transfer that happened. The dash is the visual form of "this is
 *   suggested, not recorded".
 *
 * - **Labels are always present.** A node with no label is a dot an
 *   investigator cannot act on, and a screenshot of dots is worse than a
 *   table.
 */

export type ThemeMode = 'light' | 'dark';

const INK = {
  light: {
    text: '#111620',
    muted: '#546175',
    line: '#c2cad6',
    surface: '#ffffff',
    halo: '#1f4e79',
  },
  dark: {
    text: '#f4f6f9',
    muted: '#8b99ac',
    line: '#3c4657',
    surface: '#161b25',
    halo: '#6ea8e8',
  },
} as const;

/** Node shapes per kind. Shape is the primary, colour-independent channel. */
const NODE_SHAPES: Record<string, string> = {
  account: 'ellipse',
  transaction: 'diamond',
  entity: 'hexagon',
  complaint: 'round-rectangle',
  alert: 'triangle',
  assessment: 'rectangle',
};

const NODE_COLOURS: Record<string, string> = {
  transaction: '#2f7d95',
  entity: '#5b4b8a',
  complaint: '#8a6d1f',
  alert: '#b3541e',
  assessment: '#1f6f50',
};

/**
 * The band a score falls in, by the same cut-points the server uses.
 *
 * The graph endpoint returns a score on an account node but no band, so this
 * derives one for colouring. The cut-points mirror `config/scoring.default.json`
 * — 40, 65, 85 — and a deployment that has changed them would make this
 * disagree, which is why the canvas is coloured from it but nothing else is:
 * the authoritative band is the one on the assessment, and that is what every
 * badge and report shows.
 */
export function bandFromScore(score: number | null | undefined): RiskBand | null {
  if (score === null || score === undefined || !Number.isFinite(score)) return null;
  if (score >= 85) return 'CRITICAL';
  if (score >= 65) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  return 'LOW';
}

/** The colour an account node takes, from the band its score falls in. */
export function accountColour(node: GraphNode): string {
  const band = bandFromScore(node.score);
  if (band) return RISK_BAND_TOKENS[band].hex;

  // Unassessed accounts get their own slate, and are also drawn hollow (see
  // the stylesheet) so one cannot be mistaken for an account that was
  // assessed and came back low.
  return '#8b99ac';
}

export function nodeColour(node: GraphNode): string {
  if (node.type === 'account') return accountColour(node);
  if (node.type === 'alert' && node.priority) {
    return (
      SEVERITY_TOKENS[node.priority as keyof typeof SEVERITY_TOKENS]?.hex ??
      NODE_COLOURS.alert ??
      '#b3541e'
    );
  }
  if (node.type === 'entity' && node.entity_type) {
    return ENTITY_TYPE_TOKENS[node.entity_type]?.hex ?? NODE_COLOURS.entity ?? '#5b4b8a';
  }

  return NODE_COLOURS[node.type] ?? '#6b7a8f';
}

/** A short label. Long ids make an unreadable canvas. */
export function nodeLabel(node: GraphNode): string {
  const label = node.label?.trim();
  if (label && label.length <= 18) return label;
  if (label && label.length > 18) return `${label.slice(0, 8)}…${label.slice(-6)}`;

  const id = node.account_id ?? node.id;
  return id.length <= 18 ? id : `${id.slice(0, 8)}…${id.slice(-6)}`;
}

/** True when an edge is an inference rather than a recorded transfer. */
export function isInferredEdge(edge: GraphEdge): boolean {
  if (edge.deterministic === true) return false;
  if (edge.deterministic === false) return true;

  // A transfer edge carries a transaction; anything else is a relation the
  // platform derived.
  return !edge.transaction_id;
}

export interface CytoscapeElement {
  data: Record<string, unknown>;
  classes?: string;
}

/** Map one API node onto a Cytoscape element. */
export function toCytoscapeNode(node: GraphNode, rootId?: string | null): CytoscapeElement {
  const band = bandFromScore(node.score);
  const classes = [`kind-${node.type}`];

  if (node.id === rootId) classes.push('is-root');
  if (node.type === 'account' && !band) classes.push('unassessed');

  return {
    data: {
      id: node.id,
      label: nodeLabel(node),
      kind: node.type,
      colour: nodeColour(node),
      shape: NODE_SHAPES[node.type] ?? 'ellipse',
      // Size carries score where there is one, so the eye lands on the
      // accounts worth looking at first. Clamped so an unscored node is not
      // invisible and a 100 is not a blob.
      size:
        node.type === 'account'
          ? 26 + Math.min(22, Math.max(0, (node.score ?? 0) / 100) * 22)
          : 20,
      score: node.score ?? null,
      band,
    },
    classes: classes.join(' '),
  };
}

export function toCytoscapeEdge(edge: GraphEdge): CytoscapeElement {
  const inferred = isInferredEdge(edge);

  return {
    data: {
      id: edge.id,
      source: edge.source,
      target: edge.target,
      kind: edge.type,
      label: edge.label ?? '',
      inferred,
      // Weight drives thickness for transfers; inferred edges stay thin so
      // they never visually outweigh a recorded one.
      width: inferred ? 1 : 1.5 + Math.min(3.5, Math.log10((edge.amount ?? 1) + 1) * 0.8),
    },
    classes: inferred ? 'inferred' : 'recorded',
  };
}

/** The stylesheet, for one theme. */
export function cytoscapeStylesheet(mode: ThemeMode) {
  const ink = INK[mode];

  return [
    {
      selector: 'node',
      style: {
        'background-color': 'data(colour)',
        shape: 'data(shape)',
        width: 'data(size)',
        height: 'data(size)',
        label: 'data(label)',
        'font-size': 8,
        'font-family': 'ui-monospace, SFMono-Regular, Menlo, monospace',
        color: ink.text,
        'text-valign': 'bottom',
        'text-margin-y': 3,
        'text-background-color': ink.surface,
        'text-background-opacity': 0.75,
        'text-background-padding': 1.5,
        'border-width': 1,
        'border-color': ink.line,
        'overlay-opacity': 0,
      },
    },
    {
      // An unassessed account is outlined rather than filled, so it reads as
      // "no assessment" instead of as a low one.
      selector: 'node.unassessed',
      style: {
        'background-opacity': 0.25,
        'border-width': 1.5,
        'border-style': 'dashed',
      },
    },
    {
      selector: 'node.is-root',
      style: {
        'border-width': 3,
        'border-color': ink.halo,
        'font-weight': 'bold',
        'font-size': 9,
      },
    },
    {
      selector: 'edge',
      style: {
        width: 'data(width)',
        'line-color': ink.line,
        'target-arrow-color': ink.line,
        'target-arrow-shape': 'triangle',
        'arrow-scale': 0.7,
        'curve-style': 'bezier',
        label: 'data(label)',
        'font-size': 7,
        color: ink.muted,
        'text-rotation': 'autorotate',
        'text-background-color': ink.surface,
        'text-background-opacity': 0.7,
        'text-background-padding': 1,
      },
    },
    {
      // Dashed means inferred. The single most important mark on this canvas.
      selector: 'edge.inferred',
      style: {
        'line-style': 'dashed',
        'line-dash-pattern': [4, 3],
        opacity: 0.8,
      },
    },
    {
      selector: 'node:selected',
      style: {
        'border-width': 3,
        'border-color': ink.halo,
      },
    },
    {
      selector: 'edge:selected',
      style: {
        'line-color': ink.halo,
        'target-arrow-color': ink.halo,
        width: 3,
      },
    },
    {
      selector: '.highlighted',
      style: {
        'line-color': '#b3541e',
        'target-arrow-color': '#b3541e',
        'border-color': '#b3541e',
        width: 3.5,
        'z-index': 10,
      },
    },
    {
      selector: '.dimmed',
      style: {
        opacity: 0.15,
      },
    },
  ];
}

/** Layout options. Shapes in fund-flow graphs read best left to right. */
export function layoutOptions(name: string, nodeCount: number) {
  if (name === 'dagre') {
    return {
      name: 'dagre',
      rankDir: 'LR',
      nodeSep: 28,
      rankSep: 70,
      animate: nodeCount <= 150,
      animationDuration: 250,
      fit: true,
      padding: 24,
    };
  }

  if (name === 'cose-bilkent') {
    return {
      name: 'cose-bilkent',
      // Animation on a large graph is a long freeze for no benefit.
      animate: nodeCount <= 120 ? 'end' : false,
      animationDuration: 350,
      randomize: false,
      nodeRepulsion: 6500,
      idealEdgeLength: 70,
      nestingFactor: 0.1,
      gravity: 0.3,
      numIter: nodeCount > 200 ? 1200 : 2500,
      fit: true,
      padding: 24,
    };
  }

  return { name, animate: false, fit: true, padding: 24 };
}

export const LAYOUT_OPTIONS = [
  {
    value: 'dagre',
    label: 'Flow (left to right)',
    help: 'Ranks accounts by position in the flow. The clearest view of a chain.',
  },
  {
    value: 'cose-bilkent',
    label: 'Force directed',
    help: 'Pulls clusters together. Best for spotting a shared-identifier group.',
  },
  {
    value: 'concentric',
    label: 'Concentric',
    help: 'Rings by hop distance from the root account.',
  },
  { value: 'grid', label: 'Grid', help: 'No structure, but every node is visible.' },
];
