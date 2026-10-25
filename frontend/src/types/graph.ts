import type { Iso8601 } from './common';

/**
 * Graph types, mirroring `app/api/v1/endpoints/graph.py`.
 *
 * The graph is **heterogeneous**: nodes are accounts, transactions, entities,
 * complaints, alerts or assessments, and edges are typed relations between
 * them. It is not an account-to-account graph with aggregated edges, so a
 * transfer between two accounts appears as two edges through a transaction
 * node when transactions are included.
 *
 * Because one `GraphNode` shape serves every kind, almost every field is
 * optional. `type` decides which fields are meaningful; reading `amount` off
 * an account node is a mistake the type system cannot prevent, so the
 * rendering code switches on `type` first.
 */

export type GraphNodeType =
  | 'account'
  | 'transaction'
  | 'entity'
  | 'complaint'
  | 'alert'
  | 'assessment';

export type GraphDirection = 'outgoing' | 'incoming' | 'both';

export interface GraphNode {
  id: string;
  /** Discriminator. Check this before reading any other field. */
  type: string;
  label: string;

  // Accounts
  account_id?: string | null;
  account_type?: string | null;
  status?: string | null;

  // Entities
  entity_type?: string | null;
  source?: string | null;
  verification_state?: string | null;

  // Alerts and assessments
  priority?: string | null;
  state?: string | null;
  score?: number | null;
  explanation_available?: boolean | null;

  // Transactions
  occurred_at?: Iso8601 | null;
  amount?: number | null;
  currency?: string | null;
  reference?: string | null;
  sender_account_id?: string | null;
  receiver_account_id?: string | null;

  // Complaints and correlations
  category?: string | null;
  narrative_available?: boolean | null;
  confidence?: number | null;
  match_method?: string | null;
  deterministic?: boolean | null;
  review_state?: string | null;

  metadata_json?: Record<string, unknown> | null;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  label?: string | null;

  transaction_id?: string | null;
  account_id?: string | null;
  entity_id?: string | null;
  complaint_id?: string | null;
  alert_id?: string | null;
  assessment_id?: string | null;

  amount?: number | null;
  currency?: string | null;
  occurred_at?: Iso8601 | null;

  /** Present on inferred edges only; a deterministic edge carries none. */
  confidence?: number | null;
  match_method?: string | null;
  deterministic?: boolean | null;
  review_state?: string | null;
  verification_state?: string | null;

  evidence_refs: string[];
  metadata_json?: Record<string, unknown> | null;
}

/**
 * What the traversal produced against what it was allowed.
 *
 * `truncated` is the field that matters: when a limit was hit, the absence of
 * a path in the result is not evidence that no path exists. Every view that
 * renders a graph must surface this.
 */
export interface GraphStats {
  node_count: number;
  edge_count: number;
  truncated: boolean;
  depth_requested: number;
  max_nodes: number;
  max_edges: number;
}

export interface GraphSubgraph {
  generated_at: Iso8601;
  root_node_id?: string | null;
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats: GraphStats;
  caveats: string[];
}

/**
 * One path between two accounts.
 *
 * `amount_by_currency` is a per-currency total of the transfers along the
 * path. It is deliberately not a single number: summing across currencies
 * would invent an exchange rate the platform does not hold.
 *
 * A path shows a shape in the transaction records. It does not establish that
 * the same funds traversed it — money is fungible, and claiming otherwise is
 * the error that turns an investigative lead into an unsupportable assertion.
 */
export interface GraphPath {
  path_id: string;
  from_account_id: string;
  to_account_id: string;
  direction: string;
  hop_count: number;
  nodes: GraphNode[];
  edges: GraphEdge[];
  amount_by_currency: Record<string, number>;
  earliest_at?: Iso8601 | null;
  latest_at?: Iso8601 | null;
}

export interface GraphPathsResult {
  generated_at: Iso8601;
  from_account_id: string;
  to_account_id: string;
  direction: string;
  max_depth: number;
  paths: GraphPath[];
  truncated: boolean;
  caveats: string[];
}

/** A chain of transfers leading away from, or into, one account. */
export interface MoneyTrail {
  trail_id: string;
  root_account_id: string;
  direction: string;
  hop_count: number;
  nodes: GraphNode[];
  edges: GraphEdge[];
  amount_by_currency: Record<string, number>;
  earliest_at?: Iso8601 | null;
  latest_at?: Iso8601 | null;
}

export interface MoneyTrailsResult {
  generated_at: Iso8601;
  root_account_id: string;
  direction: string;
  max_hops: number;
  trails: MoneyTrail[];
  truncated: boolean;
  caveats: string[];
}

/**
 * A set of accounts sharing one pseudonymous identifier.
 *
 * Sharing a device or a UPI handle suggests a connection. It does not prove
 * common control: shared addresses, recycled phone numbers and family devices
 * all produce the same signal, which is why `verification_states` and the
 * confidence range travel with the group.
 */
export interface SharedEntityGroup {
  entity: GraphNode;
  accounts: GraphNode[];
  edges: GraphEdge[];
  account_count: number;
  match_methods: string[];
  verification_states: string[];
  /** True only when every link in the group is an identity match. */
  deterministic: boolean;
  min_confidence?: number | null;
  max_confidence?: number | null;
}

export interface SharedEntitiesResult {
  generated_at: Iso8601;
  root_account_id: string;
  min_accounts: number;
  max_groups: number;
  max_accounts_per_entity: number;
  groups: SharedEntityGroup[];
  truncated: boolean;
  caveats: string[];
}

/**
 * The traversal limits this deployment enforces.
 *
 * Each limit has a configured value and a hard ceiling. A request above the
 * configured value is clamped rather than refused, so the UI shows the
 * effective limit instead of the one the user typed.
 */
export interface GraphStatus {
  enabled: boolean;
  max_nodes: number;
  hard_max_nodes: number;
  max_edges: number;
  hard_max_edges: number;
  max_depth: number;
  hard_max_depth: number;
  max_paths: number;
  hard_max_paths: number;
  max_trails: number;
  hard_max_trails: number;
  max_shared_groups: number;
  hard_max_shared_groups: number;
  max_accounts_per_entity: number;
  hard_max_accounts_per_entity: number;
  max_date_span_days: number;
  hard_max_date_span_days: number;
  caveats: string[];
}

export interface SubgraphQuery {
  account_id: string;
  depth?: number;
  direction?: GraphDirection;
  include_transactions?: boolean;
  include_entities?: boolean;
  include_complaints?: boolean;
  include_alerts?: boolean;
  include_assessments?: boolean;
  as_of?: string;
  date_from?: string;
  date_to?: string;
  min_amount?: number;
  max_amount?: number;
  max_nodes?: number;
  max_edges?: number;
}

export interface PathQuery {
  from_account_id: string;
  to_account_id: string;
  max_depth?: number;
  direction?: GraphDirection;
  max_paths?: number;
  as_of?: string;
  date_from?: string;
  date_to?: string;
  min_amount?: number;
  max_amount?: number;
}

export interface MoneyTrailQuery {
  account_id: string;
  direction?: 'outgoing' | 'incoming';
  max_hops?: number;
  max_trails?: number;
  as_of?: string;
  date_from?: string;
  date_to?: string;
  min_amount?: number;
  max_amount?: number;
}

export interface SharedEntitiesQuery {
  account_id: string;
  entity_type?: string;
  verification_state?: string;
  match_method?: string;
  min_accounts?: number;
  max_groups?: number;
  max_accounts_per_entity?: number;
  as_of?: string;
}

/** The account ids along a path or trail, in traversal order. */
export function accountChain(item: GraphPath | MoneyTrail): string[] {
  return item.nodes
    .filter((node) => node.type === 'account')
    .map((node) => node.account_id ?? node.id);
}

/**
 * Total transferred along a path, when every hop is in one currency.
 *
 * Returns null for a mixed-currency path rather than adding the figures
 * together: there is no rate to convert with, and a wrong total is worse than
 * no total.
 */
export function singleCurrencyTotal(
  amounts: Record<string, number>,
): { amount: number; currency: string } | null {
  const entries = Object.entries(amounts ?? {});
  if (entries.length !== 1) return null;

  const [currency, amount] = entries[0]!;
  return { amount, currency };
}
