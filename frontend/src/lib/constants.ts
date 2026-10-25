import type { AlertState } from '@/types/alert';
import type { CaseStatus, Disposition } from '@/types/case';
import type { Priority, RiskBand, ScoringMode, Severity } from '@/types/common';
/**
 * Display tokens for every enum the API returns.
 *
 * Two rules hold throughout:
 *
 * 1. **Colour never carries meaning alone.** Every entry has a `label`, and
 *    components render it. The colour is a scanning aid for someone working a
 *    queue, not the information itself.
 *
 * 2. **The risk ramp is not a traffic light.** `LOW` is slate, not green. A low
 *    score means "not prioritised", not "cleared" — the detector only finds
 *    typologies it knows about. Green would tell an analyst the opposite of
 *    what the score means.
 */

export interface DisplayToken {
  label: string;
  /** Tailwind classes for a badge: background, text, and border accent. */
  className: string;
  /** Hex, for chart series and the Cytoscape stylesheet. */
  hex: string;
  description?: string;
}

export const RISK_BAND_TOKENS: Record<RiskBand, DisplayToken> = {
  CRITICAL: {
    label: 'Critical',
    className: 'border-l-risk-critical bg-red-50 text-red-900 dark:bg-red-950/40 dark:text-red-200',
    hex: '#8c1d18',
    description: 'Multiple corroborating typologies. Review first.',
  },
  HIGH: {
    label: 'High',
    className:
      'border-l-risk-high bg-orange-50 text-orange-900 dark:bg-orange-950/40 dark:text-orange-200',
    hex: '#b3541e',
    description: 'A strong typology or several agreeing signals.',
  },
  MEDIUM: {
    label: 'Medium',
    className:
      'border-l-risk-medium bg-amber-50 text-amber-900 dark:bg-amber-950/40 dark:text-amber-200',
    hex: '#8a6d1f',
    description: 'Weaker signals that agree with each other.',
  },
  LOW: {
    label: 'Low',
    className: 'border-l-risk-low bg-ink-100 text-ink-700 dark:bg-ink-800 dark:text-ink-300',
    hex: '#546175',
    description: 'Not prioritised. This is not a clearance.',
  },
};

export const SEVERITY_TOKENS: Record<Severity, DisplayToken> = {
  CRITICAL: { label: 'Critical', className: RISK_BAND_TOKENS.CRITICAL.className, hex: '#8c1d18' },
  HIGH: { label: 'High', className: RISK_BAND_TOKENS.HIGH.className, hex: '#b3541e' },
  MEDIUM: { label: 'Medium', className: RISK_BAND_TOKENS.MEDIUM.className, hex: '#8a6d1f' },
  LOW: { label: 'Low', className: RISK_BAND_TOKENS.LOW.className, hex: '#546175' },
};

export const PRIORITY_TOKENS: Record<Priority, DisplayToken> = SEVERITY_TOKENS;

export const ALERT_STATE_TOKENS: Record<AlertState, DisplayToken> = {
  NEW: {
    label: 'New',
    className: 'bg-accent-100 text-accent-800 dark:bg-accent-900/50 dark:text-accent-200',
    hex: '#2f63ad',
    description: 'Not yet triaged.',
  },
  ACKNOWLEDGED: {
    label: 'Acknowledged',
    className: 'bg-ink-100 text-ink-700 dark:bg-ink-800 dark:text-ink-300',
    hex: '#546175',
    description: 'Seen, not yet worked.',
  },
  UNDER_REVIEW: {
    label: 'Under review',
    className: 'bg-amber-50 text-amber-900 dark:bg-amber-950/40 dark:text-amber-200',
    hex: '#8a6d1f',
    description: 'Actively being investigated.',
  },
  ESCALATED: {
    label: 'Escalated',
    className:
      'bg-orange-50 text-orange-900 dark:bg-orange-950/40 dark:text-orange-200',
    hex: '#b3541e',
    description: 'Raised to a senior investigator.',
  },
  CLOSED: {
    label: 'Closed',
    className: 'bg-ink-100 text-ink-500 dark:bg-ink-800 dark:text-ink-400',
    hex: '#8b99ac',
    description: 'Resolved without a case, or superseded.',
  },
};

export const CASE_STATUS_TOKENS: Record<CaseStatus, DisplayToken> = {
  NEW: {
    label: 'New',
    className: 'bg-accent-100 text-accent-800 dark:bg-accent-900/50 dark:text-accent-200',
    hex: '#2f63ad',
  },
  TRIAGED: {
    label: 'Triaged',
    className: 'bg-ink-100 text-ink-700 dark:bg-ink-800 dark:text-ink-300',
    hex: '#546175',
  },
  UNDER_INVESTIGATION: {
    label: 'Under investigation',
    className: 'bg-amber-50 text-amber-900 dark:bg-amber-950/40 dark:text-amber-200',
    hex: '#8a6d1f',
  },
  ESCALATED: {
    label: 'Escalated',
    className: 'bg-orange-50 text-orange-900 dark:bg-orange-950/40 dark:text-orange-200',
    hex: '#b3541e',
  },
  CLOSED: {
    label: 'Closed',
    className: 'bg-ink-100 text-ink-500 dark:bg-ink-800 dark:text-ink-400',
    hex: '#8b99ac',
  },
};

export const DISPOSITION_TOKENS: Record<Disposition, DisplayToken> = {
  CONFIRMED_FRAUD: {
    label: 'Confirmed fraud',
    className: 'bg-red-50 text-red-900 dark:bg-red-950/40 dark:text-red-200',
    hex: '#8c1d18',
    description: 'The investigator concluded the activity was fraudulent.',
  },
  FALSE_POSITIVE: {
    label: 'False positive',
    className: 'bg-emerald-50 text-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-200',
    hex: '#1f6f50',
    description: 'Legitimate activity. The detector was wrong.',
  },
  INCONCLUSIVE: {
    label: 'Inconclusive',
    className: 'bg-ink-100 text-ink-700 dark:bg-ink-800 dark:text-ink-300',
    hex: '#546175',
    description: 'Not enough information to decide either way.',
  },
  REFERRED: {
    label: 'Referred',
    className: 'bg-accent-100 text-accent-800 dark:bg-accent-900/50 dark:text-accent-200',
    hex: '#2f63ad',
    description: 'Passed to another team or an external body.',
  },
};

/**
 * Scoring mode is the single most important caveat on any score, so each one
 * carries the sentence a reader needs rather than just a label.
 */
export const SCORING_MODE_TOKENS: Record<ScoringMode, DisplayToken> = {
  TRAINED_MODEL: {
    label: 'Trained model',
    className: 'bg-accent-100 text-accent-800 dark:bg-accent-900/50 dark:text-accent-200',
    hex: '#2f63ad',
    description:
      'A validated supervised model contributed. It was trained on synthetic labels, so its measured performance describes that distribution only.',
  },
  HEURISTIC_FALLBACK: {
    label: 'Heuristic fallback',
    className: 'bg-amber-50 text-amber-900 dark:bg-amber-950/40 dark:text-amber-200',
    hex: '#8a6d1f',
    description:
      'No trained model is promoted, so the transparent heuristic scorer was used. Its weights are hand-set, not learned.',
  },
  RULES_ONLY: {
    label: 'Rules only',
    className: 'bg-ink-100 text-ink-700 dark:bg-ink-800 dark:text-ink-300',
    hex: '#546175',
    description:
      'Rule evaluation alone. Only typologies encoded in the rule pack can be detected.',
  },
  ML_DISABLED: {
    label: 'ML disabled',
    className: 'bg-ink-100 text-ink-500 dark:bg-ink-800 dark:text-ink-400',
    hex: '#8b99ac',
    description: 'Machine-learning scoring is switched off in configuration.',
  },
  UNKNOWN: {
    label: 'Unknown',
    className: 'bg-ink-100 text-ink-500 dark:bg-ink-800 dark:text-ink-400',
    hex: '#8b99ac',
    description: 'No assessment has been produced yet.',
  },
};

export const MATCH_METHOD_LABELS: Record<string, string> = {
  EXACT: 'Exact reference',
  NORMALIZED: 'Normalised reference',
  ENTITY_TEMPORAL: 'Shared entity in window',
  GRAPH_TEMPORAL: 'Amount and time proximity',
  NARRATIVE_EXTRACTION: 'Extracted from narrative',
  MANUAL: 'Manually linked',
  UNKNOWN: 'Unknown',
};

/** Tier 1-2 are identities; 3-5 are inferred. */
export const MATCH_TIER_TOKENS: Record<number, DisplayToken> = {
  1: {
    label: 'Tier 1',
    className: 'bg-accent-100 text-accent-900 dark:bg-accent-900/50 dark:text-accent-100',
    hex: '#1f4e79',
    description: 'Exact reference match. Deterministic.',
  },
  2: {
    label: 'Tier 2',
    className: 'bg-accent-50 text-accent-800 dark:bg-accent-900/40 dark:text-accent-200',
    hex: '#2f63ad',
    description: 'Normalised reference match. Deterministic.',
  },
  3: {
    label: 'Tier 3',
    className: 'bg-amber-50 text-amber-900 dark:bg-amber-950/40 dark:text-amber-200',
    hex: '#8a6d1f',
    description: 'Shared entity within the complaint window. Inferred.',
  },
  4: {
    label: 'Tier 4',
    className: 'bg-orange-50 text-orange-900 dark:bg-orange-950/40 dark:text-orange-200',
    hex: '#b3541e',
    description: 'Amount and time proximity. Inferred.',
  },
  5: {
    label: 'Tier 5',
    className: 'bg-ink-100 text-ink-600 dark:bg-ink-800 dark:text-ink-300',
    hex: '#6b7a8f',
    description: 'Reference extracted from narrative text. Weakest.',
  },
};

/**
 * What an account's lifecycle status means — and, crucially, who set it.
 *
 * Every one of these is the source system's view, reproduced. MuleGuard never
 * freezes, closes or flags an account: it ranks accounts for analyst
 * attention. An investigator reading "Review required" here must not conclude
 * that this platform placed the account under review.
 */
export const ACCOUNT_STATUS_HINTS: Record<string, string> = {
  ACTIVE: 'Reported active by the source system.',
  DORMANT:
    'Reported dormant by the source system. Reactivation after dormancy is itself a signal MuleGuard looks for.',
  CLOSED: 'Reported closed by the source system. Historical transactions are still analysed.',
  REVIEW_REQUIRED:
    'The source system flagged this account for review. MuleGuard did not set this and takes no action on it.',
};

export const CHANNEL_LABELS: Record<string, string> = {
  UPI: 'UPI',
  IMPS: 'IMPS',
  NEFT: 'NEFT',
  RTGS: 'RTGS',
  CARD: 'Card',
  INTERNAL: 'Internal',
};

export const TRANSACTION_STATUS_TOKENS: Record<string, DisplayToken> = {
  COMPLETED: {
    label: 'Completed',
    className: 'bg-emerald-50 text-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-200',
    hex: '#1f6f50',
    description: 'Counts as fund movement.',
  },
  PENDING: {
    label: 'Pending',
    className: 'bg-ink-100 text-ink-700 dark:bg-ink-800 dark:text-ink-300',
    hex: '#546175',
    description: 'Not counted in totals.',
  },
  FAILED: {
    label: 'Failed',
    className: 'bg-ink-100 text-ink-500 dark:bg-ink-800 dark:text-ink-400',
    hex: '#8b99ac',
    description: 'Not fund movement. Excluded from every total.',
  },
  REVERSED: {
    label: 'Reversed',
    className: 'bg-ink-100 text-ink-500 dark:bg-ink-800 dark:text-ink-400',
    hex: '#8b99ac',
    description: 'Not fund movement. Excluded from every total.',
  },
};

/** Entity kinds, ordered by how strongly sharing one suggests shared control. */
export const ENTITY_TYPE_TOKENS: Record<string, DisplayToken & { strength: number }> = {
  DEVICE: {
    label: 'Device',
    className: 'bg-accent-100 text-accent-800 dark:bg-accent-900/50 dark:text-accent-200',
    hex: '#1f4e79',
    strength: 5,
    description: 'Strongest association. Still shared legitimately within families.',
  },
  UPI_ID: {
    label: 'UPI handle',
    className: 'bg-accent-50 text-accent-800 dark:bg-accent-900/40 dark:text-accent-200',
    hex: '#2f63ad',
    strength: 4,
  },
  PHONE_HASH: {
    label: 'Phone',
    className: 'bg-ink-100 text-ink-700 dark:bg-ink-800 dark:text-ink-300',
    hex: '#546175',
    strength: 3,
  },
  EMAIL_HASH: {
    label: 'Email',
    className: 'bg-ink-100 text-ink-700 dark:bg-ink-800 dark:text-ink-300',
    hex: '#546175',
    strength: 3,
  },
  ADDRESS_HASH: {
    label: 'Address',
    className: 'bg-ink-100 text-ink-600 dark:bg-ink-800 dark:text-ink-300',
    hex: '#6b7a8f',
    strength: 2,
  },
  IP_HASH: {
    label: 'IP address',
    className: 'bg-ink-100 text-ink-500 dark:bg-ink-800 dark:text-ink-400',
    hex: '#8b99ac',
    strength: 1,
    description: 'Weak: carrier NAT and public Wi-Fi put unrelated accounts behind one address.',
  },
  OTHER: {
    label: 'Other',
    className: 'bg-ink-100 text-ink-500 dark:bg-ink-800 dark:text-ink-400',
    hex: '#8b99ac',
    strength: 1,
  },
};

/** Categorical series colours for charts. Accessible in light and dark. */
export const CHART_SERIES_COLORS: string[] = [
  '#1f4e79',
  '#b3541e',
  '#1f6f50',
  '#8a6d1f',
  '#5b4b8a',
  '#2f7d95',
  '#8c1d18',
  '#6b7a8f',
];

export const PAGE_SIZE_OPTIONS = [10, 25, 50, 100] as const;
export const DEFAULT_PAGE_SIZE = 25;

/** The server's hard cap. Requesting more returns this many. */
export const MAX_PAGE_SIZE = 200;

export const DEFAULT_DASHBOARD_WINDOW_DAYS = 30;
export const MAX_DASHBOARD_WINDOW_DAYS = 90;
export const WINDOW_DAY_OPTIONS = [7, 30, MAX_DASHBOARD_WINDOW_DAYS] as const;

export const DEFAULT_GRAPH_LIMITS = {
  maxHops: 2,
  maxNodes: 200,
  maxEdges: 800,
  spanDays: 90,
} as const;

/**
 * The one sentence that must accompany any score shown out of context.
 * Mirrors `app/reports/limitations.py` so the UI and the PDF agree.
 */
export const SCORE_SEMANTICS =
  'The investigative priority score ranks accounts for analyst attention. It is not a probability of guilt and does not authorise any automatic action.';
