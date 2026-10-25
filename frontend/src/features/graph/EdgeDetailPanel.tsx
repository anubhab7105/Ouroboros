import { Link } from 'react-router-dom';

import { Badge } from '@/components/common/Badge';
import { CopyButton } from '@/components/common/CopyButton';
import { EmptyState } from '@/components/common/EmptyState';
import { KeyValueList } from '@/components/common/KeyValueList';
import { formatAmount, formatConfidence } from '@/lib/amounts';
import { MATCH_METHOD_LABELS } from '@/lib/constants';
import { formatDateTime } from '@/lib/dates';
import { formatEvidenceReference, humaniseField, truncateId } from '@/lib/formatters';
import { paths } from '@/routes/paths';
import type { GraphEdge } from '@/types/graph';

import { isInferredEdge } from './cytoscapeTheme';

export interface EdgeDetailPanelProps {
  edge?: GraphEdge | null;
}

/**
 * The selected edge.
 *
 * The first thing this panel establishes is which kind of claim the edge
 * makes, because that is what decides whether it can be cited:
 *
 * - A **recorded** edge is a transfer in the ledger. It can be quoted.
 * - An **inferred** edge is something the platform derived — a shared
 *   identifier, a complaint correlation — and carries a confidence and a
 *   review state. Until a human accepts it, it is a lead.
 *
 * Confidence reads "identity" rather than 1.000 on a deterministic edge, for
 * the same reason it does everywhere else: a number there would imply a
 * measurement that was never made.
 */
export function EdgeDetailPanel({ edge }: EdgeDetailPanelProps) {
  if (!edge) {
    return (
      <EmptyState
        title="Nothing selected"
        message="Click an edge on the canvas to see what connects the two nodes."
        compact
      />
    );
  }

  const inferred = isInferredEdge(edge);

  return (
    <div>
      <div className="mb-3">
        <div className="mb-1 flex flex-wrap items-center gap-1.5">
          <Badge tone="neutral">{humaniseField(edge.type)}</Badge>
          <Badge
            tone={inferred ? 'warning' : 'neutral'}
            title={
              inferred
                ? 'Derived by the platform. It suggests a connection and does not establish one.'
                : 'A transfer that is in the ledger.'
            }
          >
            {inferred ? 'Inferred' : 'Recorded'}
          </Badge>
        </div>

        {edge.label ? (
          <p className="text-xs text-ink-800 dark:text-ink-100">{edge.label}</p>
        ) : null}
      </div>

      <KeyValueList
        columns={1}
        entries={[
          {
            label: 'From',
            value: (
              <span className="font-mono text-2xs" title={edge.source}>
                {truncateId(edge.source, 12)}
              </span>
            ),
          },
          {
            label: 'To',
            value: (
              <span className="font-mono text-2xs" title={edge.target}>
                {truncateId(edge.target, 12)}
              </span>
            ),
          },
          ...(edge.amount !== null && edge.amount !== undefined
            ? [
                {
                  label: 'Amount',
                  value: formatAmount(edge.amount, edge.currency),
                  mono: true,
                },
              ]
            : []),
          ...(edge.occurred_at
            ? [{ label: 'Occurred', value: formatDateTime(edge.occurred_at) }]
            : []),
          ...(edge.match_method
            ? [
                {
                  label: 'Matched by',
                  value: MATCH_METHOD_LABELS[edge.match_method] ?? humaniseField(edge.match_method),
                },
              ]
            : []),
          ...(inferred
            ? [
                {
                  label: 'Confidence',
                  value: edge.deterministic
                    ? 'Identity match'
                    : formatConfidence(edge.confidence),
                  help: edge.deterministic
                    ? 'An exact match on an identifier, so no confidence value applies.'
                    : 'How strongly the platform believes this link holds. Not a probability of wrongdoing.',
                },
              ]
            : []),
          ...(edge.review_state
            ? [
                {
                  label: 'Review',
                  value: humaniseField(edge.review_state),
                  help:
                    edge.review_state === 'UNREVIEWED'
                      ? 'Nobody has accepted or rejected this link, so it should not be relied on in a report.'
                      : undefined,
                },
              ]
            : []),
          ...(edge.verification_state
            ? [
                {
                  label: 'Verification',
                  value: humaniseField(edge.verification_state),
                  help: 'An unverified identifier link is a match the platform made, not one anybody has confirmed.',
                },
              ]
            : []),
        ]}
      />

      {edge.transaction_id ? (
        <div className="mt-3">
          <Link
            to={`${paths.transactions}?reference=${encodeURIComponent(edge.transaction_id)}`}
            className="text-2xs font-medium text-accent-700 hover:underline dark:text-accent-300"
          >
            Open the transaction
          </Link>
        </div>
      ) : null}

      {edge.evidence_refs.length > 0 ? (
        <div className="mt-3 border-t border-ink-200 pt-2 dark:border-ink-700">
          <h3 className="mb-1 flex items-center gap-1 text-2xs font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
            Evidence
            <CopyButton
              value={edge.evidence_refs.join('\n')}
              label="Copy all evidence references"
            />
          </h3>
          <ul className="space-y-0.5">
            {edge.evidence_refs.slice(0, 8).map((reference) => (
              <li
                key={reference}
                className="font-mono text-2xs text-ink-700 dark:text-ink-200"
                title={reference}
              >
                {formatEvidenceReference(reference)}
              </li>
            ))}
          </ul>
          {edge.evidence_refs.length > 8 ? (
            <p className="mt-0.5 text-2xs text-ink-500 dark:text-ink-400">
              and {edge.evidence_refs.length - 8} more.
            </p>
          ) : null}
        </div>
      ) : null}

      {inferred ? (
        <p className="mt-3 text-2xs leading-relaxed text-ink-600 dark:text-ink-300">
          This edge is drawn dashed because the platform derived it. Citing it in a case means
          citing an inference, and the case should say so.
        </p>
      ) : null}
    </div>
  );
}
