import { Link } from 'react-router-dom';

import { Badge } from '@/components/common/Badge';
import { Button } from '@/components/common/Button';
import { CopyButton } from '@/components/common/CopyButton';
import { EmptyState } from '@/components/common/EmptyState';
import { KeyValueList } from '@/components/common/KeyValueList';
import { RiskBadge } from '@/components/common/RiskBadge';
import { formatAmount, formatConfidence, formatScore } from '@/lib/amounts';
import { ENTITY_TYPE_TOKENS, MATCH_METHOD_LABELS } from '@/lib/constants';
import { formatDateTime } from '@/lib/dates';
import { humaniseField, truncateId } from '@/lib/formatters';
import { paths } from '@/routes/paths';
import type { GraphNode } from '@/types/graph';

import { bandFromScore } from './cytoscapeTheme';

export interface NodeDetailPanelProps {
  node?: GraphNode | null;
  /** Make this node the root of the traversal. */
  onSetRoot?: (accountId: string) => void;
}

/**
 * The selected node.
 *
 * One `GraphNode` shape serves every kind of node, so almost every field is
 * optional and most are meaningless for any given kind. This panel switches on
 * `type` first and shows only what applies, rather than printing a list of
 * dashes — a panel of empty rows teaches a reader to stop looking at it.
 */
export function NodeDetailPanel({ node, onSetRoot }: NodeDetailPanelProps) {
  if (!node) {
    return (
      <EmptyState
        title="Nothing selected"
        message="Click a node on the canvas to see what it is."
        compact
      />
    );
  }

  const band = bandFromScore(node.score);

  const header = (
    <div className="mb-3">
      <div className="mb-1 flex flex-wrap items-center gap-1.5">
        <Badge tone="neutral">{humaniseField(node.type)}</Badge>
        {node.type === 'account' ? <RiskBadge band={band} score={node.score} /> : null}
      </div>

      <p className="flex items-center gap-1 break-all font-mono text-xs text-ink-800 dark:text-ink-100">
        {node.account_id ?? node.id}
        <CopyButton value={node.account_id ?? node.id} label="Copy identifier" />
      </p>
    </div>
  );

  if (node.type === 'account') {
    const accountId = node.account_id ?? node.id;

    return (
      <div>
        {header}

        <KeyValueList
          columns={1}
          entries={[
            { label: 'Type', value: node.account_type ? humaniseField(node.account_type) : '—' },
            {
              label: 'Source status',
              value: node.status ? humaniseField(node.status) : '—',
              help: 'As the source system reports it. MuleGuard does not set it.',
            },
            {
              label: 'Score',
              value: node.score !== null && node.score !== undefined ? formatScore(node.score) : 'Not assessed',
              mono: true,
              help:
                node.score === null || node.score === undefined
                  ? 'No assessment exists for this account. That is the absence of a score, not a low one.'
                  : 'Investigative priority, 0-100. Not a probability of guilt. The band shown here is derived from the score; the authoritative one is on the assessment.',
            },
          ]}
        />

        <div className="mt-3 flex flex-wrap gap-2">
          <Link to={paths.account(accountId)}>
            <Button size="sm" variant="secondary">
              Open account
            </Button>
          </Link>

          {onSetRoot ? (
            <Button size="sm" variant="ghost" onClick={() => onSetRoot(accountId)}>
              Traverse from here
            </Button>
          ) : null}
        </div>
      </div>
    );
  }

  if (node.type === 'transaction') {
    return (
      <div>
        {header}

        <KeyValueList
          columns={1}
          entries={[
            {
              label: 'Amount',
              value: formatAmount(node.amount, node.currency),
              mono: true,
            },
            { label: 'Occurred', value: formatDateTime(node.occurred_at) },
            {
              label: 'Status',
              value: node.status ? humaniseField(node.status) : '—',
              help: 'Only a completed transfer counts as fund movement.',
            },
            { label: 'Reference', value: node.reference ?? '—', mono: true },
            {
              label: 'From',
              value: node.sender_account_id ? (
                <Link
                  to={paths.account(node.sender_account_id)}
                  className="font-mono text-accent-700 hover:underline dark:text-accent-300"
                >
                  {truncateId(node.sender_account_id, 10)}
                </Link>
              ) : (
                '—'
              ),
            },
            {
              label: 'To',
              value: node.receiver_account_id ? (
                <Link
                  to={paths.account(node.receiver_account_id)}
                  className="font-mono text-accent-700 hover:underline dark:text-accent-300"
                >
                  {truncateId(node.receiver_account_id, 10)}
                </Link>
              ) : (
                '—'
              ),
            },
          ]}
        />
      </div>
    );
  }

  if (node.type === 'entity') {
    const token = node.entity_type ? ENTITY_TYPE_TOKENS[node.entity_type] : undefined;

    return (
      <div>
        {header}

        <KeyValueList
          columns={1}
          entries={[
            {
              label: 'Identifier kind',
              value: node.entity_type ? humaniseField(node.entity_type) : '—',
              help: token?.description,
            },
            {
              label: 'Verification',
              value: node.verification_state ? humaniseField(node.verification_state) : '—',
              help: 'An unverified link is a match the platform made, not one anybody has confirmed.',
            },
            { label: 'Source', value: node.source ?? '—' },
          ]}
        />

        <p className="mt-3 text-2xs leading-relaxed text-ink-600 dark:text-ink-300">
          Accounts sharing this identifier are connected by a dashed edge. Shared devices,
          recycled phone numbers and household addresses all produce this signal, so it suggests
          common control without establishing it.
        </p>
      </div>
    );
  }

  if (node.type === 'complaint') {
    return (
      <div>
        {header}

        <KeyValueList
          columns={1}
          entries={[
            { label: 'Category', value: node.category ? humaniseField(node.category) : '—' },
            { label: 'Reference', value: node.reference ?? '—', mono: true },
            { label: 'Reported loss', value: formatAmount(node.amount, node.currency), mono: true },
            {
              label: 'Narrative',
              value: node.narrative_available ? 'On file' : 'None',
              help: 'Reading it needs the complaint-narrative permission: it is the victim’s own account of events.',
            },
            {
              label: 'Matched by',
              value: node.match_method
                ? (MATCH_METHOD_LABELS[node.match_method] ?? humaniseField(node.match_method))
                : '—',
            },
            {
              label: 'Confidence',
              value: node.deterministic
                ? 'Identity match'
                : formatConfidence(node.confidence),
              help: node.deterministic
                ? 'The complaint named a reference that exists, so no confidence value applies.'
                : 'An inference. A lead until a reviewer accepts it.',
            },
          ]}
        />

        <Link
          to={paths.complaint(node.id)}
          className="mt-3 inline-block text-2xs font-medium text-accent-700 hover:underline dark:text-accent-300"
        >
          Open complaint
        </Link>
      </div>
    );
  }

  if (node.type === 'alert') {
    return (
      <div>
        {header}

        <KeyValueList
          columns={1}
          entries={[
            { label: 'Priority', value: node.priority ? humaniseField(node.priority) : '—' },
            { label: 'State', value: node.state ? humaniseField(node.state) : '—' },
            { label: 'Score', value: formatScore(node.score), mono: true },
          ]}
        />

        <Link
          to={paths.alert(node.id)}
          className="mt-3 inline-block text-2xs font-medium text-accent-700 hover:underline dark:text-accent-300"
        >
          Open alert
        </Link>
      </div>
    );
  }

  // assessment, and anything a future backend adds
  return (
    <div>
      {header}

      <KeyValueList
        columns={1}
        entries={[
          { label: 'Score', value: formatScore(node.score), mono: true },
          {
            label: 'Band',
            value: node.review_state ? humaniseField(node.review_state) : '—',
            help: 'The band recorded on the assessment itself, which is the authoritative one.',
          },
          {
            label: 'Explanation',
            value: node.explanation_available ? 'Recorded' : 'None',
            help: node.explanation_available
              ? undefined
              : 'This assessment carries no written explanation, so the score cannot be justified from it alone.',
          },
        ]}
      />
    </div>
  );
}
