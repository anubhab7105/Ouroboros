import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link } from 'react-router-dom';

import { Badge } from '@/components/common/Badge';
import { Button } from '@/components/common/Button';
import { CopyButton } from '@/components/common/CopyButton';
import { DataTable, type Column } from '@/components/common/DataTable';
import { ErrorState } from '@/components/common/ErrorState';
import { FormField } from '@/components/common/FormField';
import { Modal } from '@/components/common/Modal';
import { Select } from '@/components/common/Select';
import { TextArea } from '@/components/common/TextArea';
import { RoleGate } from '@/components/layout/RoleGate';
import { useApiError } from '@/hooks/useApiError';
import { formatDate } from '@/lib/dates';
import { humaniseEnum, truncateId } from '@/lib/formatters';
import { queryKeys } from '@/lib/queryKeys';
import { paths } from '@/routes/paths';
import type { ComplaintCorrelation, ComplaintReviewState } from '@/types/complaint';

import { ComplaintMatchBadge } from './ComplaintMatchBadge';
import { reviewCorrelation } from './complaintsApi';

export interface ComplaintCorrelationTableProps {
  complaintId: string;
  rows: ComplaintCorrelation[];
  isLoading?: boolean;
}

/**
 * The review states a correlation can be put into.
 *
 * `REVIEWED` is deliberately not offered: it says a human looked without
 * saying what they concluded, which is the one outcome that helps nobody. The
 * other four each record a decision.
 */
const REVIEW_OPTIONS: Array<{
  value: ComplaintReviewState;
  label: string;
  help: string;
}> = [
  {
    value: 'ACCEPTED',
    label: 'Accept',
    help: 'The link holds. From here it can be relied on in a case or a report.',
  },
  {
    value: 'REJECTED',
    label: 'Reject',
    help: 'The link does not hold. Recording this is how the correlation rules get better.',
  },
  {
    value: 'NEEDS_MORE_INFO',
    label: 'Needs more information',
    help: 'Cannot be decided on what is held. Stays out of reports until it can be.',
  },
];

/**
 * Correlations for one complaint, with review.
 *
 * Deterministic and inferred rows are shown in one table but never presented
 * as equivalent: the review controls appear only on inferred rows, because
 * there is nothing for a human to decide about an exact reference match. The
 * confidence column reads "identity" rather than 1.000 for the same reason.
 *
 * Review is a senior action, enforced server-side; the control is gated here
 * so an analyst is not offered a button that will 403.
 */
export function ComplaintCorrelationTable({
  complaintId,
  rows,
  isLoading,
}: ComplaintCorrelationTableProps) {
  const queryClient = useQueryClient();

  const [pending, setPending] = useState<ComplaintCorrelation | null>(null);
  const [state, setState] = useState<ComplaintReviewState>('ACCEPTED');
  const [note, setNote] = useState('');
  const [outcome, setOutcome] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: () =>
      reviewCorrelation(complaintId, pending!.id, {
        review_state: state,
        note: note.trim() || undefined,
      }),
    onSuccess: (result) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.complaints.all });
      void queryClient.invalidateQueries({ queryKey: queryKeys.dashboard.all });

      setOutcome(
        result.changed
          ? `Correlation moved from ${humaniseEnum(result.previous_state)} to ${humaniseEnum(result.new_state)}.`
          : `Nothing changed — it was already ${humaniseEnum(result.new_state)}.`,
      );

      setPending(null);
      setNote('');
    },
  });

  const error = useApiError(mutation.error);

  const columns: Array<Column<ComplaintCorrelation>> = [
    {
      key: 'match',
      header: 'Match',
      render: (row) => (
        <ComplaintMatchBadge
          tier={row.match_tier}
          method={row.match_method}
          deterministic={row.deterministic}
          confidence={row.confidence}
          verbose
        />
      ),
      width: '26%',
    },
    {
      key: 'target',
      header: 'Linked to',
      render: (row) => {
        if (row.account_id) {
          return (
            <span className="flex items-center gap-1">
              <span className="text-2xs text-ink-500 dark:text-ink-400">account</span>
              <Link
                to={paths.account(row.account_id)}
                className="font-mono text-xs text-accent-700 hover:underline dark:text-accent-300"
                title={row.account_id}
              >
                {truncateId(row.account_id, 8)}
              </Link>
            </span>
          );
        }

        if (row.transaction_id) {
          return (
            <span className="flex items-center gap-1">
              <span className="text-2xs text-ink-500 dark:text-ink-400">transaction</span>
              <span className="font-mono text-xs" title={row.transaction_id}>
                {truncateId(row.transaction_id, 8)}
              </span>
            </span>
          );
        }

        if (row.entity_id) {
          return (
            <span className="flex items-center gap-1">
              <span
                className="text-2xs text-ink-500 dark:text-ink-400"
                title="A shared identifier such as a device or UPI handle. Sharing one suggests a connection; it does not prove common control."
              >
                identifier
              </span>
              <span className="font-mono text-xs" title={row.entity_id}>
                {truncateId(row.entity_id, 8)}
              </span>
            </span>
          );
        }

        return <span className="text-2xs text-ink-400 dark:text-ink-500">—</span>;
      },
      width: '22%',
    },
    {
      key: 'created_at',
      header: 'Found',
      render: (row) => (
        <span className="whitespace-nowrap text-xs tabular text-ink-600 dark:text-ink-300">
          {formatDate(row.created_at)}
        </span>
      ),
      hideOnSmall: true,
      width: '11%',
    },
    {
      key: 'review_state',
      header: 'Review',
      render: (row) =>
        row.deterministic ? (
          <span
            className="text-2xs text-ink-500 dark:text-ink-400"
            title="An identity match needs no review: the reference either exists or it does not."
          >
            Not required
          </span>
        ) : (
          <Badge
            tone={row.review_state === 'UNREVIEWED' ? 'warning' : 'neutral'}
            title={
              row.review_state === 'UNREVIEWED'
                ? 'Nobody has accepted or rejected this inference, so it remains a lead.'
                : undefined
            }
          >
            {humaniseEnum(row.review_state)}
          </Badge>
        ),
      width: '15%',
    },
    {
      key: 'evidence_refs',
      header: 'Evidence',
      render: (row) =>
        row.evidence_refs.length === 0 ? (
          <span className="text-2xs text-ink-400 dark:text-ink-500">—</span>
        ) : (
          <span className="flex items-center gap-1">
            <span className="font-mono text-2xs text-ink-600 dark:text-ink-300" title={row.evidence_refs.join('\n')}>
              {row.evidence_refs.length} ref{row.evidence_refs.length === 1 ? '' : 's'}
            </span>
            <CopyButton
              value={row.evidence_refs.join('\n')}
              label="Copy evidence references"
            />
          </span>
        ),
      hideOnSmall: true,
      width: '12%',
    },
    {
      key: 'actions',
      header: <span className="mg-visually-hidden">Actions</span>,
      // The endpoint gates review by role rather than by a capability flag —
      // there is no `complaint_review` in the capability map — so the control
      // follows the same rule.
      render: (row) =>
        row.deterministic ? null : (
          <RoleGate roles={['SENIOR_INVESTIGATOR', 'ADMIN']} silent>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => {
                setOutcome(null);
                setState('ACCEPTED');
                setPending(row);
              }}
            >
              Review
            </Button>
          </RoleGate>
        ),
      width: '14%',
    },
  ];

  return (
    <div>
      <DataTable
        caption="Correlations for this complaint, with review state"
        columns={columns}
        rows={rows}
        rowKey={(row) => row.id}
        isLoading={isLoading}
        emptyTitle="No correlation found for this complaint"
        emptyMessage="Correlation runs as part of an analysis run. An absence here is not evidence that no account is involved."
      />

      {outcome ? (
        <p role="status" className="mt-2 px-4 text-2xs text-ink-600 dark:text-ink-300">
          {outcome}
        </p>
      ) : null}

      {error && !pending ? <ErrorState error={error} compact className="mt-2" /> : null}

      <Modal
        open={Boolean(pending)}
        onClose={() => setPending(null)}
        title="Review this correlation"
        size="md"
        footer={
          <div className="flex items-center justify-end gap-2">
            <Button variant="ghost" onClick={() => setPending(null)} disabled={mutation.isPending}>
              Cancel
            </Button>
            <Button
              variant="primary"
              isLoading={mutation.isPending}
              onClick={() => mutation.mutate()}
            >
              Record decision
            </Button>
          </div>
        }
      >
        {pending ? (
          <div className="space-y-4">
            {error ? <ErrorState error={error} compact /> : null}

            <div className="rounded-md border border-ink-200 p-3 dark:border-ink-700">
              <ComplaintMatchBadge
                tier={pending.match_tier}
                method={pending.match_method}
                deterministic={pending.deterministic}
                confidence={pending.confidence}
                verbose
              />
              <p className="mt-2 text-2xs leading-relaxed text-ink-700 dark:text-ink-200">
                {pending.match_tier === 5
                  ? 'This link came from text extracted out of the complaint narrative, which is the weakest signal the platform produces. Check the reference against the ledger before accepting it.'
                  : pending.match_tier === 4
                    ? 'This link rests on proximity in amount and time. Coincidence is entirely possible at this tier.'
                    : 'This link rests on a shared identifier within the complaint window. Shared devices and recycled phone numbers produce the same signal.'}
              </p>
            </div>

            <FormField label="Decision">
              {({ id }) => (
                <>
                  <Select
                    id={id}
                    value={state}
                    onChange={(event) => setState(event.target.value as ComplaintReviewState)}
                    options={REVIEW_OPTIONS.map((option) => ({
                      value: option.value,
                      label: option.label,
                    }))}
                  />
                  <p className="mt-1 text-2xs text-ink-600 dark:text-ink-300">
                    {REVIEW_OPTIONS.find((option) => option.value === state)?.help}
                  </p>
                </>
              )}
            </FormField>

            <FormField
              label="Note"
              hint="Optional, permanent, and attributed to you. A rejection with a stated reason is what improves the correlation rules."
            >
              {({ id }) => (
                <TextArea
                  id={id}
                  value={note}
                  onChange={(event) => setNote(event.target.value)}
                  rows={3}
                  maxLength={2000}
                />
              )}
            </FormField>
          </div>
        ) : null}
      </Modal>
    </div>
  );
}
