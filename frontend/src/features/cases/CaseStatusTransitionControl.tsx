import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';

import { Button } from '@/components/common/Button';
import { ErrorState } from '@/components/common/ErrorState';
import { FormField } from '@/components/common/FormField';
import { Modal } from '@/components/common/Modal';
import { Select } from '@/components/common/Select';
import { TextArea } from '@/components/common/TextArea';
import { RoleGate } from '@/components/layout/RoleGate';
import { useApiError } from '@/hooks/useApiError';
import { queryKeys } from '@/lib/queryKeys';
import type { CaseActionResult, InvestigationCase } from '@/types/case';

import { DISPOSITION_OPTIONS, transitionsFrom, type TransitionSpec } from './caseTransitions';
import { closeCase, escalateCase, reopenCase, startCase } from './casesApi';

export interface CaseStatusTransitionControlProps {
  investigation: InvestigationCase;
}

/**
 * The status actions for a case.
 *
 * Which actions appear comes from a client-side table (`caseTransitions.ts`),
 * because the API does not publish the available transitions. That table can
 * drift from the server, so nothing here pre-empts a refusal: the action is
 * attempted and a 403 or a 409 is shown as what it is.
 *
 * Closing and reopening both go through a confirmation that states what the
 * action does. Closing in particular is the moment the case's conclusion is
 * recorded, and a misclick there is a wrong answer in a record somebody may
 * rely on.
 *
 * `changed: false` is reported rather than hidden. Starting an
 * already-started case is a no-op, and telling the user "nothing changed" is
 * more useful than a success message that implies otherwise.
 */
export function CaseStatusTransitionControl({
  investigation,
}: CaseStatusTransitionControlProps) {
  const queryClient = useQueryClient();
  const [pending, setPending] = useState<TransitionSpec | null>(null);
  const [reason, setReason] = useState('');
  const [disposition, setDisposition] = useState('');
  const [outcome, setOutcome] = useState<string | null>(null);
  const [submitted, setSubmitted] = useState(false);

  const mutation = useMutation({
    mutationFn: async (spec: TransitionSpec): Promise<CaseActionResult> => {
      switch (spec.action) {
        case 'start':
          return startCase(investigation.id);
        case 'escalate':
          return escalateCase(investigation.id, { reason: reason.trim() });
        case 'close':
          return closeCase(investigation.id, {
            reason: reason.trim(),
            disposition,
          });
        case 'reopen':
          return reopenCase(investigation.id, { reason: reason.trim() });
      }
    },
    onSuccess: (result) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.cases.all });
      void queryClient.invalidateQueries({ queryKey: queryKeys.dashboard.all });

      setOutcome(
        result.changed
          ? `Case moved from ${result.previous_status} to ${result.new_status}.`
          : `Nothing changed — the case was already ${result.new_status}.`,
      );

      setPending(null);
      setReason('');
      setDisposition('');
      setSubmitted(false);
    },
  });

  const error = useApiError(mutation.error);
  const available = transitionsFrom(investigation.status);

  const canSubmit = (spec: TransitionSpec) =>
    (!spec.requiresReason || reason.trim().length > 0) &&
    (!spec.requiresDisposition || disposition.length > 0);

  const start = (spec: TransitionSpec) => {
    setOutcome(null);
    setSubmitted(false);
    setReason('');
    setDisposition('');

    if (spec.confirm || spec.requiresReason || spec.requiresDisposition) {
      setPending(spec);
    } else {
      mutation.mutate(spec);
    }
  };

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2">
        {available.length === 0 ? (
          <p className="text-2xs text-ink-500 dark:text-ink-400">
            No status change is available from {investigation.status}.
          </p>
        ) : (
          available.map((spec) => {
            const blocked = spec.requiresAssignee && !investigation.assignee_id;

            return (
              <RoleGate key={spec.action} permissions={[spec.capability]} silent>
                <Button
                  size="sm"
                  variant={spec.action === 'close' ? 'primary' : 'secondary'}
                  onClick={() => start(spec)}
                  disabled={blocked}
                  isLoading={mutation.isPending && mutation.variables?.action === spec.action}
                  title={
                    blocked
                      ? 'Assign the case first. An investigation in progress needs somebody accountable for it.'
                      : spec.description
                  }
                >
                  {spec.label}
                </Button>
              </RoleGate>
            );
          })
        )}
      </div>

      {outcome ? (
        <p role="status" className="mt-2 text-2xs text-ink-600 dark:text-ink-300">
          {outcome}
        </p>
      ) : null}

      {error && !pending ? <ErrorState error={error} compact className="mt-2" /> : null}

      <Modal
        open={Boolean(pending)}
        onClose={() => setPending(null)}
        title={pending?.label ?? ''}
        footer={
          <div className="flex items-center justify-end gap-2">
            <Button variant="ghost" onClick={() => setPending(null)} disabled={mutation.isPending}>
              Cancel
            </Button>
            <Button
              variant={pending?.action === 'close' ? 'primary' : 'secondary'}
              isLoading={mutation.isPending}
              onClick={() => {
                if (!pending) return;
                setSubmitted(true);
                if (canSubmit(pending)) mutation.mutate(pending);
              }}
            >
              {pending?.label}
            </Button>
          </div>
        }
      >
        {pending ? (
          <div className="space-y-4">
            <p className="text-xs leading-relaxed text-ink-700 dark:text-ink-200">
              {pending.description}
            </p>

            {error ? <ErrorState error={error} compact /> : null}

            {pending.requiresDisposition ? (
              <FormField
                label="Disposition"
                required
                hint="The first thing anyone reading this case later will see."
                error={
                  submitted && !disposition ? 'Choose the outcome of the investigation.' : undefined
                }
              >
                {({ id, describedBy, invalid }) => (
                  <>
                    <Select
                      id={id}
                      aria-describedby={describedBy}
                      invalid={invalid}
                      value={disposition}
                      onChange={(event) => setDisposition(event.target.value)}
                      placeholder="Choose an outcome"
                      options={DISPOSITION_OPTIONS.map((option) => ({
                        value: option.value,
                        label: option.label,
                      }))}
                    />
                    {disposition ? (
                      <p className="mt-1 text-2xs text-ink-600 dark:text-ink-300">
                        {DISPOSITION_OPTIONS.find((option) => option.value === disposition)?.help}
                      </p>
                    ) : null}
                  </>
                )}
              </FormField>
            ) : null}

            <FormField
              label="Reason"
              required={pending.requiresReason}
              hint={
                pending.requiresReason
                  ? 'Recorded in the case history and in the audit trail. Write what you concluded, not what you did.'
                  : 'Optional, and recorded permanently.'
              }
              error={
                submitted && pending.requiresReason && !reason.trim()
                  ? 'A reason is required.'
                  : undefined
              }
            >
              {({ id, describedBy, invalid }) => (
                <TextArea
                  id={id}
                  aria-describedby={describedBy}
                  invalid={invalid}
                  value={reason}
                  onChange={(event) => setReason(event.target.value)}
                  rows={4}
                  maxLength={2000}
                  showCount
                />
              )}
            </FormField>
          </div>
        ) : null}
      </Modal>
    </div>
  );
}
