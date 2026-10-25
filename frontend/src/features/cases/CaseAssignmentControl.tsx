import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';

import { Button } from '@/components/common/Button';
import { ErrorState } from '@/components/common/ErrorState';
import { FormField } from '@/components/common/FormField';
import { Modal } from '@/components/common/Modal';
import { TextArea } from '@/components/common/TextArea';
import { TextInput } from '@/components/common/TextInput';
import { RoleGate } from '@/components/layout/RoleGate';
import { useApiError } from '@/hooks/useApiError';
import { useAuth } from '@/hooks/useAuth';
import { PERMISSIONS } from '@/lib/permissions';
import { queryKeys } from '@/lib/queryKeys';
import { truncateId } from '@/lib/formatters';
import type { InvestigationCase } from '@/types/case';

import { assignCase } from './casesApi';

export interface CaseAssignmentControlProps {
  investigation: InvestigationCase;
}

/**
 * Assign a case.
 *
 * Assignment is a senior-investigator action, so the control is gated —
 * silently, because it sits in a toolbar where an explanation per missing
 * button would be noise. "Assign to me" is offered as a shortcut because
 * taking ownership of a case is the common operation and typing one's own id
 * is a step nobody should have to take.
 *
 * The id field accepts a user id, which is what the API takes. There is no
 * user-picker because the users endpoint is administrator-only, so an
 * investigator cannot list their colleagues; offering a dropdown that 403s
 * would be worse than a field that works.
 */
export function CaseAssignmentControl({ investigation }: CaseAssignmentControlProps) {
  const queryClient = useQueryClient();
  const { user } = useAuth();

  const [open, setOpen] = useState(false);
  const [assigneeId, setAssigneeId] = useState('');
  const [note, setNote] = useState('');
  const [submitted, setSubmitted] = useState(false);
  const [outcome, setOutcome] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: (id: string) => assignCase(investigation.id, { assignee_id: id, note: note.trim() || undefined }),
    onSuccess: (result) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.cases.all });
      void queryClient.invalidateQueries({ queryKey: queryKeys.dashboard.all });

      setOutcome(
        result.changed
          ? `Assigned to ${result.new_assignee_id ? truncateId(result.new_assignee_id, 8) : 'the chosen user'}.`
          : 'Nothing changed — the case was already assigned to that user.',
      );

      setOpen(false);
      setNote('');
      setAssigneeId('');
      setSubmitted(false);
    },
  });

  const error = useApiError(mutation.error);

  return (
    <div>
      <RoleGate permissions={[PERMISSIONS.assignCase]} silent>
        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" variant="secondary" onClick={() => setOpen(true)}>
            {investigation.assignee_id ? 'Reassign' : 'Assign'}
          </Button>

          {user && investigation.assignee_id !== user.id ? (
            <Button
              size="sm"
              variant="ghost"
              isLoading={mutation.isPending}
              onClick={() => {
                setOutcome(null);
                mutation.mutate(user.id);
              }}
            >
              Assign to me
            </Button>
          ) : null}
        </div>
      </RoleGate>

      {outcome ? (
        <p role="status" className="mt-2 text-2xs text-ink-600 dark:text-ink-300">
          {outcome}
        </p>
      ) : null}

      {error && !open ? <ErrorState error={error} compact className="mt-2" /> : null}

      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title="Assign case"
        size="sm"
        footer={
          <div className="flex items-center justify-end gap-2">
            <Button variant="ghost" onClick={() => setOpen(false)} disabled={mutation.isPending}>
              Cancel
            </Button>
            <Button
              variant="primary"
              isLoading={mutation.isPending}
              onClick={() => {
                setSubmitted(true);
                if (assigneeId.trim()) mutation.mutate(assigneeId.trim());
              }}
            >
              Assign
            </Button>
          </div>
        }
      >
        <div className="space-y-4">
          {error ? <ErrorState error={error} compact /> : null}

          <FormField
            label="User id"
            required
            hint="The investigator's user id. Assignment is recorded in the audit trail against your name."
            error={submitted && !assigneeId.trim() ? 'Enter the user id to assign to.' : undefined}
          >
            {({ id, describedBy, invalid }) => (
              <TextInput
                id={id}
                aria-describedby={describedBy}
                invalid={invalid}
                mono
                value={assigneeId}
                onChange={(event) => setAssigneeId(event.target.value)}
                autoFocus
              />
            )}
          </FormField>

          <FormField label="Note" hint="Optional. Added to the case history.">
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
      </Modal>
    </div>
  );
}
