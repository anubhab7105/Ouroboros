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
import type { Alert } from '@/types/alert';

import { acknowledgeAlert, assignAlert, closeAlert, escalateAlert, reopenAlert } from './alertsApi';

export interface AlertTriageActionsProps {
  alert: Alert;
  /** Rendered inline in a table row rather than in a detail panel. */
  compact?: boolean;
}

type Pending = 'close' | 'assign' | null;

/**
 * The triage actions for one alert.
 *
 * Which actions are offered depends on the alert's state, and the gating is
 * per action rather than per role: acknowledging is an analyst action,
 * assigning and escalating are senior ones. Each control is hidden silently
 * when the capability is absent, because a triage toolbar explaining four
 * missing buttons would be unusable.
 *
 * Closing requires a reason, and the field says the reason is permanent. An
 * alert closed as a false positive with no explanation is a finding nobody can
 * review and a signal the rules never learn from.
 *
 * Every result reports `changed`, so clicking twice says "nothing changed"
 * instead of claiming a second success.
 */
export function AlertTriageActions({ alert, compact = false }: AlertTriageActionsProps) {
  const queryClient = useQueryClient();
  const { user } = useAuth();

  const [pending, setPending] = useState<Pending>(null);
  const [reason, setReason] = useState('');
  const [assigneeId, setAssigneeId] = useState('');
  const [note, setNote] = useState('');
  const [submitted, setSubmitted] = useState(false);
  const [outcome, setOutcome] = useState<string | null>(null);

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: queryKeys.alerts.all });
    void queryClient.invalidateQueries({ queryKey: queryKeys.dashboard.all });
  };

  const report = (changed: boolean, from: string, to: string) =>
    setOutcome(
      changed
        ? `Alert moved from ${from} to ${to}.`
        : `Nothing changed — the alert was already ${to}.`,
    );

  const acknowledge = useMutation({
    mutationFn: () => acknowledgeAlert(alert.id),
    onSuccess: (result) => {
      invalidate();
      report(result.changed, result.previous_state, result.new_state);
    },
  });

  const escalate = useMutation({
    mutationFn: () => escalateAlert(alert.id),
    onSuccess: (result) => {
      invalidate();
      report(result.changed, result.previous_state, result.new_state);
    },
  });

  const reopen = useMutation({
    mutationFn: () => reopenAlert(alert.id),
    onSuccess: (result) => {
      invalidate();
      report(result.changed, result.previous_state, result.new_state);
    },
  });

  const close = useMutation({
    mutationFn: () => closeAlert(alert.id, { reason: reason.trim() }),
    onSuccess: (result) => {
      invalidate();
      report(result.changed, result.previous_state, result.new_state);
      setPending(null);
      setReason('');
      setSubmitted(false);
    },
  });

  const assign = useMutation({
    mutationFn: (id: string) =>
      assignAlert(alert.id, { assignee_id: id, note: note.trim() || undefined }),
    onSuccess: (result) => {
      invalidate();
      setOutcome(
        result.changed
          ? 'Alert assigned.'
          : 'Nothing changed — the alert was already assigned to that user.',
      );
      setPending(null);
      setAssigneeId('');
      setNote('');
      setSubmitted(false);
    },
  });

  const error = useApiError(
    acknowledge.error ?? escalate.error ?? reopen.error ?? close.error ?? assign.error,
  );

  const isClosed = alert.state === 'CLOSED';
  const size = compact ? 'sm' : 'md';

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2">
        {!isClosed && alert.state === 'NEW' ? (
          <RoleGate permissions={[PERMISSIONS.triageAlerts]} silent>
            <Button
              size={size}
              variant="primary"
              isLoading={acknowledge.isPending}
              onClick={() => {
                setOutcome(null);
                acknowledge.mutate();
              }}
              title="Take this alert. It leaves the awaiting-triage queue and is attributed to you."
            >
              Acknowledge
            </Button>
          </RoleGate>
        ) : null}

        {!isClosed ? (
          <RoleGate permissions={[PERMISSIONS.assignAlerts]} silent>
            <Button
              size={size}
              variant="secondary"
              onClick={() => {
                setOutcome(null);
                setPending('assign');
              }}
            >
              {alert.assigned_to ? 'Reassign' : 'Assign'}
            </Button>
          </RoleGate>
        ) : null}

        {!isClosed && user && alert.assigned_to !== user.id ? (
          <RoleGate permissions={[PERMISSIONS.assignAlerts]} silent>
            <Button
              size={size}
              variant="ghost"
              isLoading={assign.isPending}
              onClick={() => {
                setOutcome(null);
                assign.mutate(user.id);
              }}
            >
              Assign to me
            </Button>
          </RoleGate>
        ) : null}

        {!isClosed && alert.state !== 'ESCALATED' ? (
          <RoleGate permissions={[PERMISSIONS.escalateAlerts]} silent>
            <Button
              size={size}
              variant="secondary"
              isLoading={escalate.isPending}
              onClick={() => {
                setOutcome(null);
                escalate.mutate();
              }}
              title="Hand this to a senior investigator."
            >
              Escalate
            </Button>
          </RoleGate>
        ) : null}

        {!isClosed ? (
          <RoleGate permissions={[PERMISSIONS.triageAlerts]} silent>
            <Button
              size={size}
              variant="secondary"
              onClick={() => {
                setOutcome(null);
                setPending('close');
              }}
            >
              Close
            </Button>
          </RoleGate>
        ) : (
          <RoleGate permissions={[PERMISSIONS.triageAlerts]} silent>
            <Button
              size={size}
              variant="secondary"
              isLoading={reopen.isPending}
              onClick={() => {
                setOutcome(null);
                reopen.mutate();
              }}
              title="Return this alert to the queue. The closure stays in the history."
            >
              Reopen
            </Button>
          </RoleGate>
        )}
      </div>

      {outcome ? (
        <p role="status" className="mt-2 text-2xs text-ink-600 dark:text-ink-300">
          {outcome}
        </p>
      ) : null}

      {error && !pending ? <ErrorState error={error} compact className="mt-2" /> : null}

      <Modal
        open={pending === 'close'}
        onClose={() => setPending(null)}
        title="Close this alert"
        size="sm"
        footer={
          <div className="flex items-center justify-end gap-2">
            <Button variant="ghost" onClick={() => setPending(null)} disabled={close.isPending}>
              Cancel
            </Button>
            <Button
              variant="primary"
              isLoading={close.isPending}
              onClick={() => {
                setSubmitted(true);
                if (reason.trim()) close.mutate();
              }}
            >
              Close alert
            </Button>
          </div>
        }
      >
        <div className="space-y-3">
          {error ? <ErrorState error={error} compact /> : null}

          <FormField
            label="Reason"
            required
            hint="Permanent, attributed to you, and the only record of why this was not pursued. If it was a false positive, say what the innocent explanation was."
            error={submitted && !reason.trim() ? 'A reason is required to close an alert.' : undefined}
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
                autoFocus
              />
            )}
          </FormField>
        </div>
      </Modal>

      <Modal
        open={pending === 'assign'}
        onClose={() => setPending(null)}
        title="Assign this alert"
        size="sm"
        footer={
          <div className="flex items-center justify-end gap-2">
            <Button variant="ghost" onClick={() => setPending(null)} disabled={assign.isPending}>
              Cancel
            </Button>
            <Button
              variant="primary"
              isLoading={assign.isPending}
              onClick={() => {
                setSubmitted(true);
                if (assigneeId.trim()) assign.mutate(assigneeId.trim());
              }}
            >
              Assign
            </Button>
          </div>
        }
      >
        <div className="space-y-3">
          {error ? <ErrorState error={error} compact /> : null}

          <FormField
            label="User id"
            required
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

          <FormField label="Note" hint="Optional. Recorded in the alert's history.">
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
