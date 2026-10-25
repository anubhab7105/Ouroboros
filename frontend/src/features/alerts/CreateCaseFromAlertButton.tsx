import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { Button } from '@/components/common/Button';
import { ErrorState } from '@/components/common/ErrorState';
import { FormField } from '@/components/common/FormField';
import { Modal } from '@/components/common/Modal';
import { Select } from '@/components/common/Select';
import { TextArea } from '@/components/common/TextArea';
import { TextInput } from '@/components/common/TextInput';
import { RoleGate } from '@/components/layout/RoleGate';
import { useApiError } from '@/hooks/useApiError';
import { formatCount } from '@/lib/amounts';
import { SEVERITY_TOKENS } from '@/lib/constants';
import { PERMISSIONS } from '@/lib/permissions';
import { queryKeys } from '@/lib/queryKeys';
import { paths } from '@/routes/paths';
import type { Alert } from '@/types/alert';

import { createCaseFromAlert } from './alertsApi';

export interface CreateCaseFromAlertButtonProps {
  alert: Alert;
  size?: 'sm' | 'md';
}

const PRIORITY_OPTIONS = Object.entries(SEVERITY_TOKENS).map(([value, token]) => ({
  value,
  label: token.label,
}));

/**
 * Open an investigation from this alert.
 *
 * This is the main path into a case, and it carries the alert's evidence
 * across. The result reports how many items were copied and whether that was
 * truncated — which matters, because a case that received 50 of 300 evidence
 * items looks complete and is not. The UI states the number before navigating
 * rather than leaving the investigator to notice.
 *
 * The title and priority default to the alert's own. They are editable because
 * an alert title describes a pattern and a case title should describe an
 * investigation, which is not always the same sentence.
 */
export function CreateCaseFromAlertButton({
  alert,
  size = 'sm',
}: CreateCaseFromAlertButtonProps) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState(alert.title);
  const [description, setDescription] = useState(alert.summary ?? '');
  const [priority, setPriority] = useState(alert.priority);

  const mutation = useMutation({
    mutationFn: () =>
      createCaseFromAlert(alert.id, {
        title: title.trim() || undefined,
        description: description.trim() || undefined,
        priority,
      }),
    onSuccess: (result) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.alerts.all });
      void queryClient.invalidateQueries({ queryKey: queryKeys.cases.all });
      void queryClient.invalidateQueries({ queryKey: queryKeys.dashboard.all });

      // Navigate straight to the case: the investigator's next action is
      // always to work it, and the copied-evidence note is shown there.
      navigate(paths.case(result.case.id), {
        state: {
          copiedEvidence: result.copied_evidence_count,
          totalEvidence: result.total_evidence_count,
          evidenceTruncated: result.evidence_truncated,
        },
      });
    },
  });

  const error = useApiError(mutation.error);

  // An alert that already has a case gets a link rather than a second one.
  if (alert.active_case_id) {
    return (
      <Button
        size={size}
        variant="secondary"
        onClick={() => navigate(paths.case(alert.active_case_id!))}
      >
        Open case
      </Button>
    );
  }

  return (
    <>
      <RoleGate permissions={[PERMISSIONS.createCase]} silent>
        <Button size={size} variant="primary" onClick={() => setOpen(true)}>
          Open a case
        </Button>
      </RoleGate>

      <Modal
        open={open}
        onClose={() => setOpen(false)}
        title="Open a case from this alert"
        footer={
          <div className="flex items-center justify-end gap-2">
            <Button variant="ghost" onClick={() => setOpen(false)} disabled={mutation.isPending}>
              Cancel
            </Button>
            <Button
              variant="primary"
              isLoading={mutation.isPending}
              onClick={() => mutation.mutate()}
            >
              Open case
            </Button>
          </div>
        }
      >
        <div className="space-y-4">
          {error ? <ErrorState error={error} compact /> : null}

          <p className="text-2xs leading-relaxed text-ink-600 dark:text-ink-300">
            The alert's evidence is copied onto the new case
            {alert.evidence_count ? ` (${formatCount(alert.evidence_count)} items)` : ''}. Copying
            is capped server-side; if it is truncated, the case will say so.
          </p>

          <FormField
            label="Case title"
            hint="The alert title describes a pattern. A case title should describe the investigation."
          >
            {({ id }) => (
              <TextInput
                id={id}
                value={title}
                onChange={(event) => setTitle(event.target.value)}
                maxLength={200}
                autoFocus
              />
            )}
          </FormField>

          <FormField label="Description">
            {({ id }) => (
              <TextArea
                id={id}
                value={description}
                onChange={(event) => setDescription(event.target.value)}
                rows={4}
                maxLength={2000}
                showCount
              />
            )}
          </FormField>

          <FormField label="Priority" hint="Defaults to the alert's priority.">
            {({ id }) => (
              <Select
                id={id}
                value={priority}
                onChange={(event) => setPriority(event.target.value)}
                options={PRIORITY_OPTIONS}
              />
            )}
          </FormField>
        </div>
      </Modal>
    </>
  );
}
