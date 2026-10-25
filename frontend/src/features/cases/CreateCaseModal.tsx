import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';

import { Button } from '@/components/common/Button';
import { ErrorState } from '@/components/common/ErrorState';
import { FormField } from '@/components/common/FormField';
import { Modal } from '@/components/common/Modal';
import { Select } from '@/components/common/Select';
import { TextArea } from '@/components/common/TextArea';
import { TextInput } from '@/components/common/TextInput';
import { useApiError } from '@/hooks/useApiError';
import { SEVERITY_TOKENS } from '@/lib/constants';
import { queryKeys } from '@/lib/queryKeys';
import { paths } from '@/routes/paths';

import { createCase } from './casesApi';

export interface CreateCaseModalProps {
  open: boolean;
  onClose: () => void;
  /** Pre-fill when opening from an account or an alert. */
  accountId?: string;
  alertId?: string;
}

const PRIORITY_OPTIONS = Object.entries(SEVERITY_TOKENS).map(([value, token]) => ({
  value,
  label: token.label,
}));

/**
 * Open a case directly.
 *
 * Most cases are created from an alert during triage, which carries the
 * alert's evidence across. This path exists for the other kind — an
 * investigator acting on something they noticed — and it says so, because a
 * case with no originating alert and no evidence is a case somebody will have
 * to justify later.
 *
 * Every field is optional to the API. The form still asks for a title and a
 * description, since a case titled by the server's default is one nobody can
 * find again.
 */
export function CreateCaseModal({ open, onClose, accountId, alertId }: CreateCaseModalProps) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [priority, setPriority] = useState('MEDIUM');
  const [account, setAccount] = useState(accountId ?? '');
  const [submitted, setSubmitted] = useState(false);

  const mutation = useMutation({
    mutationFn: () =>
      createCase({
        title: title.trim() || undefined,
        description: description.trim() || undefined,
        priority,
        account_id: account.trim() || undefined,
        alert_id: alertId,
      }),
    onSuccess: (created) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.cases.all });
      onClose();
      navigate(paths.case(created.id));
    },
  });

  const error = useApiError(mutation.error);

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();
    setSubmitted(true);

    if (!title.trim()) return;
    mutation.mutate();
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Open a case"
      footer={
        <div className="flex items-center justify-end gap-2">
          <Button variant="ghost" onClick={onClose} disabled={mutation.isPending}>
            Cancel
          </Button>
          <Button
            variant="primary"
            onClick={handleSubmit}
            isLoading={mutation.isPending}
          >
            Open case
          </Button>
        </div>
      }
    >
      <form onSubmit={handleSubmit} className="space-y-4" noValidate>
        {error ? <ErrorState error={error} compact /> : null}

        <FormField
          label="Title"
          required
          hint="What somebody searching for this case in six months would type."
          error={submitted && !title.trim() ? 'Give the case a title.' : undefined}
        >
          {({ id, describedBy, invalid }) => (
            <TextInput
              id={id}
              aria-describedby={describedBy}
              invalid={invalid}
              value={title}
              onChange={(event) => setTitle(event.target.value)}
              maxLength={200}
              autoFocus
            />
          )}
        </FormField>

        <FormField
          label="Why this case is being opened"
          hint="Without an originating alert, this is the only record of what prompted the investigation."
        >
          {({ id }) => (
            <TextArea
              id={id}
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              maxLength={2000}
              showCount
              rows={4}
            />
          )}
        </FormField>

        <div className="grid gap-3 sm:grid-cols-2">
          <FormField label="Priority">
            {({ id }) => (
              <Select
                id={id}
                value={priority}
                onChange={(event) => setPriority(event.target.value)}
                options={PRIORITY_OPTIONS}
              />
            )}
          </FormField>

          <FormField label="Account" hint="Optional, but a case about nothing is hard to work.">
            {({ id }) => (
              <TextInput
                id={id}
                mono
                value={account}
                onChange={(event) => setAccount(event.target.value)}
              />
            )}
          </FormField>
        </div>

        {alertId ? (
          <p className="text-2xs text-ink-600 dark:text-ink-300">
            This case will be linked to alert{' '}
            <span className="font-mono">{alertId}</span>.
          </p>
        ) : (
          <p className="text-2xs text-ink-600 dark:text-ink-300">
            No originating alert. Nothing is attached as evidence yet — add it from the case before
            drawing a conclusion.
          </p>
        )}
      </form>
    </Modal>
  );
}
