import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';

import { Button } from '@/components/common/Button';
import { ErrorState } from '@/components/common/ErrorState';
import { FormField } from '@/components/common/FormField';
import { Modal } from '@/components/common/Modal';
import { Select } from '@/components/common/Select';
import { TextInput } from '@/components/common/TextInput';
import { useApiError } from '@/hooks/useApiError';
import { queryKeys } from '@/lib/queryKeys';
import { EVIDENCE_TYPE_LABELS, EVIDENCE_TYPE_MEANING } from '@/types/evidence';

import { addCaseEvidence } from './casesApi';

export interface AddEvidenceModalProps {
  open: boolean;
  onClose: () => void;
  caseId: string;
  /** Pre-filled when attaching from a record the user is already looking at. */
  initialType?: string;
  initialId?: string;
}

const TYPE_OPTIONS = Object.entries(EVIDENCE_TYPE_LABELS).map(([value, label]) => ({
  value,
  label,
}));

/**
 * Attach a record to a case as evidence.
 *
 * The form states what the chosen kind of evidence can establish, as the kind
 * is selected. That is not decoration: attaching a network path and attaching
 * a transaction support different claims, and an investigator writing a
 * conclusion needs to know which they have. The same sentences appear on the
 * evidence table and in the generated report, so the three cannot drift.
 *
 * Nothing is validated against the record existing — the server does that, and
 * a wrong id comes back as a clear 404 rather than being silently accepted.
 */
export function AddEvidenceModal({
  open,
  onClose,
  caseId,
  initialType,
  initialId,
}: AddEvidenceModalProps) {
  const queryClient = useQueryClient();

  const [evidenceType, setEvidenceType] = useState(initialType ?? 'TRANSACTION');
  const [evidenceId, setEvidenceId] = useState(initialId ?? '');
  const [submitted, setSubmitted] = useState(false);

  const mutation = useMutation({
    mutationFn: () =>
      addCaseEvidence(caseId, {
        evidence_type: evidenceType,
        evidence_id: evidenceId.trim(),
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.cases.all });
      setEvidenceId('');
      setSubmitted(false);
      onClose();
    },
  });

  const error = useApiError(mutation.error);

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Attach evidence"
      footer={
        <div className="flex items-center justify-end gap-2">
          <Button variant="ghost" onClick={onClose} disabled={mutation.isPending}>
            Cancel
          </Button>
          <Button
            variant="primary"
            isLoading={mutation.isPending}
            onClick={() => {
              setSubmitted(true);
              if (evidenceId.trim()) mutation.mutate();
            }}
          >
            Attach
          </Button>
        </div>
      }
    >
      <div className="space-y-4">
        {error ? <ErrorState error={error} compact /> : null}

        <FormField label="Kind">
          {({ id }) => (
            <>
              <Select
                id={id}
                value={evidenceType}
                onChange={(event) => setEvidenceType(event.target.value)}
                options={TYPE_OPTIONS}
              />
              <p className="mt-1 text-2xs leading-relaxed text-ink-600 dark:text-ink-300">
                {EVIDENCE_TYPE_MEANING[evidenceType] ?? 'Attached evidence.'}
              </p>
            </>
          )}
        </FormField>

        <FormField
          label="Identifier"
          required
          hint="The record's id, or a transaction reference. The server checks that it exists."
          error={submitted && !evidenceId.trim() ? 'Enter the identifier to attach.' : undefined}
        >
          {({ id, describedBy, invalid }) => (
            <TextInput
              id={id}
              aria-describedby={describedBy}
              invalid={invalid}
              mono
              value={evidenceId}
              onChange={(event) => setEvidenceId(event.target.value)}
              autoFocus
            />
          )}
        </FormField>

        <p className="text-2xs leading-relaxed text-ink-600 dark:text-ink-300">
          A snapshot of the record is stored alongside the reference, so a later change to the
          underlying data stays visible rather than quietly rewriting what the case relied on.
        </p>
      </div>
    </Modal>
  );
}
