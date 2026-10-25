import type { ConfirmOptions } from '@/hooks/useConfirm';

import { Button } from './Button';
import { Modal } from './Modal';

export interface ConfirmDialogProps {
  open: boolean;
  options: ConfirmOptions | null;
  onConfirm: () => void;
  onCancel: () => void;
  isBusy?: boolean;
}

/**
 * A confirmation dialog.
 *
 * Used where an action is consequential and not trivially undone: closing a
 * case (which records a disposition in the audit trail), removing evidence
 * from a case, running an analysis over every account.
 *
 * The confirm button is not auto-focused for a destructive action, so a user
 * who hits Enter out of habit does not commit it. For an ordinary
 * confirmation that caution is unnecessary friction, so `destructive` controls
 * which applies.
 */
export function ConfirmDialog({
  open,
  options,
  onConfirm,
  onCancel,
  isBusy = false,
}: ConfirmDialogProps) {
  if (!options) return null;

  return (
    <Modal
      open={open}
      onClose={isBusy ? () => undefined : onCancel}
      title={options.title}
      size="sm"
      dismissable={!isBusy}
      footer={
        <>
          <Button variant="ghost" onClick={onCancel} disabled={isBusy}>
            {options.cancelLabel ?? 'Cancel'}
          </Button>
          <Button
            variant={options.destructive ? 'danger' : 'primary'}
            onClick={onConfirm}
            isLoading={isBusy}
            autoFocus={!options.destructive}
          >
            {options.confirmLabel ?? 'Confirm'}
          </Button>
        </>
      }
    >
      <p className="text-sm leading-relaxed text-ink-700 dark:text-ink-200">{options.message}</p>
    </Modal>
  );
}
