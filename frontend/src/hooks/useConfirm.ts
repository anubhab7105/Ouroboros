import { useCallback, useState } from 'react';

/**
 * State for a confirmation dialog.
 *
 * `window.confirm` is deliberately not used: it cannot explain consequences,
 * cannot be styled, and blocks the event loop. Case closure and evidence
 * removal both need a sentence of explanation before the user commits, which
 * is what `ConfirmDialog` renders from this state.
 */

export interface ConfirmOptions {
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  /** Marks a consequential action: destructive styling and no default focus. */
  destructive?: boolean;
}

interface PendingConfirm extends ConfirmOptions {
  resolve: (confirmed: boolean) => void;
}

export function useConfirm() {
  const [pending, setPending] = useState<PendingConfirm | null>(null);

  const confirm = useCallback(
    (options: ConfirmOptions) =>
      new Promise<boolean>((resolve) => {
        setPending({ ...options, resolve });
      }),
    [],
  );

  const handleConfirm = useCallback(() => {
    pending?.resolve(true);
    setPending(null);
  }, [pending]);

  const handleCancel = useCallback(() => {
    pending?.resolve(false);
    setPending(null);
  }, [pending]);

  return {
    confirm,
    pending,
    isOpen: pending !== null,
    onConfirm: handleConfirm,
    onCancel: handleCancel,
  };
}
