import { Button } from '@/components/common/Button';
import { AmountInput } from '@/components/common/AmountInput';
import { DatePicker } from '@/components/common/DatePicker';
import { FormField } from '@/components/common/FormField';
import { Select } from '@/components/common/Select';
import { TextInput } from '@/components/common/TextInput';
import { CHANNEL_LABELS, TRANSACTION_STATUS_TOKENS } from '@/lib/constants';
export interface TransactionFiltersProps {
  values: Record<string, string>;
  /**
   * Values come from, and go back into, the URL, so everything here is a
   * string. The page parses the numeric ones before they reach the API.
   */
  onChange: (next: Record<string, string | undefined>) => void;
  onClear: () => void;
  activeCount: number;
}

const STATUS_OPTIONS = Object.entries(TRANSACTION_STATUS_TOKENS).map(([value, token]) => ({
  value,
  label: token.label,
}));

const CHANNEL_OPTIONS = Object.entries(CHANNEL_LABELS).map(([value, label]) => ({
  value,
  label,
}));

/**
 * Ledger filters.
 *
 * "Completed only" is offered as a status choice rather than a separate
 * checkbox, because the API has one status parameter and a checkbox that
 * silently overrode a chosen status would be a trap.
 *
 * The amount fields accept decimals and are sent as numbers; an empty field is
 * dropped from the query rather than sent as an empty string, which the API
 * would reject outright.
 */
export function TransactionFilters({
  values,
  onChange,
  onClear,
  activeCount,
}: TransactionFiltersProps) {
  return (
    <div>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-6">
        <FormField label="Search">
          {({ id }) => (
            <TextInput
              id={id}
              value={values.q ?? ''}
              onChange={(event) => onChange({ q: event.target.value })}
              placeholder="Reference or account"
            />
          )}
        </FormField>

        <FormField label="Account">
          {({ id }) => (
            <TextInput
              id={id}
              mono
              value={values.account_id ?? ''}
              onChange={(event) => onChange({ account_id: event.target.value })}
              placeholder="Either side"
            />
          )}
        </FormField>

        <FormField label="Status">
          {({ id }) => (
            <Select
              id={id}
              value={values.status ?? ''}
              onChange={(event) => onChange({ status: event.target.value })}
              placeholder="Any status"
              options={STATUS_OPTIONS}
            />
          )}
        </FormField>

        <FormField label="Channel">
          {({ id }) => (
            <Select
              id={id}
              value={values.channel ?? ''}
              onChange={(event) => onChange({ channel: event.target.value })}
              placeholder="Any channel"
              options={CHANNEL_OPTIONS}
            />
          )}
        </FormField>

        <FormField label="From date">
          {({ id }) => (
            <DatePicker
              id={id}
              noFuture
              value={values.date_from?.slice(0, 10) ?? ''}
              onValueChange={(value) => onChange({ date_from: value || undefined })}
            />
          )}
        </FormField>

        <FormField label="To date">
          {({ id }) => (
            <DatePicker
              id={id}
              noFuture
              value={values.date_to?.slice(0, 10) ?? ''}
              onValueChange={(value) => onChange({ date_to: value || undefined })}
            />
          )}
        </FormField>

        <FormField label="Minimum amount">
          {({ id }) => (
            <AmountInput
              id={id}
              value={values.min_amount ?? ''}
              onValueChange={(value) => onChange({ min_amount: value || undefined })}
            />
          )}
        </FormField>

        <FormField label="Maximum amount">
          {({ id }) => (
            <AmountInput
              id={id}
              value={values.max_amount ?? ''}
              onValueChange={(value) => onChange({ max_amount: value || undefined })}
            />
          )}
        </FormField>

        <FormField label="Reference">
          {({ id }) => (
            <TextInput
              id={id}
              mono
              value={values.reference ?? ''}
              onChange={(event) => onChange({ reference: event.target.value })}
              placeholder="Exact match"
            />
          )}
        </FormField>

        <FormField label="Currency">
          {({ id }) => (
            <TextInput
              id={id}
              maxLength={3}
              value={values.currency ?? ''}
              onChange={(event) => onChange({ currency: event.target.value.toUpperCase() })}
              placeholder="INR"
            />
          )}
        </FormField>
      </div>

      {activeCount > 0 ? (
        <div className="mt-2 flex items-center gap-3">
          <Button size="sm" variant="ghost" onClick={onClear}>
            Clear {activeCount} filter{activeCount === 1 ? '' : 's'}
          </Button>
          <p className="text-2xs text-ink-500 dark:text-ink-400">
            Filters are in the URL, so this view can be shared as a link.
          </p>
        </div>
      ) : null}
    </div>
  );
}
