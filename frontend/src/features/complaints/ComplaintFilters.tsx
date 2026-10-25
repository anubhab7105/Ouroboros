import { AmountInput } from '@/components/common/AmountInput';
import { Button } from '@/components/common/Button';
import { DatePicker } from '@/components/common/DatePicker';
import { FormField } from '@/components/common/FormField';
import { Select } from '@/components/common/Select';
import { TextInput } from '@/components/common/TextInput';
export interface ComplaintFiltersProps {
  values: Record<string, string>;
  onChange: (next: Record<string, string | undefined>) => void;
  onClear: () => void;
  activeCount: number;
  /** Categories observed in the data, from the stats endpoint. */
  categories?: string[];
  sources?: string[];
}

/**
 * Complaint filters.
 *
 * Category and source are free-text on the server, so the options come from
 * what is actually present in the data rather than from a hard-coded list that
 * would go stale the first time a new complaint source was loaded. A text
 * field is offered alongside for a value not yet seen.
 *
 * There is no review-state filter on the complaint list: review state belongs
 * to a correlation, not to a complaint, and the endpoint does not accept one.
 * The dashboard's unreviewed-links figure is the way into that queue.
 */
export function ComplaintFilters({
  values,
  onChange,
  onClear,
  activeCount,
  categories = [],
  sources = [],
}: ComplaintFiltersProps) {
  return (
    <div>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
        <FormField label="Search">
          {({ id }) => (
            <TextInput
              id={id}
              value={values.q ?? ''}
              onChange={(event) => onChange({ q: event.target.value })}
              placeholder="Reference or category"
            />
          )}
        </FormField>

        <FormField label="Category">
          {({ id }) =>
            categories.length > 0 ? (
              <Select
                id={id}
                value={values.category ?? ''}
                onChange={(event) => onChange({ category: event.target.value })}
                placeholder="Any category"
                options={categories.map((value) => ({ value, label: value }))}
              />
            ) : (
              <TextInput
                id={id}
                value={values.category ?? ''}
                onChange={(event) => onChange({ category: event.target.value })}
              />
            )
          }
        </FormField>

        <FormField label="Source">
          {({ id }) =>
            sources.length > 0 ? (
              <Select
                id={id}
                value={values.source ?? ''}
                onChange={(event) => onChange({ source: event.target.value })}
                placeholder="Any source"
                options={sources.map((value) => ({ value, label: value }))}
              />
            ) : (
              <TextInput
                id={id}
                value={values.source ?? ''}
                onChange={(event) => onChange({ source: event.target.value })}
              />
            )
          }
        </FormField>

        <FormField
          label="Account named"
          hint="The account the complainant alleged, not a finding."
        >
          {({ id }) => (
            <TextInput
              id={id}
              mono
              value={values.suspected_account_id ?? ''}
              onChange={(event) => onChange({ suspected_account_id: event.target.value })}
            />
          )}
        </FormField>

        <FormField label="Victim account">
          {({ id }) => (
            <TextInput
              id={id}
              mono
              value={values.victim_account_id ?? ''}
              onChange={(event) => onChange({ victim_account_id: event.target.value })}
            />
          )}
        </FormField>

        <FormField label="Transaction reference">
          {({ id }) => (
            <TextInput
              id={id}
              mono
              value={values.transaction_reference ?? ''}
              onChange={(event) => onChange({ transaction_reference: event.target.value })}
            />
          )}
        </FormField>

        <FormField label="Reported after">
          {({ id }) => (
            <DatePicker
              id={id}
              noFuture
              value={values.date_from?.slice(0, 10) ?? ''}
              onValueChange={(value) => onChange({ date_from: value || undefined })}
            />
          )}
        </FormField>

        <FormField label="Reported before">
          {({ id }) => (
            <DatePicker
              id={id}
              noFuture
              value={values.date_to?.slice(0, 10) ?? ''}
              onValueChange={(value) => onChange({ date_to: value || undefined })}
            />
          )}
        </FormField>

        <FormField label="Minimum loss">
          {({ id }) => (
            <AmountInput
              id={id}
              value={values.min_amount ?? ''}
              onValueChange={(value) => onChange({ min_amount: value || undefined })}
            />
          )}
        </FormField>
      </div>

      {activeCount > 0 ? (
        <div className="mt-2">
          <Button size="sm" variant="ghost" onClick={onClear}>
            Clear {activeCount} filter{activeCount === 1 ? '' : 's'}
          </Button>
        </div>
      ) : null}
    </div>
  );
}
