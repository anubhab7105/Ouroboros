import { Button } from '@/components/common/Button';
import { DatePicker } from '@/components/common/DatePicker';
import { FormField } from '@/components/common/FormField';
import { Select } from '@/components/common/Select';
import { TextInput } from '@/components/common/TextInput';
import { CASE_STATUS_TOKENS, DISPOSITION_TOKENS, SEVERITY_TOKENS } from '@/lib/constants';
import type { CaseFilters as Filters } from '@/types/case';

export interface CaseFiltersProps {
  values: Record<string, string>;
  onChange: (next: Partial<Filters & Record<string, string>>) => void;
  onClear: () => void;
  activeCount: number;
}

const STATUS_OPTIONS = Object.entries(CASE_STATUS_TOKENS).map(([value, token]) => ({
  value,
  label: token.label,
}));

const PRIORITY_OPTIONS = Object.entries(SEVERITY_TOKENS).map(([value, token]) => ({
  value,
  label: token.label,
}));

const DISPOSITION_OPTIONS = Object.entries(DISPOSITION_TOKENS).map(([value, token]) => ({
  value,
  label: token.label,
}));

/**
 * Case filters.
 *
 * Status is a single value because the API takes one. There is no "open only"
 * shortcut, for the same reason: the endpoint has no such parameter, and a
 * control that quietly filtered to four statuses client-side would make the
 * pager's totals wrong.
 */
export function CaseFilters({ values, onChange, onClear, activeCount }: CaseFiltersProps) {
  return (
    <div>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
        <FormField label="Search">
          {({ id }) => (
            <TextInput
              id={id}
              value={values.q ?? ''}
              onChange={(event) => onChange({ q: event.target.value })}
              placeholder="Title or description"
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

        <FormField label="Priority">
          {({ id }) => (
            <Select
              id={id}
              value={values.priority ?? ''}
              onChange={(event) => onChange({ priority: event.target.value })}
              placeholder="Any priority"
              options={PRIORITY_OPTIONS}
            />
          )}
        </FormField>

        <FormField label="Disposition" hint="Closed cases only.">
          {({ id }) => (
            <Select
              id={id}
              value={values.disposition ?? ''}
              onChange={(event) => onChange({ disposition: event.target.value })}
              placeholder="Any outcome"
              options={DISPOSITION_OPTIONS}
            />
          )}
        </FormField>

        <FormField label="Assignee">
          {({ id }) => (
            <TextInput
              id={id}
              value={values.assignee_id ?? ''}
              onChange={(event) => onChange({ assignee_id: event.target.value })}
              placeholder="User id"
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
            />
          )}
        </FormField>

        <FormField label="Opened after">
          {({ id }) => (
            <DatePicker
              id={id}
              noFuture
              value={values.date_from?.slice(0, 10) ?? ''}
              onValueChange={(value) => onChange({ date_from: value || undefined })}
            />
          )}
        </FormField>

        <FormField label="Closed after">
          {({ id }) => (
            <DatePicker
              id={id}
              noFuture
              value={values.closed_from?.slice(0, 10) ?? ''}
              onValueChange={(value) => onChange({ closed_from: value || undefined })}
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
