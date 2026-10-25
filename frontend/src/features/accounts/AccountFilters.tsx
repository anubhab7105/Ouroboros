import { Button } from '@/components/common/Button';
import { DatePicker } from '@/components/common/DatePicker';
import { FormField } from '@/components/common/FormField';
import { Select } from '@/components/common/Select';
import { TextInput } from '@/components/common/TextInput';
import { ACCOUNT_STATUS_HINTS } from '@/lib/constants';
import { humaniseEnum } from '@/lib/formatters';
import type { AccountFilters as Filters } from '@/types/account';

export interface AccountFiltersProps {
  values: Record<string, string>;
  onChange: (next: Partial<Filters & Record<string, string>>) => void;
  onClear: () => void;
  activeCount: number;
}

const TYPE_OPTIONS = ['INDIVIDUAL', 'BUSINESS', 'MERCHANT', 'OTHER'].map((value) => ({
  value,
  label: humaniseEnum(value),
}));

const STATUS_OPTIONS = Object.keys(ACCOUNT_STATUS_HINTS).map((value) => ({
  value,
  label: humaniseEnum(value),
}));

/**
 * Account filters.
 *
 * There is deliberately no risk-band filter here, even though one would be
 * obvious: the account list endpoint does not accept one. Risk band lives on
 * the latest assessment, which is a joined summary rather than a filterable
 * column, so offering the control would produce a filter that silently did
 * nothing. The dashboard's risk distribution is the way into a band.
 */
export function AccountFilters({ values, onChange, onClear, activeCount }: AccountFiltersProps) {
  return (
    <div>
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <FormField label="Search">
          {({ id }) => (
            <TextInput
              id={id}
              value={values.q ?? ''}
              onChange={(event) => onChange({ q: event.target.value })}
              placeholder="Account id"
            />
          )}
        </FormField>

        <FormField label="Type">
          {({ id }) => (
            <Select
              id={id}
              value={values.account_type ?? ''}
              onChange={(event) => onChange({ account_type: event.target.value })}
              placeholder="Any type"
              options={TYPE_OPTIONS}
            />
          )}
        </FormField>

        <FormField label="Source status" hint="As the source system reports it.">
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

        <FormField label="Opened after">
          {({ id }) => (
            <DatePicker
              id={id}
              noFuture
              value={values.created_from?.slice(0, 10) ?? ''}
              onValueChange={(value) => onChange({ created_from: value || undefined })}
            />
          )}
        </FormField>

        <FormField label="Opened before">
          {({ id }) => (
            <DatePicker
              id={id}
              noFuture
              value={values.created_to?.slice(0, 10) ?? ''}
              onValueChange={(value) => onChange({ created_to: value || undefined })}
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
