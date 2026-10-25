import { Button } from '@/components/common/Button';
import { DatePicker } from '@/components/common/DatePicker';
import { FormField } from '@/components/common/FormField';
import { Select } from '@/components/common/Select';
import { TextInput } from '@/components/common/TextInput';
import { ALERT_STATE_TOKENS, SCORING_MODE_TOKENS, SEVERITY_TOKENS } from '@/lib/constants';
import { OPEN_ALERT_STATES } from '@/types/alert';

export interface AlertFiltersProps {
  values: Record<string, string>;
  onChange: (next: Record<string, string | undefined>) => void;
  onClear: () => void;
  activeCount: number;
}

const STATE_OPTIONS = Object.entries(ALERT_STATE_TOKENS).map(([value, token]) => ({
  value,
  label: token.label,
}));

const PRIORITY_OPTIONS = Object.entries(SEVERITY_TOKENS).map(([value, token]) => ({
  value,
  label: token.label,
}));

const MODE_OPTIONS = Object.entries(SCORING_MODE_TOKENS).map(([value, token]) => ({
  value,
  label: token.label,
}));

/**
 * Triage queue filters.
 *
 * Two shortcuts earn their place, because they are how a queue is actually
 * worked and both are awkward to express through the raw parameters:
 *
 * - **Open only** sets the four non-closed states at once. The API has no
 *   `open_only` flag, but it does accept repeated `states`, so the shortcut
 *   expands to exactly that rather than filtering in the browser.
 *
 * - **Unassigned** cannot be expressed at all: the API filters by
 *   `assigned_to` equal to a value, with no "is null" form. The control is
 *   therefore offered as *state NEW*, which is the closest honest equivalent,
 *   and labelled as such rather than as a true owner filter.
 */
export function AlertFilters({ values, onChange, onClear, activeCount }: AlertFiltersProps) {
  const openOnly = values.states === OPEN_ALERT_STATES.join(',');

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Button
          size="sm"
          variant={openOnly ? 'primary' : 'secondary'}
          onClick={() =>
            onChange({ states: openOnly ? undefined : OPEN_ALERT_STATES.join(',') })
          }
          title="The four states that still represent work: new, acknowledged, under review and escalated."
        >
          Open only
        </Button>

        <Button
          size="sm"
          variant={values.states === 'NEW' ? 'primary' : 'secondary'}
          onClick={() => onChange({ states: values.states === 'NEW' ? undefined : 'NEW' })}
          title="Alerts in the NEW state — nobody has acknowledged them. The API cannot filter for 'no owner', so this is the closest equivalent."
        >
          Awaiting triage
        </Button>

        <Button
          size="sm"
          variant={values.priorities === 'CRITICAL,HIGH' ? 'primary' : 'secondary'}
          onClick={() =>
            onChange({
              priorities: values.priorities === 'CRITICAL,HIGH' ? undefined : 'CRITICAL,HIGH',
            })
          }
        >
          Critical and high
        </Button>
      </div>

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
        <FormField label="Search">
          {({ id }) => (
            <TextInput
              id={id}
              value={values.q ?? ''}
              onChange={(event) => onChange({ q: event.target.value })}
              placeholder="Title, summary or rule code"
            />
          )}
        </FormField>

        <FormField label="State">
          {({ id }) => (
            <Select
              id={id}
              value={values.states?.includes(',') ? '' : (values.states ?? '')}
              onChange={(event) => onChange({ states: event.target.value })}
              placeholder={values.states?.includes(',') ? 'Several selected' : 'Any state'}
              options={STATE_OPTIONS}
            />
          )}
        </FormField>

        <FormField label="Priority">
          {({ id }) => (
            <Select
              id={id}
              value={values.priorities?.includes(',') ? '' : (values.priorities ?? '')}
              onChange={(event) => onChange({ priorities: event.target.value })}
              placeholder={values.priorities?.includes(',') ? 'Several selected' : 'Any priority'}
              options={PRIORITY_OPTIONS}
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

        <FormField label="Owner" hint="A user id. There is no filter for 'no owner'.">
          {({ id }) => (
            <TextInput
              id={id}
              value={values.assigned_to ?? ''}
              onChange={(event) => onChange({ assigned_to: event.target.value })}
            />
          )}
        </FormField>

        <FormField label="Scored by">
          {({ id }) => (
            <Select
              id={id}
              value={values.scoring_mode ?? ''}
              onChange={(event) => onChange({ scoring_mode: event.target.value })}
              placeholder="Any mode"
              options={MODE_OPTIONS}
            />
          )}
        </FormField>

        <FormField label="Minimum score">
          {({ id }) => (
            <TextInput
              id={id}
              type="number"
              min={0}
              max={100}
              value={values.min_score ?? ''}
              onChange={(event) => onChange({ min_score: event.target.value })}
            />
          )}
        </FormField>

        <FormField label="First seen after" hint="Queue age is measured from first seen.">
          {({ id }) => (
            <DatePicker
              id={id}
              noFuture
              value={values.first_seen_from?.slice(0, 10) ?? ''}
              onValueChange={(value) => onChange({ first_seen_from: value || undefined })}
            />
          )}
        </FormField>

        <FormField
          label="Acknowledged by"
          hint="A user id. Rule codes are not a filter — search for one with the search box."
        >
          {({ id }) => (
            <TextInput
              id={id}
              value={values.acknowledged_by ?? ''}
              onChange={(event) => onChange({ acknowledged_by: event.target.value })}
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
