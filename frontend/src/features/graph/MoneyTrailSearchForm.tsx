import { Button } from '@/components/common/Button';
import { AmountInput } from '@/components/common/AmountInput';
import { DatePicker } from '@/components/common/DatePicker';
import { FormField } from '@/components/common/FormField';
import { Select } from '@/components/common/Select';
import { TextInput } from '@/components/common/TextInput';
import type { GraphStatus } from '@/types/graph';

export type TrailMode = 'trails' | 'paths';

export interface TrailSearchState {
  mode: TrailMode;
  accountId: string;
  destinationId: string;
  direction: 'outgoing' | 'incoming';
  maxHops: number;
  minAmount: string;
  dateFrom: string;
  dateTo: string;
}

export interface MoneyTrailSearchFormProps {
  value: TrailSearchState;
  onChange: (next: Partial<TrailSearchState>) => void;
  onSearch: () => void;
  isSearching?: boolean;
  status?: GraphStatus;
}

/**
 * Two different questions, in one form.
 *
 * They are genuinely distinct and the API separates them:
 *
 * - **Trails** follow money away from (or into) one account, without a
 *   destination in mind. This is the question "where did it go".
 * - **Paths** look for a connection between two named accounts. This is
 *   "is there a route from A to B", which is what a referral usually asks.
 *
 * Picking one changes which fields apply, so the form shows only those, rather
 * than leaving a destination field that silently does nothing in trail mode.
 *
 * The hop limit is capped by the deployment and the cap is stated, because a
 * path search that found nothing at three hops is a very different statement
 * from one that found nothing at ten.
 */
export function MoneyTrailSearchForm({
  value,
  onChange,
  onSearch,
  isSearching,
  status,
}: MoneyTrailSearchFormProps) {
  const maxHops = value.mode === 'paths' ? status?.max_depth : status?.max_trails;

  return (
    <form
      className="space-y-3"
      onSubmit={(event) => {
        event.preventDefault();
        onSearch();
      }}
    >
      <FormField label="Question">
        {({ id }) => (
          <>
            <Select
              id={id}
              value={value.mode}
              onChange={(event) => onChange({ mode: event.target.value as TrailMode })}
              options={[
                { value: 'trails', label: 'Where did money go from this account?' },
                { value: 'paths', label: 'Is there a route between two accounts?' },
              ]}
            />
            <p className="mt-1 text-2xs text-ink-600 dark:text-ink-300">
              {value.mode === 'trails'
                ? 'Follows chains of transfers outward from one account, with no destination in mind.'
                : 'Searches for chains of transfers connecting two named accounts.'}
            </p>
          </>
        )}
      </FormField>

      <FormField
        label={value.mode === 'paths' ? 'From account' : 'Account'}
        required
      >
        {({ id }) => (
          <TextInput
            id={id}
            mono
            value={value.accountId}
            onChange={(event) => onChange({ accountId: event.target.value })}
            placeholder="acc_…"
          />
        )}
      </FormField>

      {value.mode === 'paths' ? (
        <FormField label="To account" required>
          {({ id }) => (
            <TextInput
              id={id}
              mono
              value={value.destinationId}
              onChange={(event) => onChange({ destinationId: event.target.value })}
              placeholder="acc_…"
            />
          )}
        </FormField>
      ) : (
        <FormField label="Direction">
          {({ id }) => (
            <Select
              id={id}
              value={value.direction}
              onChange={(event) =>
                onChange({ direction: event.target.value as 'outgoing' | 'incoming' })
              }
              options={[
                { value: 'outgoing', label: 'Outgoing — where money went' },
                { value: 'incoming', label: 'Incoming — where money came from' },
              ]}
            />
          )}
        </FormField>
      )}

      <div className="grid gap-3 sm:grid-cols-2">
        <FormField
          label="Maximum hops"
          hint={maxHops ? `Capped at ${maxHops} here.` : undefined}
        >
          {({ id }) => (
            <TextInput
              id={id}
              type="number"
              min={1}
              max={maxHops ?? 10}
              value={String(value.maxHops)}
              onChange={(event) => onChange({ maxHops: Number(event.target.value) || 1 })}
            />
          )}
        </FormField>

        <FormField
          label="Minimum transfer"
          hint="Ignores smaller hops. Useful on a noisy account; it can also hide a chain built from small amounts."
        >
          {({ id }) => (
            <AmountInput
              id={id}
              value={value.minAmount}
              onValueChange={(next) => onChange({ minAmount: next })}
            />
          )}
        </FormField>

        <FormField label="From date">
          {({ id }) => (
            <DatePicker
              id={id}
              noFuture
              value={value.dateFrom}
              onValueChange={(next) => onChange({ dateFrom: next })}
            />
          )}
        </FormField>

        <FormField label="To date">
          {({ id }) => (
            <DatePicker
              id={id}
              noFuture
              value={value.dateTo}
              onValueChange={(next) => onChange({ dateTo: next })}
            />
          )}
        </FormField>
      </div>

      <Button
        type="submit"
        variant="primary"
        size="sm"
        isLoading={isSearching}
        disabled={
          !value.accountId.trim() ||
          (value.mode === 'paths' && !value.destinationId.trim())
        }
      >
        Search
      </Button>

      <p className="text-2xs leading-relaxed text-ink-500 dark:text-ink-400">
        A result shows a chain of transfers that exists in the ledger. It does not establish that
        the same funds travelled it — money is fungible, and that distinction is the difference
        between a lead and a claim a court would reject.
      </p>
    </form>
  );
}
