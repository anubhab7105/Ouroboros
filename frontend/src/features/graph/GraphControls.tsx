import { Badge } from '@/components/common/Badge';
import { AmountInput } from '@/components/common/AmountInput';
import { Button } from '@/components/common/Button';
import { DatePicker } from '@/components/common/DatePicker';
import { FormField } from '@/components/common/FormField';
import { Select } from '@/components/common/Select';
import { TextInput } from '@/components/common/TextInput';
import { formatCount } from '@/lib/amounts';
import type { GraphDirection, GraphStatus } from '@/types/graph';

import { LAYOUT_OPTIONS } from './cytoscapeTheme';
import type { GraphFilterState } from './useGraphFilters';

export interface GraphControlsProps {
  filters: GraphFilterState;
  status?: GraphStatus;
  clampedFields: string[];
  layout: string;
  onLayoutChange: (layout: string) => void;
  onRootChange: (accountId: string) => void;
  onUpdate: (next: Record<string, string | number | boolean | undefined>) => void;
  onReset: () => void;
  onFit: () => void;
}

const DIRECTIONS: Array<{ value: GraphDirection; label: string; help: string }> = [
  {
    value: 'both',
    label: 'Both',
    help: 'Everything connected to the root, in either direction.',
  },
  {
    value: 'outgoing',
    label: 'Outgoing',
    help: 'Where money went. The view for following a distribution.',
  },
  {
    value: 'incoming',
    label: 'Incoming',
    help: 'Where money came from. The view for finding a collection.',
  },
];

const INCLUDES: Array<{ key: keyof GraphFilterState; label: string; help: string }> = [
  {
    key: 'include_transactions',
    label: 'Transfers',
    help: 'Transaction nodes and the transfer edges between accounts. Without these the canvas shows relationships but no money.',
  },
  {
    key: 'include_entities',
    label: 'Shared identifiers',
    help: 'Devices, UPI handles and other pseudonymous identifiers, as dashed edges.',
  },
  {
    key: 'include_complaints',
    label: 'Complaints',
    help: 'Complaints and their correlations. Dashed, because most are inferences.',
  },
  { key: 'include_alerts', label: 'Alerts', help: 'Risk findings raised on these accounts.' },
  {
    key: 'include_assessments',
    label: 'Assessments',
    help: 'Score nodes. Off by default: they add a node per account and rarely change a reading.',
  },
];

/**
 * The traversal controls.
 *
 * The limits are the point of this panel. A network view that silently clamps
 * depth and node count will, sooner or later, be read as "there is no
 * connection" when the honest answer is "the traversal stopped". So the
 * deployment's caps are shown next to the controls, and anything the server
 * clamped is named explicitly.
 *
 * Direction has a real investigative meaning rather than being a technical
 * knob, so each option says what it is for.
 */
export function GraphControls({
  filters,
  status,
  clampedFields,
  layout,
  onLayoutChange,
  onRootChange,
  onUpdate,
  onReset,
  onFit,
}: GraphControlsProps) {
  return (
    <div className="space-y-3">
      <FormField label="Root account" hint="The account the traversal starts from.">
        {({ id }) => (
          <TextInput
            id={id}
            mono
            value={filters.account_id}
            onChange={(event) => onRootChange(event.target.value)}
            placeholder="acc_…"
          />
        )}
      </FormField>

      <div className="grid gap-3 sm:grid-cols-2">
        <FormField
          label="Depth"
          hint={status ? `This deployment allows up to ${status.max_depth}.` : undefined}
        >
          {({ id }) => (
            <TextInput
              id={id}
              type="number"
              min={1}
              max={status?.max_depth ?? 10}
              value={String(filters.depth ?? 2)}
              onChange={(event) => onUpdate({ depth: event.target.value })}
            />
          )}
        </FormField>

        <FormField label="Direction">
          {({ id }) => (
            <>
              <Select
                id={id}
                value={filters.direction ?? 'both'}
                onChange={(event) => onUpdate({ direction: event.target.value })}
                options={DIRECTIONS.map((option) => ({
                  value: option.value,
                  label: option.label,
                }))}
              />
              <p className="mt-1 text-2xs text-ink-600 dark:text-ink-300">
                {DIRECTIONS.find((option) => option.value === (filters.direction ?? 'both'))?.help}
              </p>
            </>
          )}
        </FormField>
      </div>

      <fieldset>
        <legend className="mg-label">Include</legend>
        <ul className="mt-1 space-y-1">
          {INCLUDES.map((entry) => (
            <li key={String(entry.key)}>
              <label className="flex items-start gap-1.5 text-2xs text-ink-700 dark:text-ink-200">
                <input
                  type="checkbox"
                  className="mt-0.5 h-3.5 w-3.5 shrink-0"
                  checked={Boolean(filters[entry.key])}
                  onChange={(event) => onUpdate({ [entry.key]: event.target.checked })}
                />
                <span className="min-w-0">
                  <span className="font-medium">{entry.label}</span>
                  <span className="block text-ink-500 dark:text-ink-400">{entry.help}</span>
                </span>
              </label>
            </li>
          ))}
        </ul>
      </fieldset>

      <div className="grid gap-3 sm:grid-cols-2">
        <FormField label="From date">
          {({ id }) => (
            <DatePicker
              id={id}
              noFuture
              value={filters.date_from?.slice(0, 10) ?? ''}
              onValueChange={(value) => onUpdate({ date_from: value || undefined })}
            />
          )}
        </FormField>

        <FormField label="To date">
          {({ id }) => (
            <DatePicker
              id={id}
              noFuture
              value={filters.date_to?.slice(0, 10) ?? ''}
              onValueChange={(value) => onUpdate({ date_to: value || undefined })}
            />
          )}
        </FormField>
      </div>

      <FormField
        label="Point in time"
        hint="Shows the network as it stood then: links valid at that instant, transfers before it."
      >
        {({ id }) => (
          <DatePicker
            id={id}
            noFuture
            value={filters.as_of?.slice(0, 10) ?? ''}
            onValueChange={(value) => onUpdate({ as_of: value || undefined })}
          />
        )}
      </FormField>

      <FormField
        label="Minimum transfer"
        hint="Drops smaller transfers, which thins a dense canvas — and can hide a structuring pattern built from small amounts."
      >
        {({ id }) => (
          <AmountInput
            id={id}
            value={filters.min_amount !== undefined ? String(filters.min_amount) : ''}
            onValueChange={(value) => onUpdate({ min_amount: value || undefined })}
          />
        )}
      </FormField>

      <FormField label="Layout">
        {({ id }) => (
          <>
            <Select
              id={id}
              value={layout}
              onChange={(event) => onLayoutChange(event.target.value)}
              options={LAYOUT_OPTIONS.map((option) => ({
                value: option.value,
                label: option.label,
              }))}
            />
            <p className="mt-1 text-2xs text-ink-600 dark:text-ink-300">
              {LAYOUT_OPTIONS.find((option) => option.value === layout)?.help}
            </p>
          </>
        )}
      </FormField>

      {clampedFields.length > 0 ? (
        <p
          role="status"
          className="rounded-md border border-ink-200 bg-amber-50 p-2.5 text-2xs leading-relaxed text-amber-900 dark:border-ink-700 dark:bg-amber-950/40 dark:text-amber-200"
        >
          This deployment clamped your {clampedFields.join(', ')}. The canvas shows the clamped
          traversal, so an absent connection may simply be beyond the limit.
        </p>
      ) : null}

      {status ? (
        <div className="flex flex-wrap gap-1.5">
          <Badge tone="neutral" title="Maximum nodes a traversal will return here.">
            {formatCount(status.max_nodes)} nodes
          </Badge>
          <Badge tone="neutral" title="Maximum edges a traversal will return here.">
            {formatCount(status.max_edges)} edges
          </Badge>
          <Badge tone="neutral" title="Maximum hop depth.">
            depth {status.max_depth}
          </Badge>
          <Badge tone="neutral" title="Maximum span a date range may cover.">
            {formatCount(status.max_date_span_days)} days
          </Badge>
        </div>
      ) : null}

      <div className="flex flex-wrap items-center gap-2">
        <Button size="sm" variant="secondary" onClick={onFit}>
          Fit to view
        </Button>
        <Button size="sm" variant="ghost" onClick={onReset}>
          Reset filters
        </Button>
      </div>
    </div>
  );
}
