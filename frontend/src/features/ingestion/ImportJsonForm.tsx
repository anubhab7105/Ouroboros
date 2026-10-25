import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useMemo, useState } from 'react';

import { Button } from '@/components/common/Button';
import { Card } from '@/components/common/Card';
import { ErrorState } from '@/components/common/ErrorState';
import { FormField } from '@/components/common/FormField';
import { Select } from '@/components/common/Select';
import { TextArea } from '@/components/common/TextArea';
import { TextInput } from '@/components/common/TextInput';
import { useApiError } from '@/hooks/useApiError';
import { formatCount } from '@/lib/amounts';
import type { BatchIngestResult, IngestEntityType } from '@/types/ingestion';

import { IngestionResultPanel } from './IngestionResultPanel';
import { ingestBatch } from './ingestionApi';

export interface ImportJsonFormProps {
  /** The server's batch cap, so oversized pastes are caught before sending. */
  maxBatchSize?: number;
}

const ENTITY_OPTIONS: Array<{ value: IngestEntityType; label: string; shape: string }> = [
  {
    value: 'accounts',
    label: 'Accounts',
    shape: '{ "id"?, "account_type", "status", "created_at", "metadata_json"? }',
  },
  {
    value: 'transactions',
    label: 'Transactions',
    shape:
      '{ "reference", "sender_account_id", "receiver_account_id", "amount", "currency"?, "occurred_at", "status"?, "channel"? }',
  },
  {
    value: 'complaints',
    label: 'Complaints',
    shape:
      '{ "reference", "reported_at", "category"?, "narrative_raw", "transaction_reference"?, "suspected_account_id"?, "amount"? }',
  },
  {
    value: 'entities',
    label: 'Identifiers',
    shape: '{ "entity_type", "identifier_hash", "identifier_display"?, "source"? }',
  },
  {
    value: 'entity-links',
    label: 'Identifier links',
    shape:
      '{ "account_id", "entity_id", "match_method"?, "confidence"?, "verification_state"?, "valid_from"? }',
  },
];

/** Accept either a bare array or `{ records: [...] }`. */
function parseRecords(text: string): { records: object[]; error: string | null } {
  const trimmed = text.trim();
  if (!trimmed) return { records: [], error: null };

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch (caught) {
    return {
      records: [],
      error: caught instanceof Error ? caught.message : 'That is not valid JSON.',
    };
  }

  const candidate =
    Array.isArray(parsed)
      ? parsed
      : parsed && typeof parsed === 'object' && Array.isArray((parsed as { records?: unknown }).records)
        ? (parsed as { records: unknown[] }).records
        : null;

  if (!candidate) {
    return {
      records: [],
      error: 'Expected an array of records, or an object with a "records" array.',
    };
  }

  const nonObject = candidate.findIndex(
    (item) => !item || typeof item !== 'object' || Array.isArray(item),
  );

  if (nonObject !== -1) {
    return { records: [], error: `Row ${nonObject + 1} is not an object.` };
  }

  return { records: candidate as object[], error: null };
}

/**
 * Load records pasted as JSON.
 *
 * The parse happens in the browser first, and deliberately so: a malformed
 * paste produces "row 14 is not an object" immediately rather than a 422 from
 * the server after a round trip. What it does *not* do is validate the fields
 * — that is the server's job, it does it well, and duplicating the rules here
 * would mean two sets of validation that disagree the first time one changes.
 *
 * Dry run is on by default. On a hand-assembled batch it is the difference
 * between a list of corrections and a half-loaded dataset.
 */
export function ImportJsonForm({ maxBatchSize }: ImportJsonFormProps) {
  const queryClient = useQueryClient();

  const [entityType, setEntityType] = useState<IngestEntityType>('accounts');
  const [text, setText] = useState('');
  const [sourceSystem, setSourceSystem] = useState('manual-import');
  const [batchId, setBatchId] = useState('');
  const [dryRun, setDryRun] = useState(true);
  const [allowPartial, setAllowPartial] = useState(true);
  const [result, setResult] = useState<BatchIngestResult | null>(null);

  const parsed = useMemo(() => parseRecords(text), [text]);
  const selected = ENTITY_OPTIONS.find((option) => option.value === entityType);

  const tooLarge = Boolean(maxBatchSize && parsed.records.length > maxBatchSize);

  const mutation = useMutation({
    mutationFn: () =>
      ingestBatch(entityType, parsed.records, {
        source_system: sourceSystem.trim() || undefined,
        source_batch_id: batchId.trim() || undefined,
        dry_run: dryRun,
        allow_partial: allowPartial,
      }),
    onSuccess: (batchResult) => {
      setResult(batchResult);
      if (!dryRun) void queryClient.invalidateQueries();
    },
  });

  const error = useApiError(mutation.error);

  return (
    <Card
      title="Import JSON"
      description="Paste records, or an object with a records array. The server validates the fields; this form only checks that the JSON is well formed."
    >
      <div className="grid gap-3 sm:grid-cols-3">
        <FormField label="Record type">
          {({ id }) => (
            <Select
              id={id}
              value={entityType}
              onChange={(event) => setEntityType(event.target.value as IngestEntityType)}
              options={ENTITY_OPTIONS.map((option) => ({
                value: option.value,
                label: option.label,
              }))}
            />
          )}
        </FormField>

        <FormField label="Source system" hint="Recorded against every row.">
          {({ id }) => (
            <TextInput
              id={id}
              value={sourceSystem}
              onChange={(event) => setSourceSystem(event.target.value)}
              maxLength={100}
            />
          )}
        </FormField>

        <FormField label="Batch id" hint="Optional. Lets this load be found again.">
          {({ id }) => (
            <TextInput
              id={id}
              value={batchId}
              onChange={(event) => setBatchId(event.target.value)}
              maxLength={100}
            />
          )}
        </FormField>
      </div>

      {selected ? (
        <p className="mt-2 break-words font-mono text-2xs text-ink-500 dark:text-ink-400">
          {selected.shape}
        </p>
      ) : null}

      <FormField
        label="Records"
        className="mt-3"
        error={parsed.error ?? undefined}
        hint={
          parsed.records.length > 0
            ? `${formatCount(parsed.records.length)} row${parsed.records.length === 1 ? '' : 's'} parsed.`
            : 'A JSON array, or { "records": [ … ] }.'
        }
      >
        {({ id, describedBy, invalid }) => (
          <TextArea
            id={id}
            aria-describedby={describedBy}
            invalid={invalid}
            value={text}
            onChange={(event) => setText(event.target.value)}
            rows={12}
            className="font-mono text-2xs"
            placeholder='[{"id": "acc_1", "account_type": "INDIVIDUAL", "status": "ACTIVE", "created_at": "2026-01-01T00:00:00Z"}]'
          />
        )}
      </FormField>

      {tooLarge ? (
        <p className="mt-2 text-2xs text-amber-900 dark:text-amber-200">
          {formatCount(parsed.records.length)} rows exceeds this deployment's batch cap of{' '}
          {formatCount(maxBatchSize ?? 0)}. Split the paste, or the server will truncate it.
        </p>
      ) : null}

      <div className="mt-3 flex flex-wrap items-center gap-3 border-t border-ink-200 pt-3 dark:border-ink-700">
        <label className="flex items-center gap-1.5 text-xs text-ink-700 dark:text-ink-200">
          <input
            type="checkbox"
            checked={dryRun}
            onChange={(event) => setDryRun(event.target.checked)}
            className="h-3.5 w-3.5"
          />
          Dry run
        </label>

        <label className="flex items-center gap-1.5 text-xs text-ink-700 dark:text-ink-200">
          <input
            type="checkbox"
            checked={allowPartial}
            onChange={(event) => setAllowPartial(event.target.checked)}
            className="h-3.5 w-3.5"
          />
          Accept the valid rows
          <span className="text-ink-500 dark:text-ink-400">
            (otherwise one bad row rejects the batch)
          </span>
        </label>

        <Button
          variant="primary"
          size="sm"
          isLoading={mutation.isPending}
          disabled={parsed.records.length === 0 || Boolean(parsed.error)}
          onClick={() => {
            setResult(null);
            mutation.mutate();
          }}
        >
          {dryRun ? 'Validate' : 'Import'}
        </Button>
      </div>

      {error ? <ErrorState error={error} className="mt-4" /> : null}

      {result ? (
        <div className="mt-4">
          <IngestionResultPanel result={result} submitted={parsed.records.length} />
        </div>
      ) : null}
    </Card>
  );
}
