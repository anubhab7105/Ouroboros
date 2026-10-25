import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useMemo, useState } from 'react';

import { Badge } from '@/components/common/Badge';
import { Button } from '@/components/common/Button';
import { Card } from '@/components/common/Card';
import { ErrorState } from '@/components/common/ErrorState';
import { FormField } from '@/components/common/FormField';
import { KeyValueList } from '@/components/common/KeyValueList';
import { TextInput } from '@/components/common/TextInput';
import { useApiError } from '@/hooks/useApiError';
import { formatCount } from '@/lib/amounts';
import { saveJson } from '@/lib/download';
import type { BatchIngestResult, IngestEntityType } from '@/types/ingestion';

import { IngestionResultPanel } from './IngestionResultPanel';
import { INGEST_ORDER, ingestBatch } from './ingestionApi';
import {
  DEFAULT_GENERATE_OPTIONS,
  datasetSizes,
  generateDataset,
  type GenerateOptions,
} from './syntheticData';

/**
 * Generate a synthetic dataset and load it.
 *
 * There is no generation endpoint — the API ingests records and nothing more —
 * so the dataset is built in the browser and loaded through the ordinary
 * ingestion endpoints. That is the honest arrangement: the resulting data is
 * as traceable as any other import, carries a source system and a batch id,
 * and can be validated as a dry run first.
 *
 * Batches go in dependency order (accounts, then transactions, then
 * complaints, then entities, then links), because a transaction referencing an
 * account that does not yet exist is rejected. If one batch fails the sequence
 * stops rather than loading orphaned rows on top of it.
 *
 * Every pattern the generator plants is listed after a load, so the person who
 * loaded it knows which accounts should light up — and can tell a rule that is
 * broken from a dataset that simply contains nothing to find.
 */
export function GenerateDataForm() {
  const queryClient = useQueryClient();

  const [options, setOptions] = useState<GenerateOptions>(DEFAULT_GENERATE_OPTIONS);
  const [dryRun, setDryRun] = useState(true);
  const [results, setResults] = useState<Array<{ type: IngestEntityType; result: BatchIngestResult }>>(
    [],
  );
  const [stoppedAt, setStoppedAt] = useState<IngestEntityType | null>(null);

  const dataset = useMemo(() => generateDataset(options), [options]);
  const sizes = useMemo(() => datasetSizes(dataset), [dataset]);

  const batchId = `generated-${options.seed}-${options.normalAccounts}-${options.patterns}`;

  const mutation = useMutation({
    mutationFn: async () => {
      const collected: Array<{ type: IngestEntityType; result: BatchIngestResult }> = [];
      setStoppedAt(null);

      const payloads: Record<IngestEntityType, object[]> = {
        accounts: dataset.accounts,
        transactions: dataset.transactions,
        complaints: dataset.complaints,
        entities: dataset.entities,
        'entity-links': dataset.entityLinks,
      };

      for (const entityType of INGEST_ORDER) {
        const records = payloads[entityType];
        if (records.length === 0) continue;

        const result = await ingestBatch(entityType, records, {
          source_system: 'muleguard-synthetic-generator',
          source_batch_id: batchId,
          dry_run: dryRun,
          allow_partial: true,
        });

        collected.push({ type: entityType, result });
        setResults([...collected]);

        // Later batches reference earlier rows, so a failure here means
        // everything after it would be orphaned. Stop rather than continue.
        if (!result.ok && !dryRun) {
          setStoppedAt(entityType);
          break;
        }
      }

      return collected;
    },
    onSuccess: () => {
      if (!dryRun) {
        void queryClient.invalidateQueries();
      }
    },
  });

  const error = useApiError(mutation.error);

  const numberField = (
    label: string,
    key: keyof GenerateOptions,
    hint: string,
    min = 0,
  ) => (
    <FormField label={label} hint={hint}>
      {({ id }) => (
        <TextInput
          id={id}
          type="number"
          min={min}
          value={String(options[key])}
          onChange={(event) =>
            setOptions((current) => ({
              ...current,
              [key]: Math.max(min, Number(event.target.value) || 0),
            }))
          }
        />
      )}
    </FormField>
  );

  return (
    <Card
      title="Generate a synthetic dataset"
      description="Built in the browser and loaded through the ordinary ingestion endpoints. Nothing about it is privileged: it is an import like any other."
    >
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {numberField(
          'Ordinary accounts',
          'normalAccounts',
          'Unremarkable accounts. A dataset of nothing but fraud teaches nothing about precision.',
          1,
        )}
        {numberField(
          'Pattern sets',
          'patterns',
          'Each set plants a collection account, a pass-through, a fan-out, a layering chain, a dormant reactivation and a shared-identifier cluster.',
          1,
        )}
        {numberField('Days of history', 'days', 'How far back activity is spread.', 1)}
        {numberField('Complaints', 'complaints', 'Raised against the planted patterns.', 0)}
        {numberField('Seed', 'seed', 'The same seed reproduces the same dataset exactly.', 1)}

        <FormField label="Currency" hint="Applied to every generated amount.">
          {({ id }) => (
            <TextInput
              id={id}
              maxLength={3}
              value={options.currency}
              onChange={(event) =>
                setOptions((current) => ({
                  ...current,
                  currency: event.target.value.toUpperCase(),
                }))
              }
            />
          )}
        </FormField>
      </div>

      <div className="mt-4 border-t border-ink-200 pt-3 dark:border-ink-700">
        <h3 className="mb-2 text-2xs font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
          This dataset
        </h3>

        <KeyValueList
          columns={4}
          entries={Object.entries(sizes).map(([name, count]) => ({
            label: name.replace('-', ' '),
            value: formatCount(count),
          }))}
        />

        <div className="mt-3">
          <h4 className="mb-1.5 text-2xs font-semibold text-ink-600 dark:text-ink-300">
            Patterns planted, and where
          </h4>
          <ul className="space-y-1.5">
            {dataset.plantedPatterns.slice(0, 12).map((pattern, index) => (
              <li key={`${pattern.kind}-${index}`} className="text-2xs">
                <span className="font-medium text-ink-800 dark:text-ink-100">{pattern.kind}</span>
                <span className="ml-1.5 font-mono text-ink-500 dark:text-ink-400">
                  {pattern.accountIds.slice(0, 3).join(', ')}
                  {pattern.accountIds.length > 3 ? ` +${pattern.accountIds.length - 3}` : ''}
                </span>
                <span className="block text-ink-600 dark:text-ink-300">{pattern.note}</span>
              </li>
            ))}
          </ul>

          {dataset.plantedPatterns.length > 12 ? (
            <p className="mt-1 text-2xs text-ink-500 dark:text-ink-400">
              and {dataset.plantedPatterns.length - 12} more.
            </p>
          ) : null}
        </div>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-ink-200 pt-3 dark:border-ink-700">
        <label className="flex items-center gap-1.5 text-xs text-ink-700 dark:text-ink-200">
          <input
            type="checkbox"
            checked={dryRun}
            onChange={(event) => setDryRun(event.target.checked)}
            className="h-3.5 w-3.5"
          />
          Dry run
          <span className="text-ink-500 dark:text-ink-400">
            (validate everything, write nothing)
          </span>
        </label>

        <Button
          variant="primary"
          size="sm"
          isLoading={mutation.isPending}
          onClick={() => {
            setResults([]);
            mutation.mutate();
          }}
        >
          {dryRun ? 'Validate' : 'Load dataset'}
        </Button>

        <Button
          variant="ghost"
          size="sm"
          onClick={() =>
            saveJson(
              {
                generated_at: new Date().toISOString(),
                options,
                planted_patterns: dataset.plantedPatterns,
                accounts: dataset.accounts,
                transactions: dataset.transactions,
                complaints: dataset.complaints,
                entities: dataset.entities,
                entity_links: dataset.entityLinks,
              },
              `muleguard-synthetic-${options.seed}.json`,
            )
          }
        >
          Download as JSON
        </Button>

        <Badge tone="neutral" title="Recorded against every row, so this load can be found later.">
          batch {batchId}
        </Badge>
      </div>

      {error ? <ErrorState error={error} className="mt-4" /> : null}

      {stoppedAt ? (
        <p
          role="status"
          className="mt-4 rounded-md border border-ink-200 bg-amber-50 p-3 text-xs leading-relaxed text-amber-900 dark:border-ink-700 dark:bg-amber-950/40 dark:text-amber-200"
        >
          The sequence stopped at the <strong>{stoppedAt}</strong> batch. Later batches reference
          earlier rows, so continuing would have loaded orphaned records. Fix the rejections below
          and run again — already-loaded rows will come back as duplicates rather than being
          written twice.
        </p>
      ) : null}

      {results.length > 0 ? (
        <div className="mt-4 space-y-4">
          {results.map(({ type, result }) => (
            <IngestionResultPanel
              key={type}
              result={result}
              submitted={sizes[type]}
            />
          ))}
        </div>
      ) : null}
    </Card>
  );
}
