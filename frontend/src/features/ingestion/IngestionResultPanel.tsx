import { Badge } from '@/components/common/Badge';
import { Card } from '@/components/common/Card';
import { DataTable, type Column } from '@/components/common/DataTable';
import { KeyValueList } from '@/components/common/KeyValueList';
import { formatCount } from '@/lib/amounts';
import { humaniseField } from '@/lib/formatters';
import type { BatchIngestResult, IngestionRowError } from '@/types/ingestion';

export interface IngestionResultPanelProps {
  result: BatchIngestResult;
  /** How many rows were submitted, to detect rows the server never reported. */
  submitted?: number;
}

/**
 * The outcome of one ingestion batch.
 *
 * Four counters, not one. "Imported 400" would hide the batch that accepted
 * nothing because every row was a duplicate, and the batch that accepted 390
 * and rejected 10 — which are completely different situations and only one of
 * them needs action.
 *
 * `dry_run` is called out loudly. A dry run that reports 400 accepted has
 * written nothing, and somebody who misses that will wonder why the dashboard
 * is empty.
 */
export function IngestionResultPanel({ result, submitted }: IngestionResultPanelProps) {
  const errorColumns: Array<Column<IngestionRowError>> = [
    {
      key: 'row',
      header: 'Row',
      numeric: true,
      render: (row) => (
        <span className="text-xs tabular">
          {row.row !== null && row.row !== undefined ? row.row : '—'}
        </span>
      ),
      width: '10%',
    },
    {
      key: 'field',
      header: 'Field',
      render: (row) => (
        <span className="font-mono text-2xs text-ink-700 dark:text-ink-200">
          {row.field ?? '—'}
        </span>
      ),
      width: '22%',
    },
    {
      key: 'code',
      header: 'Code',
      render: (row) => (
        <span className="font-mono text-2xs text-ink-600 dark:text-ink-300">
          {row.code ?? '—'}
        </span>
      ),
      hideOnSmall: true,
      width: '22%',
    },
    {
      key: 'message',
      header: 'Problem',
      render: (row) => (
        <span className="text-2xs text-ink-800 dark:text-ink-100">{row.message ?? '—'}</span>
      ),
      width: '46%',
    },
  ];

  const accounted =
    result.accepted + result.rejected + result.duplicated + result.skipped;
  const unaccounted = submitted !== undefined ? submitted - accounted : 0;

  return (
    <Card
      title={`${humaniseField(result.entity_type)} batch`}
      actions={
        <div className="flex items-center gap-1.5">
          {result.dry_run ? (
            <Badge tone="warning" title="Nothing was written. This was a validation pass only.">
              Dry run
            </Badge>
          ) : null}
          <Badge tone={result.ok ? 'neutral' : 'danger'}>
            {result.ok ? 'Accepted' : 'Failed'}
          </Badge>
        </div>
      }
      caveats={result.caveats}
    >
      {result.dry_run ? (
        <p
          role="status"
          className="mb-3 rounded-md border border-ink-200 bg-amber-50 p-3 text-xs leading-relaxed text-amber-900 dark:border-ink-700 dark:bg-amber-950/40 dark:text-amber-200"
        >
          This was a dry run. Every row was validated and <strong>nothing was written</strong>.
          Re-submit with dry run switched off to load the data.
        </p>
      ) : null}

      <KeyValueList
        columns={4}
        entries={[
          {
            label: 'Accepted',
            value: formatCount(result.accepted),
            help: result.dry_run
              ? 'Rows that would be written. Nothing was.'
              : 'Rows written to the database.',
          },
          {
            label: 'Rejected',
            value: formatCount(result.rejected),
            help: 'Failed validation. The errors are listed below, capped by the server.',
          },
          {
            label: 'Already present',
            value: formatCount(result.duplicated),
            help: 'Rows whose identifier already exists.',
          },
          {
            label: 'Skipped',
            value: formatCount(result.skipped),
            help: `Passed over by the duplicate strategy (${result.on_duplicate}).`,
          },
        ]}
      />

      <KeyValueList
        className="mt-4 border-t border-ink-200 pt-3 dark:border-ink-700"
        columns={3}
        entries={[
          {
            label: 'Partial rows allowed',
            value: result.allow_partial ? 'Yes' : 'No',
            help: result.allow_partial
              ? 'Valid rows were accepted and invalid ones rejected individually.'
              : 'All or nothing: one bad row rejects the batch.',
          },
          { label: 'On duplicate', value: humaniseField(result.on_duplicate) },
          {
            label: 'Source system',
            value: result.source_system ?? '—',
            help: 'Recorded against the rows so a later correction can find them.',
          },
          { label: 'Batch id', value: result.source_batch_id ?? '—', mono: true },
          {
            label: 'Request id',
            value: result.request_id ?? '—',
            mono: true,
            help: 'Quote this when reporting a problem with the load.',
          },
        ]}
      />

      {unaccounted > 0 ? (
        <p className="mt-3 text-2xs text-ink-700 dark:text-ink-200">
          {formatCount(unaccounted)} of the {formatCount(submitted ?? 0)} rows submitted are not
          accounted for in these four counters. That usually means the batch was truncated at the
          server's limit of {' '}
          <span className="font-mono">max_batch_size</span>; re-submit the remainder.
        </p>
      ) : null}

      {result.errors.length > 0 ? (
        <div className="mt-4 border-t border-ink-200 pt-3 dark:border-ink-700">
          <h3 className="mb-2 text-2xs font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
            Rejected rows
          </h3>

          <DataTable
            caption="Rows the server rejected, with the reason for each"
            columns={errorColumns}
            rows={result.errors}
            rowKey={(row, index) => `${row.row ?? 'row'}-${row.field ?? 'field'}-${index}`}
            emptyTitle="No row errors"
          />

          {result.rejected > result.errors.length ? (
            <p className="mt-2 text-2xs text-ink-600 dark:text-ink-300">
              {formatCount(result.rejected)} rows were rejected and{' '}
              {formatCount(result.errors.length)} errors are listed — the server caps how many it
              returns. Fix these and re-submit to see the rest.
            </p>
          ) : null}
        </div>
      ) : null}
    </Card>
  );
}
