import { useMemo, useState } from 'react';

import { Badge } from '@/components/common/Badge';
import { Card } from '@/components/common/Card';
import { DataTable, type Column } from '@/components/common/DataTable';
import { EmptyState } from '@/components/common/EmptyState';
import { Select } from '@/components/common/Select';
import { TextInput } from '@/components/common/TextInput';
import { formatCount } from '@/lib/amounts';
import { humaniseField } from '@/lib/formatters';
import type { FeatureSchema } from '@/types/model';

export interface FeatureSchemaTableProps {
  schema?: FeatureSchema;
  isLoading?: boolean;
}

interface FeatureRow {
  name: string;
  /** The trailing window token, where the name encodes one. */
  window: string | null;
  /** The leading token, used as a rough family. */
  family: string;
}

/**
 * Split a feature name into a family and a window.
 *
 * The schema publishes names and windows as two flat lists rather than
 * structured entries, so this derives what it can from the naming convention
 * and says nothing where it cannot. A guess presented as structure would be
 * worse than a flat list.
 */
function parseFeature(name: string, windows: string[]): FeatureRow {
  const window = windows.find((candidate) => name.endsWith(`_${candidate}`)) ?? null;
  const family = name.split('_')[0] ?? name;

  return { name, window, family };
}

/**
 * The feature catalog.
 *
 * Two parts, and the second is the one that matters for review:
 *
 * - **The features in use**, filterable, because a catalog of ninety-odd
 *   names is only useful if you can find the one you are looking at.
 *
 * - **The inputs the schema refuses.** Protected attributes and proxies for
 *   them are rejected at the schema level, so supplying one fails rather than
 *   being silently ignored. Putting that list on screen makes the exclusion
 *   auditable instead of a claim in a document nobody reads.
 */
export function FeatureSchemaTable({ schema, isLoading }: FeatureSchemaTableProps) {
  const [search, setSearch] = useState('');
  const [windowFilter, setWindowFilter] = useState('');
  const [familyFilter, setFamilyFilter] = useState('');

  const rows = useMemo(() => {
    const windows = schema?.feature_windows ?? [];
    return (schema?.feature_fields ?? []).map((name) => parseFeature(name, windows));
  }, [schema]);

  const families = useMemo(
    () => [...new Set(rows.map((row) => row.family))].sort(),
    [rows],
  );

  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase();

    return rows.filter((row) => {
      if (term && !row.name.toLowerCase().includes(term)) return false;
      if (windowFilter && row.window !== windowFilter) return false;
      if (familyFilter && row.family !== familyFilter) return false;
      return true;
    });
  }, [rows, search, windowFilter, familyFilter]);

  const columns: Array<Column<FeatureRow>> = [
    {
      key: 'name',
      header: 'Feature',
      render: (row) => (
        <span className="font-mono text-2xs text-ink-800 dark:text-ink-100">{row.name}</span>
      ),
      width: '58%',
    },
    {
      key: 'family',
      header: 'Family',
      render: (row) => (
        <span className="text-2xs text-ink-700 dark:text-ink-200">{humaniseField(row.family)}</span>
      ),
      width: '22%',
    },
    {
      key: 'window',
      header: 'Window',
      render: (row) =>
        row.window ? (
          <Badge tone="neutral" title="The lookback this feature is computed over.">
            {row.window}
          </Badge>
        ) : (
          <span className="text-2xs text-ink-400 dark:text-ink-500">—</span>
        ),
      width: '20%',
    },
  ];

  return (
    <Card
      title="Feature schema"
      description={
        schema
          ? `Version ${schema.feature_schema_version}: ${formatCount(schema.feature_fields.length)} features over ${schema.feature_windows.length} windows.`
          : undefined
      }
      caveats={schema?.caveats}
    >
      {!isLoading && !schema?.available ? (
        <EmptyState
          title="No feature schema is published"
          message={`This deployment reports the schema as unavailable and scores as "${schema?.fallback_label ?? 'unknown'}". Without a published schema the inputs cannot be reviewed from here.`}
          compact
        />
      ) : (
        <>
          <div className="mb-3 grid gap-2 sm:grid-cols-3">
            <TextInput
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Filter by name"
              aria-label="Filter features by name"
            />
            <Select
              value={familyFilter}
              onChange={(event) => setFamilyFilter(event.target.value)}
              placeholder="Any family"
              aria-label="Filter features by family"
              options={families.map((value) => ({ value, label: humaniseField(value) }))}
            />
            <Select
              value={windowFilter}
              onChange={(event) => setWindowFilter(event.target.value)}
              placeholder="Any window"
              aria-label="Filter features by window"
              options={(schema?.feature_windows ?? []).map((value) => ({ value, label: value }))}
            />
          </div>

          <DataTable
            caption="Features in the active schema"
            columns={columns}
            rows={filtered}
            rowKey={(row) => row.name}
            isLoading={isLoading}
            skeletonRows={6}
            emptyTitle="No feature matches that filter"
          />

          {schema && schema.forbidden_fields.length > 0 ? (
            <div className="mt-4 border-t border-ink-200 pt-3 dark:border-ink-700">
              <h3 className="mb-1.5 text-2xs font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
                Inputs the schema refuses
              </h3>
              <ul className="flex flex-wrap gap-1.5">
                {schema.forbidden_fields.map((field) => (
                  <li key={field}>
                    <Badge
                      tone="neutral"
                      title="Rejected at the schema level. Supplying this fails rather than being silently ignored."
                    >
                      {humaniseField(field)}
                    </Badge>
                  </li>
                ))}
              </ul>
              <p className="mt-2 text-2xs leading-relaxed text-ink-600 dark:text-ink-300">
                Refused rather than merely omitted, so the exclusion is enforced by the schema and
                not by convention. This is the list to check when asked what the model is not
                allowed to see.
              </p>
            </div>
          ) : null}

          <p className="mt-3 text-2xs leading-relaxed text-ink-500 dark:text-ink-400">
            Every feature is computed strictly before an assessment's as-of instant, so a feature
            cannot see the behaviour it is meant to predict.
          </p>
        </>
      )}
    </Card>
  );
}
