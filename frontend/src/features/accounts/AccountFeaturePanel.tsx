import { useQuery } from '@tanstack/react-query';
import { useMemo, useState } from 'react';

import { Badge } from '@/components/common/Badge';
import { Card } from '@/components/common/Card';
import { EmptyState } from '@/components/common/EmptyState';
import { LoadingSpinner } from '@/components/common/LoadingSpinner';
import { Select } from '@/components/common/Select';
import { TextInput } from '@/components/common/TextInput';
import { formatRatio } from '@/lib/amounts';
import { queryKeys } from '@/lib/queryKeys';
import { humaniseField } from '@/lib/formatters';
import { fetchFeatureSchema } from '@/features/model-monitoring/modelApi';

export interface AccountFeaturePanelProps {
  /** The feature snapshot id recorded on the assessment, if there was one. */
  featureSnapshotId?: string | null;
  featureSchemaVersion?: string | null;
}

/**
 * Which features the scorer is built from.
 *
 * The API has no endpoint that returns an individual account's feature values:
 * the snapshot is persisted and referenced by the assessment, but it is not
 * served. Rather than invent one, this panel shows the *schema* — the catalog
 * of features in force, with the inputs the schema explicitly forbids — and
 * names the snapshot the assessment used.
 *
 * The forbidden list is the part worth reading. It records the attributes the
 * model is not permitted to see, which is a claim that should be auditable
 * from the interface rather than taken on trust from a document.
 */
export function AccountFeaturePanel({
  featureSnapshotId,
  featureSchemaVersion,
}: AccountFeaturePanelProps) {
  const [search, setSearch] = useState('');
  const [windowFilter, setWindowFilter] = useState('');

  const query = useQuery({
    queryKey: queryKeys.model.featureSchema(),
    queryFn: fetchFeatureSchema,
    staleTime: 10 * 60_000,
  });

  const schema = query.data;

  const fields = useMemo(() => {
    const all = schema?.feature_fields ?? [];
    const term = search.trim().toLowerCase();

    return all.filter((field) => {
      if (term && !field.toLowerCase().includes(term)) return false;
      if (windowFilter && !field.includes(windowFilter)) return false;
      return true;
    });
  }, [schema, search, windowFilter]);

  return (
    <Card
      title="Features"
      description="The feature catalog the scorer is built from. Individual feature values are persisted in a snapshot but are not served by the API, so this shows the schema and names the snapshot used."
      caveats={schema?.caveats}
    >
      {query.isLoading ? (
        <LoadingSpinner label="Loading feature schema" />
      ) : !schema?.available ? (
        <EmptyState
          title="No feature schema is published"
          message={`This deployment reports the schema as unavailable, and scores as "${schema?.fallback_label ?? 'unknown'}".`}
          compact
        />
      ) : (
        <>
          <div className="mb-3 flex flex-wrap items-center gap-2 text-2xs">
            <Badge tone="neutral" title="The schema version the catalog below belongs to.">
              Schema {schema.feature_schema_version}
            </Badge>
            {featureSchemaVersion && featureSchemaVersion !== schema.feature_schema_version ? (
              <Badge
                tone="warning"
                title="This assessment was computed under a different schema version, so the catalog below is not exactly the one it used."
              >
                Assessment used {featureSchemaVersion}
              </Badge>
            ) : null}
            <span className="text-ink-500 dark:text-ink-400">
              {schema.feature_fields.length} features
            </span>
            {featureSnapshotId ? (
              <span className="font-mono text-ink-500 dark:text-ink-400" title={featureSnapshotId}>
                snapshot {featureSnapshotId.slice(0, 8)}…
              </span>
            ) : null}
          </div>

          <div className="mb-3 grid gap-2 sm:grid-cols-2">
            <TextInput
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Filter features"
              aria-label="Filter features by name"
            />
            <Select
              value={windowFilter}
              onChange={(event) => setWindowFilter(event.target.value)}
              placeholder="Any window"
              aria-label="Filter features by window"
              options={(schema.feature_windows ?? []).map((value) => ({
                value,
                label: value,
              }))}
            />
          </div>

          {fields.length === 0 ? (
            <EmptyState title="No feature matches that filter" compact />
          ) : (
            <ul className="grid max-h-72 grid-cols-1 gap-x-4 gap-y-0.5 overflow-y-auto sm:grid-cols-2">
              {fields.map((field) => (
                <li
                  key={field}
                  className="truncate font-mono text-2xs text-ink-700 dark:text-ink-200"
                  title={field}
                >
                  {field}
                </li>
              ))}
            </ul>
          )}

          {schema.forbidden_fields.length > 0 ? (
            <div className="mt-4 border-t border-ink-200 pt-3 dark:border-ink-700">
              <h3 className="mb-1.5 text-2xs font-semibold uppercase tracking-wide text-ink-500 dark:text-ink-400">
                Inputs the schema refuses
              </h3>
              <ul className="flex flex-wrap gap-1.5">
                {schema.forbidden_fields.map((field) => (
                  <li key={field}>
                    <Badge
                      tone="neutral"
                      title="Rejected by the feature schema. The model cannot see this, and an attempt to supply it fails rather than being ignored."
                    >
                      {humaniseField(field)}
                    </Badge>
                  </li>
                ))}
              </ul>
              <p className="mt-2 text-2xs leading-relaxed text-ink-600 dark:text-ink-300">
                These are refused at the schema level rather than merely left out, so the exclusion
                is enforced rather than conventional.
              </p>
            </div>
          ) : null}

          {schema.feature_windows.length > 0 ? (
            <p className="mt-3 text-2xs text-ink-500 dark:text-ink-400">
              Windows in use: {schema.feature_windows.join(', ')}. Each feature is computed strictly
              before the assessment's as-of instant, so a feature cannot see the behaviour it is
              meant to predict. Ratios print as {formatRatio(0.5)}-style values.
            </p>
          ) : null}
        </>
      )}
    </Card>
  );
}
