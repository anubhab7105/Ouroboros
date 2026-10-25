import { Badge } from '@/components/common/Badge';
import { CopyButton } from '@/components/common/CopyButton';
import { DataTable, type Column } from '@/components/common/DataTable';
import { SeverityBadge } from '@/components/common/SeverityBadge';
import { formatRatio } from '@/lib/amounts';
import { formatEvidenceReference } from '@/lib/formatters';
import type { RuleHit } from '@/types/account';

export interface RuleHitsTableProps {
  rows: RuleHit[];
  isLoading?: boolean;
  /** Include rules that were evaluated and did not fire. */
  includeNotTriggered?: boolean;
  onSelectEvidence?: (reference: string) => void;
  emptyMessage?: string;
}

/**
 * Which detection rules fired, with the number each one measured.
 *
 * This is the explainability surface. Three things make it one rather than a
 * list of rule names:
 *
 * - **The measured value sits next to the threshold.** "Rapid pass-through
 *   fired" is an assertion; "funds left within 00:11 against a 24-hour
 *   threshold" is a fact an analyst can check and, where appropriate,
 *   disagree with.
 *
 * - **Rules that did not fire can be shown.** Knowing that the fan-in rule was
 *   evaluated and came back below threshold is evidence about the account, and
 *   an analyst who cannot see it may redo that work by hand.
 *
 * - **Evidence references are listed per rule,** so the specific transactions
 *   behind the finding are reachable rather than implied.
 */
export function RuleHitsTable({
  rows,
  isLoading,
  includeNotTriggered = false,
  onSelectEvidence,
  emptyMessage,
}: RuleHitsTableProps) {
  const visible = includeNotTriggered ? rows : rows.filter((row) => row.triggered);

  const columns: Array<Column<RuleHit>> = [
    {
      key: 'severity',
      header: 'Severity',
      render: (row) => <SeverityBadge severity={row.severity} />,
      width: '11%',
    },
    {
      key: 'rule_code',
      header: 'Rule',
      render: (row) => (
        <span className="flex items-center gap-1">
          <span className="font-mono text-2xs text-ink-800 dark:text-ink-100">{row.rule_code}</span>
          <span className="text-2xs text-ink-400 dark:text-ink-500" title="Rule pack version">
            {row.rule_version}
          </span>
          <CopyButton value={row.rule_code} label={`Copy rule code ${row.rule_code}`} />
        </span>
      ),
      width: '24%',
    },
    {
      key: 'triggered',
      header: 'Fired',
      render: (row) =>
        row.triggered ? (
          <Badge tone="warning" title="The rule's conditions were met.">
            Yes
          </Badge>
        ) : (
          <Badge tone="neutral" title="The rule was evaluated and its conditions were not met.">
            No
          </Badge>
        ),
      width: '9%',
    },
    {
      key: 'measured_value',
      header: 'Measured / threshold',
      numeric: true,
      render: (row) => (
        <span className="whitespace-nowrap text-xs tabular">
          <span className="font-medium text-ink-900 dark:text-ink-50">
            {formatRatio(row.measured_value)}
          </span>
          <span className="text-ink-400 dark:text-ink-500"> / </span>
          <span className="text-ink-600 dark:text-ink-300">{formatRatio(row.threshold)}</span>
        </span>
      ),
      width: '16%',
    },
    {
      key: 'explanation',
      header: 'Why',
      render: (row) => (
        <span className="text-2xs leading-relaxed text-ink-700 dark:text-ink-200">
          {row.explanation ?? '—'}
        </span>
      ),
      width: '28%',
    },
    {
      key: 'evidence_refs',
      header: 'Evidence',
      render: (row) =>
        row.evidence_refs.length === 0 ? (
          <span className="text-2xs text-ink-400 dark:text-ink-500">—</span>
        ) : (
          <ul className="space-y-0.5">
            {row.evidence_refs.slice(0, 3).map((reference) => (
              <li key={reference}>
                {onSelectEvidence ? (
                  <button
                    type="button"
                    onClick={() => onSelectEvidence(reference)}
                    className="font-mono text-2xs text-accent-700 hover:underline dark:text-accent-300"
                    title={reference}
                  >
                    {formatEvidenceReference(reference)}
                  </button>
                ) : (
                  <span className="font-mono text-2xs text-ink-600 dark:text-ink-300" title={reference}>
                    {formatEvidenceReference(reference)}
                  </span>
                )}
              </li>
            ))}
            {row.evidence_refs.length > 3 ? (
              <li
                className="text-2xs text-ink-500 dark:text-ink-400"
                title={row.evidence_refs.slice(3).join('\n')}
              >
                +{row.evidence_refs.length - 3} more
              </li>
            ) : null}
          </ul>
        ),
      hideOnSmall: true,
      width: '12%',
    },
  ];

  return (
    <DataTable
      caption="Detection rules evaluated for this assessment, with measured values"
      columns={columns}
      rows={visible}
      rowKey={(row) => row.id}
      isLoading={isLoading}
      emptyTitle={includeNotTriggered ? 'No rules were evaluated' : 'No rules fired'}
      emptyMessage={
        emptyMessage ??
        (includeNotTriggered
          ? 'The assessment recorded no rule evaluations. Check that a rule pack is loaded.'
          : 'This score came from the model and anomaly components rather than from rules.')
      }
    />
  );
}
